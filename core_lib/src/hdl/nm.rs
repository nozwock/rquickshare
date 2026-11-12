//! The parts of NetworkManager's D-Bus API the bandwidth upgrade needs:
//! finding the Wi-Fi device and what it supports, and joining or hosting a
//! network with a temporary connection profile.
//!
//! This talks D-Bus directly rather than running nmcli, so it also works in
//! a Flatpak sandbox, given `--system-talk-name=org.freedesktop.NetworkManager`.

use std::net::Ipv4Addr;

/// Name prefixes of the connections we add.
pub(crate) const HOTSPOT_PREFIX: &str = "rqs-hotspot-";
pub(crate) const UPGRADE_PREFIX: &str = "rqs-upgrade-";

/// `NM_WIFI_DEVICE_CAP_AP`: the device can host an access point.
pub(crate) const CAP_AP: u32 = 0x40;
/// `NM_WIFI_DEVICE_CAP_FREQ_5GHZ`.
pub(crate) const CAP_FREQ_5GHZ: u32 = 0x400;

#[derive(Debug, Clone)]
// Only the Linux implementation reads the fields.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct WifiDevice {
    /// D-Bus object path.
    pub path: String,
    pub interface: String,
    /// `NMDeviceWifiCapabilities` flags.
    pub capabilities: u32,
}

/// A Wi-Fi network to join or host.
#[derive(Debug, Clone)]
// Only the Linux implementation reads the fields.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct WifiProfile {
    pub name: String,
    pub ssid: String,
    pub password: String,
    /// Host an access point that hands out addresses, instead of joining.
    pub host: bool,
    /// NetworkManager band ("a" or "bg") and channel to use.
    pub channel: Option<(&'static str, u32)>,
}

#[cfg(target_os = "linux")]
pub(crate) use linux::*;
#[cfg(not(target_os = "linux"))]
pub(crate) use unsupported::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::time::{Duration, Instant};

    use anyhow::{anyhow, bail};
    use dbus::Path;
    use dbus::arg::{PropMap, RefArg, Variant};
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    use dbus::blocking::{Connection, Proxy};

    use super::{Ipv4Addr, WifiDevice, WifiProfile};

    const NM: &str = "org.freedesktop.NetworkManager";
    const NM_PATH: &str = "/org/freedesktop/NetworkManager";
    const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
    const WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
    const ACCESS_POINT: &str = "org.freedesktop.NetworkManager.AccessPoint";
    const ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
    const IP4_CONFIG: &str = "org.freedesktop.NetworkManager.IP4Config";
    const SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
    const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
    const SETTINGS_CONNECTION: &str = "org.freedesktop.NetworkManager.Settings.Connection";
    const CALL_TIMEOUT: Duration = Duration::from_secs(10);
    const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);

    const DEVICE_TYPE_WIFI: u32 = 2;
    const ACTIVE_ACTIVATED: u32 = 2;
    const ACTIVE_DEACTIVATING: u32 = 3;

    /// Runs blocking D-Bus calls off the async runtime.
    async fn blocking<T: Send + 'static>(
        f: impl FnOnce(&Connection) -> Result<T, anyhow::Error> + Send + 'static,
    ) -> Result<T, anyhow::Error> {
        tokio::task::spawn_blocking(move || {
            let conn = Connection::new_system()
                .map_err(|e| anyhow!("connecting to the system bus: {e}"))?;
            f(&conn)
        })
        .await?
    }

    fn proxy<'a>(conn: &'a Connection, path: &'a str) -> Proxy<'a, &'a Connection> {
        conn.with_proxy(NM, path, CALL_TIMEOUT)
    }

    fn v<T: RefArg + 'static>(value: T) -> Variant<Box<dyn RefArg>> {
        Variant(Box::new(value))
    }

    /// The first Wi-Fi device NetworkManager manages.
    pub(crate) async fn wifi_device() -> Result<WifiDevice, anyhow::Error> {
        blocking(|conn| {
            let (devices,): (Vec<Path<'static>>,) = proxy(conn, NM_PATH)
                .method_call(NM, "GetDevices", ())
                .map_err(|e| anyhow!("NetworkManager: {e}"))?;
            for path in devices {
                let device = proxy(conn, &path);
                if device.get::<u32>(DEVICE, "DeviceType").ok() != Some(DEVICE_TYPE_WIFI) {
                    continue;
                }
                return Ok(WifiDevice {
                    path: path.to_string(),
                    interface: device.get(DEVICE, "Interface")?,
                    capabilities: device.get(WIRELESS, "WirelessCapabilities").unwrap_or(0),
                });
            }
            bail!("no Wi-Fi device")
        })
        .await
    }

    /// BSSID and frequency (MHz) of the access point `device` is on.
    pub(crate) async fn active_access_point(device: &WifiDevice) -> Option<(String, i32)> {
        let path = device.path.clone();
        blocking(move |conn| {
            let ap: Path<'static> = proxy(conn, &path).get(WIRELESS, "ActiveAccessPoint")?;
            if &*ap == "/" {
                bail!("not connected");
            }
            let ap = proxy(conn, &ap);
            let bssid: String = ap.get(ACCESS_POINT, "HwAddress")?;
            let frequency: u32 = ap.get(ACCESS_POINT, "Frequency")?;
            Ok((bssid, i32::try_from(frequency)?))
        })
        .await
        .ok()
    }

    /// The IPv4 address `device` currently has.
    pub(crate) async fn ipv4_address(device: &WifiDevice) -> Option<Ipv4Addr> {
        let path = device.path.clone();
        blocking(move |conn| {
            let config: Path<'static> = proxy(conn, &path).get(DEVICE, "Ip4Config")?;
            if &*config == "/" {
                bail!("no IPv4 configuration");
            }
            let addresses: Vec<PropMap> = proxy(conn, &config).get(IP4_CONFIG, "AddressData")?;
            addresses
                .iter()
                .find_map(|a| a.get("address")?.0.as_str()?.parse().ok())
                .ok_or_else(|| anyhow!("no IPv4 address"))
        })
        .await
        .ok()
    }

    /// A connection [`activate`] brought up. Dropping it takes it down and
    /// deletes it.
    pub(crate) struct Activation {
        // Also keeps the activation alive: it is bound to this D-Bus client.
        // (In a mutex only to be `Sync`.)
        conn: std::sync::Mutex<Connection>,
        path: String,
    }

    impl std::fmt::Debug for Activation {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Activation")
                .field("path", &self.path)
                .finish()
        }
    }

    impl Drop for Activation {
        fn drop(&mut self) {
            if let Ok(conn) = self.conn.get_mut() {
                delete_blocking(conn, &self.path);
            }
        }
    }

    /// Adds `profile` as a temporary connection and brings it up on
    /// `device`, for as long as the returned [`Activation`] lives.
    ///
    /// The connection is volatile (NetworkManager deletes it once it goes
    /// down) and its activation is bound to our D-Bus connection, so even
    /// if we crash or are killed NetworkManager takes it down: a hotspot
    /// left behind would keep the Wi-Fi off the user's network.
    pub(crate) async fn activate(
        device: &WifiDevice,
        profile: WifiProfile,
    ) -> Result<Activation, anyhow::Error> {
        let device = device.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::new_system()
                .map_err(|e| anyhow!("connecting to the system bus: {e}"))?;
            delete_leftovers(&conn);
            let gateway = profile.host.then(hotspot_gateway).flatten();
            let nm = proxy(&conn, NM_PATH);
            let device_path = Path::from(device.path.clone());
            let added: Result<(Path<'static>, Path<'static>, PropMap), _> = nm.method_call(
                NM,
                "AddAndActivateConnection2",
                (
                    settings(&device, &profile, gateway),
                    device_path.clone(),
                    Path::from("/"),
                    PropMap::from([
                        ("persist".to_string(), v("volatile".to_string())),
                        ("bind-activation".to_string(), v("dbus-client".to_string())),
                    ]),
                ),
            );
            let (connection, active) = match added {
                Ok((connection, active, _)) => (connection, active),
                // NetworkManager < 1.16.
                Err(e) if e.name() == Some("org.freedesktop.DBus.Error.UnknownMethod") => {
                    let (connection, active): (Path<'static>, Path<'static>) = nm
                        .method_call(
                            NM,
                            "AddAndActivateConnection",
                            (
                                settings(&device, &profile, gateway),
                                device_path,
                                Path::from("/"),
                            ),
                        )
                        .map_err(|e| anyhow!("NetworkManager: {e}"))?;
                    (connection, active)
                }
                Err(e) => bail!("NetworkManager: {e}"),
            };

            let activation = Activation {
                path: connection.to_string(),
                conn: std::sync::Mutex::new(conn),
            };
            // On failure, dropping `activation` deletes the connection.
            wait_activated(&activation.conn.lock().unwrap(), &active, &device)?;
            Ok(activation)
        })
        .await?
    }

    /// Deletes connections a previous run left behind (older versions
    /// didn't bind them to the process).
    fn delete_leftovers(conn: &Connection) {
        let Ok((connections,)): Result<(Vec<Path<'static>>,), _> =
            proxy(conn, SETTINGS_PATH).method_call(SETTINGS, "ListConnections", ())
        else {
            return;
        };
        for path in connections {
            let Ok((settings,)): Result<(HashMap<String, PropMap>,), _> =
                proxy(conn, &path).method_call(SETTINGS_CONNECTION, "GetSettings", ())
            else {
                continue;
            };
            let id = settings
                .get("connection")
                .and_then(|c| c.get("id"))
                .and_then(|id| id.0.as_str().map(String::from));
            if let Some(id) = id.filter(|id| {
                id.starts_with(super::HOTSPOT_PREFIX) || id.starts_with(super::UPGRADE_PREFIX)
            }) {
                info!("bwu: deleting leftover connection {id}");
                delete_blocking(conn, &path);
            }
        }
    }

    fn wait_activated(
        conn: &Connection,
        active: &str,
        device: &WifiDevice,
    ) -> Result<(), anyhow::Error> {
        let started = Instant::now();
        loop {
            match proxy(conn, active).get::<u32>(ACTIVE, "State") {
                Ok(ACTIVE_ACTIVATED) => return Ok(()),
                Ok(state) if state < ACTIVE_DEACTIVATING => {}
                // Deactivated, or already gone.
                _ => {
                    let (_, reason): (u32, u32) = proxy(conn, &device.path)
                        .get(DEVICE, "StateReason")
                        .unwrap_or_default();
                    bail!("activation failed (NMDeviceStateReason {reason})");
                }
            }
            if started.elapsed() > ACTIVATION_TIMEOUT {
                bail!("activation timed out");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn delete_blocking(conn: &Connection, connection: &str) {
        let r: Result<(), _> =
            proxy(conn, connection).method_call(SETTINGS_CONNECTION, "Delete", ());
        if let Err(e) = r {
            // A volatile connection may already be gone.
            debug!("bwu: deleting {connection}: {e}");
        }
    }

    /// Picks the address to host on, or `None` to leave it to
    /// NetworkManager.
    ///
    /// NetworkManager always hosts on 10.42.0.1/24 by default. That is also
    /// where k3s puts its pod network (`cni0`), and with the subnet taken the
    /// phone joins but never reaches us.
    fn hotspot_gateway() -> Option<Ipv4Addr> {
        let routes = std::fs::read_to_string("/proc/net/route")
            .inspect_err(|e| debug!("bwu: reading routes: {e}"))
            .ok()?;
        let routes = parse_routes(&routes);
        let gateway = free_subnet(&routes);
        match gateway {
            Some(gw) if gw != DEFAULT_GATEWAY => {
                info!("bwu: {DEFAULT_GATEWAY}/24 is in use, hosting on {gw}/24")
            }
            Some(_) => {}
            None => warn!("bwu: every hotspot subnet we try is in use"),
        }
        gateway
    }

    fn settings(
        device: &WifiDevice,
        profile: &WifiProfile,
        gateway: Option<Ipv4Addr>,
    ) -> HashMap<String, PropMap> {
        let mut connection = PropMap::from([
            ("id".to_string(), v(profile.name.clone())),
            ("uuid".to_string(), v(random_uuid())),
            ("type".to_string(), v("802-11-wireless".to_string())),
            ("interface-name".to_string(), v(device.interface.clone())),
            ("autoconnect".to_string(), v(false)),
        ]);
        if let Some(user) = user_name() {
            // Owned by us, so changing it needs no authorization.
            connection.insert("permissions".into(), v(vec![format!("user:{user}:")]));
        }

        let mut wireless = PropMap::from([
            ("ssid".to_string(), v(profile.ssid.as_bytes().to_vec())),
            (
                "mode".to_string(),
                v(if profile.host { "ap" } else { "infrastructure" }.to_string()),
            ),
        ]);
        if !profile.host {
            // Probe for the SSID directly instead of waiting for a scan.
            wireless.insert("hidden".into(), v(true));
        }
        if let Some((band, channel)) = profile.channel {
            wireless.insert("band".into(), v(band.to_string()));
            wireless.insert("channel".into(), v(channel));
        }

        let mut security = PropMap::from([
            ("key-mgmt".to_string(), v("wpa-psk".to_string())),
            ("psk".to_string(), v(profile.password.clone())),
        ]);
        if profile.host {
            for key in ["proto", "pairwise", "group"] {
                let value = if key == "proto" { "rsn" } else { "ccmp" };
                security.insert(key.into(), v(vec![value.to_string()]));
            }
        }

        let ipv4 = if profile.host {
            let mut ipv4 = PropMap::from([("method".to_string(), v("shared".to_string()))]);
            if let Some(gateway) = gateway {
                // NetworkManager hands out addresses from this subnet.
                ipv4.insert(
                    "address-data".into(),
                    v(vec![PropMap::from([
                        ("address".to_string(), v(gateway.to_string())),
                        ("prefix".to_string(), v(24u32)),
                    ])]),
                );
            }
            ipv4
        } else {
            PropMap::from([
                ("method".to_string(), v("auto".to_string())),
                // Keep the default route on the network we were on.
                ("never-default".to_string(), v(true)),
            ])
        };

        HashMap::from([
            ("connection".to_string(), connection),
            ("802-11-wireless".to_string(), wireless),
            ("802-11-wireless-security".to_string(), security),
            ("ipv4".to_string(), ipv4),
            (
                "ipv6".to_string(),
                PropMap::from([("method".to_string(), v("ignore".to_string()))]),
            ),
        ])
    }

    /// NetworkManager's own choice.
    const DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
    /// Where to host, in order. These avoid what Docker (172.17/16) and
    /// Android's Wi-Fi Direct groups (192.168.49/24) use.
    const HOTSPOT_GATEWAYS: [Ipv4Addr; 6] = [
        DEFAULT_GATEWAY,
        Ipv4Addr::new(192, 168, 42, 1),
        Ipv4Addr::new(192, 168, 43, 1),
        Ipv4Addr::new(192, 168, 44, 1),
        Ipv4Addr::new(192, 168, 45, 1),
        Ipv4Addr::new(172, 31, 42, 1),
    ];

    /// Destination and netmask of each route in `/proc/net/route`.
    fn parse_routes(table: &str) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        // Addresses are the kernel's __be32 printed as a native integer.
        let addr = |hex: &str| {
            u32::from_str_radix(hex, 16)
                .ok()
                .map(|n| Ipv4Addr::from(n.to_ne_bytes()))
        };
        table
            .lines()
            .skip(1)
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                Some((addr(fields.get(1)?)?, addr(fields.get(7)?)?))
            })
            .collect()
    }

    /// The first of [`HOTSPOT_GATEWAYS`] whose /24 no route overlaps,
    /// ignoring default routes.
    fn free_subnet(routes: &[(Ipv4Addr, Ipv4Addr)]) -> Option<Ipv4Addr> {
        const PREFIX_24: u32 = 0xffff_ff00;
        HOTSPOT_GATEWAYS.into_iter().find(|gw| {
            let subnet = u32::from(*gw) & PREFIX_24;
            !routes.iter().any(|(dest, mask)| {
                let mask = u32::from(*mask);
                // Two subnets overlap if they agree on the shorter prefix.
                let shorter = mask & PREFIX_24;
                mask != 0 && subnet & shorter == u32::from(*dest) & shorter
            })
        })
    }

    fn random_uuid() -> String {
        let mut b: [u8; 16] = rand::random();
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h = hex::encode(b);
        format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    }

    fn user_name() -> Option<String> {
        if let Some(user) = std::env::var("USER").ok().filter(|u| !u.is_empty()) {
            return Some(user);
        }
        // SAFETY: getpwuid returns null or a pointer to a static entry,
        // which we copy out of before any other call can overwrite it.
        unsafe {
            let entry = libc::getpwuid(libc::getuid());
            if entry.is_null() {
                return None;
            }
            CStr::from_ptr((*entry).pw_name)
                .to_str()
                .ok()
                .map(String::from)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // From a k3s node: its pod network sits where NetworkManager would
        // host by default.
        const K3S_ROUTES: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wls5f3\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
cni0\t00002A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
flannel.1\t00012A0A\t00012A0A\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0
wls5f3\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
";

        #[test]
        fn parses_route_table() {
            let routes = parse_routes(K3S_ROUTES);
            assert_eq!(routes.len(), 4);
            assert_eq!(
                routes[1],
                (Ipv4Addr::new(10, 42, 0, 0), Ipv4Addr::new(255, 255, 255, 0))
            );
        }

        #[test]
        fn keeps_the_default_subnet_when_free() {
            let routes = parse_routes(K3S_ROUTES);
            // Only the default route and the LAN.
            let lan = [routes[0], routes[3]];
            assert_eq!(free_subnet(&lan), Some(DEFAULT_GATEWAY));
        }

        #[test]
        fn avoids_a_taken_subnet() {
            let routes = parse_routes(K3S_ROUTES);
            assert_eq!(free_subnet(&routes), Some(Ipv4Addr::new(192, 168, 42, 1)));
        }

        #[test]
        fn avoids_subnets_inside_a_wider_route() {
            let routes = [
                (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0)),
                (Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
            ];
            assert_eq!(free_subnet(&routes), Some(Ipv4Addr::new(172, 31, 42, 1)));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use anyhow::bail;

    use super::{Ipv4Addr, WifiDevice, WifiProfile};

    pub(crate) async fn wifi_device() -> Result<WifiDevice, anyhow::Error> {
        bail!("Wi-Fi upgrades need NetworkManager")
    }

    pub(crate) async fn active_access_point(_: &WifiDevice) -> Option<(String, i32)> {
        None
    }

    pub(crate) async fn ipv4_address(_: &WifiDevice) -> Option<Ipv4Addr> {
        None
    }

    #[derive(Debug)]
    pub(crate) struct Activation;

    pub(crate) async fn activate(
        _: &WifiDevice,
        _: WifiProfile,
    ) -> Result<Activation, anyhow::Error> {
        bail!("Wi-Fi upgrades need NetworkManager")
    }
}
