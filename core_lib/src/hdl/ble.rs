use std::pin::Pin;
use std::time::{Duration, SystemTime};

use anyhow::anyhow;
use btleplug::api::{Central, CentralEvent, Manager as _, ScanFilter};
use btleplug::platform::{Adapter, Manager};
use futures::stream::StreamExt;
use tokio::sync::broadcast::Sender;
use tokio::sync::watch;
use tokio::time::{Instant, Sleep, sleep};
use tokio_util::sync::CancellationToken;
use uuid::{uuid, Uuid};

const SERVICE_UUID_SHARING: Uuid = uuid!("0000fe2c-0000-1000-8000-00805f9b34fb");

const INNER_NAME: &str = "BleListener";

// Timings used when duty-cycling the scan (see `ScanMode`).
//
// We scan for a short window, then leave the adapter alone for a longer gap so
// that BlueZ isn't held in continuous discovery for the whole lifetime of the app.
// See: https://github.com/Martichou/rquickshare/issues/429
const DUTY_CYCLE_SCAN: Duration = Duration::from_secs(5);
const DUTY_CYCLE_IDLE: Duration = Duration::from_secs(25);
// How long to wait before trying again when the scan couldn't be started, e.g.
// because the Bluetooth adapter got powered off.
const RETRY_DELAY: Duration = Duration::from_secs(30);

/// How the BLE scan is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    /// Keep a single discovery session open.
    Continuous,
    /// Alternate between short scan windows and longer gaps.
    DutyCycle,
}

impl ScanMode {
    /// A BlueZ discovery session switches the controller to an active, accept-all scan
    /// and suppresses the kernel's passive background scan, which is what lets bonded
    /// BLE peripherals (keyboards, mice) reconnect on their own. Holding one open for
    /// the whole lifetime of the app therefore keeps such devices from reconnecting,
    /// most visibly after a suspend/resume. Linux/BlueZ is the only place where this
    /// is a problem, other platforms multiplex scanning, so they keep scanning
    /// continuously.
    ///
    /// While the app is in the foreground we scan continuously, so that nearby devices
    /// are noticed quickly. In the background we duty-cycle.
    fn for_foreground(foreground: bool) -> Self {
        if cfg!(target_os = "linux") && !foreground {
            Self::DutyCycle
        } else {
            Self::Continuous
        }
    }
}

/// A timer that is only waited on while it is armed.
struct Deadline {
    sleep: Pin<Box<Sleep>>,
    armed: bool,
}

impl Deadline {
    fn new() -> Self {
        Self {
            sleep: Box::pin(sleep(Duration::ZERO)),
            armed: false,
        }
    }

    fn arm(&mut self, after: Duration) {
        self.sleep.as_mut().reset(Instant::now() + after);
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Completes when the deadline is reached, and disarms it.
    async fn reached(&mut self) {
        self.sleep.as_mut().await;
        self.armed = false;
    }
}

pub struct BleListener {
    adapter: Adapter,
    sender: Sender<()>,
}

impl BleListener {
    pub async fn new(sender: Sender<()>) -> Result<Self, anyhow::Error> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        if adapters.is_empty() {
            return Err(anyhow!("no bluetooth adapter"));
        }

        Ok(Self {
            adapter: adapters[0].clone(),
            sender,
        })
    }

    /// Opens a discovery session, if there isn't one yet.
    ///
    /// Failing to scan is not fatal: the adapter can come and go (e.g. it gets powered
    /// off), so the caller is expected to try again later. Returns whether we're scanning.
    async fn start_scan(&self, scanning: &mut bool) -> bool {
        if !*scanning {
            // Filter on the NearyShare/QuickShare services UUID

            // Not using the ScanFilter here to filter out advertisements
            // not matching the Nearby Share service UUID, it seems to
            // exclude Nearby Share advertisements despite its UUID being
            // in the filter.
            //
            // Perhaps broken?
            match self.adapter.start_scan(ScanFilter::default()).await {
                Ok(()) => {
                    *scanning = true;
                    debug!("{INNER_NAME}: scan started");
                }
                Err(err) => warn!("{INNER_NAME}: couldn't start the scan: {err}"),
            }
        }

        *scanning
    }

    /// Closes the discovery session, if there is one.
    async fn stop_scan(&self, scanning: &mut bool) {
        if *scanning {
            // If this fails, then the session is most likely already gone (e.g. the
            // adapter got powered off), so either way we're not scanning anymore.
            *scanning = false;
            match self.adapter.stop_scan().await {
                Ok(()) => debug!("{INNER_NAME}: scan stopped"),
                Err(err) => warn!("{INNER_NAME}: couldn't stop the scan: {err}"),
            }
        }
    }

    /// Switch to `mode`.
    async fn enter_mode(&self, mode: ScanMode, scanning: &mut bool, deadline: &mut Deadline) {
        match mode {
            ScanMode::Continuous => {
                if self.start_scan(scanning).await {
                    deadline.disarm();
                } else {
                    deadline.arm(RETRY_DELAY);
                }
            }
            ScanMode::DutyCycle => {
                // Start with a gap rather than a scan. The service gets (re)started
                // right after a resume, and the peripherals that are waking up then
                // should get the chance to reconnect right away.
                self.stop_scan(scanning).await;
                deadline.arm(DUTY_CYCLE_IDLE);
            }
        }
    }

    /// The deadline got reached: begin the next scan window or the next gap.
    async fn deadline_reached(&self, mode: ScanMode, scanning: &mut bool, deadline: &mut Deadline) {
        if *scanning {
            match mode {
                ScanMode::DutyCycle => {
                    self.stop_scan(scanning).await;
                    deadline.arm(DUTY_CYCLE_IDLE);
                }
                ScanMode::Continuous => deadline.disarm(),
            }
        } else {
            match (mode, self.start_scan(scanning).await) {
                (ScanMode::DutyCycle, true) => deadline.arm(DUTY_CYCLE_SCAN),
                (ScanMode::Continuous, true) => deadline.disarm(),
                (_, false) => deadline.arm(RETRY_DELAY),
            }
        }
    }

    pub async fn run(
        self,
        ctk: CancellationToken,
        mut foreground_rx: watch::Receiver<bool>,
    ) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");

        let mut events = self.adapter.events().await?;

        let mut last_alert: SystemTime = SystemTime::UNIX_EPOCH;

        // Whether we've got a discovery session open.
        let mut scanning = false;
        let mut mode = ScanMode::for_foreground(*foreground_rx.borrow_and_update());
        let mut deadline = Deadline::new();

        self.enter_mode(mode, &mut scanning, &mut deadline).await;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                changed = foreground_rx.changed() => {
                    if changed.is_err() {
                        // The sender is gone, there won't be any more changes. Park here
                        // until we're cancelled, to not spin on the closed channel.
                        debug!("{INNER_NAME}: foreground sender dropped, waiting to be cancelled");
                        ctk.cancelled().await;
                        info!("{INNER_NAME}: tracker cancelled, breaking");
                        break;
                    }

                    let new_mode = ScanMode::for_foreground(*foreground_rx.borrow_and_update());
                    if new_mode != mode {
                        debug!("{INNER_NAME}: scan mode changed: {mode:?} -> {new_mode:?}");
                        mode = new_mode;
                        self.enter_mode(mode, &mut scanning, &mut deadline).await;
                    }
                }
                _ = deadline.reached(), if deadline.armed => {
                    self.deadline_reached(mode, &mut scanning, &mut deadline).await;
                }
                Some(e) = events.next() => {
                    // Anything still being delivered during a gap isn't of interest.
                    if !scanning {
                        continue;
                    }

                    match e {
                        CentralEvent::ServiceDataAdvertisement { id, service_data } => {
                            // Sanity check as per: https://github.com/Martichou/rquickshare/issues/74
                            // Seems like the filtering is not enough, so we'll add a check before
                            // proceeding with the service_data.
                            //
                            // ...The filtering is being done only here now.
                            if let Some(service_data) = service_data.get(&SERVICE_UUID_SHARING) {
                                let now = SystemTime::now();
                                // Quick Share seems to emit LE advert every 10 seconds...
                                // Doesn't really seem much of a spam, so we wait for 10s now
                                // just in case some implementation is sending it under that
                                // time period
                                if now.duration_since(last_alert)? <= Duration::from_secs(10) {
                                    // debug!("{INNER_NAME}: Received LE advert but last alert was {}s ago", now.duration_since(last_alert)?.as_secs());
                                    continue;
                                }

                                debug!("{INNER_NAME}: A device ({id}) is sharing ({}) nearby", hex::encode(service_data));
                                self.sender.send(())?;
                                last_alert = now;
                            }
                        },
                        // Not interesting for us
                        _ => {
                            // trace!("{INNER_NAME}: Another CentralEvent got the same services: {:?}", e);
                        }
                    }
                }
            }
        }

        // Don't leave the discovery session behind: the service gets restarted at times,
        // and the new listener would otherwise start another session next to this one.
        self.stop_scan(&mut scanning).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_mode_depends_on_foreground_and_platform() {
        // In the foreground we always scan continuously.
        assert_eq!(ScanMode::for_foreground(true), ScanMode::Continuous);

        // In the background we only duty-cycle on Linux/BlueZ.
        assert_eq!(
            ScanMode::for_foreground(false),
            if cfg!(target_os = "linux") {
                ScanMode::DutyCycle
            } else {
                ScanMode::Continuous
            }
        );
    }

    #[tokio::test]
    async fn deadline_disarms_when_reached() {
        let mut deadline = Deadline::new();
        assert!(!deadline.armed);

        deadline.arm(Duration::from_millis(10));
        assert!(deadline.armed);

        deadline.reached().await;
        assert!(!deadline.armed);
    }

    #[tokio::test]
    async fn deadline_can_be_disarmed_and_rearmed() {
        let mut deadline = Deadline::new();

        deadline.arm(Duration::from_secs(60));
        deadline.disarm();
        assert!(!deadline.armed);

        // Re-arming moves the deadline, it doesn't have to wait for the previous one.
        deadline.arm(Duration::from_millis(10));
        deadline.reached().await;
        assert!(!deadline.armed);
    }
}
