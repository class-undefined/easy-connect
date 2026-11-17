use ec_compat::session_status::SessionEndReason;
use std::time::{Duration, Instant};

const DELAYS: [Duration; 5] = [
    Duration::from_secs(3),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
    Duration::from_secs(30),
];

/// A manual connection must succeed before background logins may be retried.
/// Only network failures and expired sessions qualify, never remote kicks.
#[derive(Default)]
pub(super) struct Reconnect {
    established: bool,
    attempts: usize,
    next: Option<Instant>,
}

impl Reconnect {
    pub(super) fn connected(&mut self) {
        self.established = true;
        self.attempts = 0;
        self.next = None;
    }

    pub(super) fn cancel(&mut self) {
        *self = Self::default();
    }

    pub(super) fn schedule(
        &mut self,
        reason: Option<SessionEndReason>,
        transient_failure: bool,
        now: Instant,
    ) -> Option<Duration> {
        let recoverable = match reason {
            Some(SessionEndReason::ConnectionLost | SessionEndReason::Timeout) => true,
            None => transient_failure,
            Some(_) => false,
        };
        if !self.established || !recoverable {
            self.cancel();
            return None;
        }
        let delay = DELAYS[self.attempts.min(DELAYS.len() - 1)];
        self.attempts = self.attempts.saturating_add(1);
        self.next = Some(now + delay);
        Some(delay)
    }

    pub(super) fn pending(&self) -> bool {
        self.next.is_some()
    }

    pub(super) fn take_due(&mut self, now: Instant) -> bool {
        if self.next.is_some_and(|deadline| now >= deadline) {
            self.next = None;
            true
        } else {
            false
        }
    }

    pub(super) fn attempt(&self) -> usize {
        self.attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_retries_back_off_and_remain_available_after_a_long_outage() {
        let mut reconnect = Reconnect::default();
        reconnect.connected();
        let mut now = Instant::now();
        for (index, seconds) in [3, 5, 10, 20, 30, 30, 30].into_iter().enumerate() {
            let reason = (index == 0).then_some(SessionEndReason::ConnectionLost);
            let delay = reconnect.schedule(reason, index > 0, now).unwrap();
            assert_eq!(delay, Duration::from_secs(seconds));
            assert!(!reconnect.take_due(now + delay - Duration::from_millis(1)));
            now += delay;
            assert!(reconnect.take_due(now));
            assert!(!reconnect.take_due(now));
        }
        reconnect.connected();
        assert_eq!(reconnect.attempt(), 0);
        assert_eq!(
            reconnect.schedule(Some(SessionEndReason::Timeout), false, now),
            Some(Duration::from_secs(3))
        );
    }

    #[test]
    fn initial_login_failure_is_not_retried_and_cancellation_disarms_recovery() {
        let now = Instant::now();
        let mut reconnect = Reconnect::default();
        assert!(reconnect.schedule(None, true, now).is_none());
        reconnect.connected();
        reconnect.schedule(Some(SessionEndReason::ConnectionLost), false, now);
        reconnect.cancel();
        assert!(!reconnect.take_due(now + Duration::from_secs(300)));
        assert!(reconnect.schedule(None, true, now).is_none());
    }

    #[test]
    fn explicit_session_ends_and_non_network_errors_stop_automatic_logins() {
        let now = Instant::now();
        for reason in [
            Some(SessionEndReason::PrivateKick),
            Some(SessionEndReason::AdminKick),
            Some(SessionEndReason::OutsideTimePlan),
            Some(SessionEndReason::LoggedOut),
            Some(SessionEndReason::LocalException),
            Some(SessionEndReason::Unknown),
            Some(SessionEndReason::SessionChanged),
            None,
        ] {
            let mut reconnect = Reconnect::default();
            reconnect.connected();
            assert!(reconnect.schedule(reason, reason.is_some(), now).is_none());
            assert!(!reconnect.pending());
            assert!(reconnect.schedule(None, true, now).is_none());
        }
    }
}
