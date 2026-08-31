#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnounceAdmissionConfig {
    pub steady_per_sec: u16,
    pub grace_per_sec: u16,
    pub grace_secs: u32,
}

impl AnnounceAdmissionConfig {
    pub const DISABLED: Self = Self {
        steady_per_sec: 0,
        grace_per_sec: 0,
        grace_secs: 0,
    };
}

impl Default for AnnounceAdmissionConfig {
    fn default() -> Self {
        Self::DISABLED
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnounceAdmission {
    last_refill_ms: u64,
    credit_milli: u64,
    initialized: bool,
}

impl AnnounceAdmission {
    pub const fn new() -> Self {
        Self {
            last_refill_ms: 0,
            credit_milli: 0,
            initialized: false,
        }
    }

    /// Admit one announce through a bounded token bucket. PATH_RESPONSE announces
    /// are protocol-critical and always exempt. A zero rate means unlimited in
    /// that phase, preserving the disabled default.
    pub fn admit(
        &mut self,
        config: AnnounceAdmissionConfig,
        path_response: bool,
        now_ms: u64,
    ) -> bool {
        if path_response {
            return true;
        }
        let first = !self.initialized;
        if first {
            self.last_refill_ms = now_ms;
            self.initialized = true;
        }

        let in_grace = now_ms < (config.grace_secs as u64).saturating_mul(1000);
        let rate = if in_grace {
            config.grace_per_sec
        } else {
            config.steady_per_sec
        };
        if rate == 0 {
            self.last_refill_ms = now_ms;
            self.credit_milli = 0;
            return true;
        }

        let capacity = (rate as u64).saturating_mul(1000);
        if first {
            self.credit_milli = capacity;
        } else {
            let elapsed = now_ms.saturating_sub(self.last_refill_ms);
            self.credit_milli = self
                .credit_milli
                .saturating_add(elapsed.saturating_mul(rate as u64))
                .min(capacity);
        }
        self.last_refill_ms = now_ms;

        if self.credit_milli < 1000 {
            return false;
        }
        self.credit_milli -= 1000;
        true
    }
}

impl Default for AnnounceAdmission {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITED: AnnounceAdmissionConfig = AnnounceAdmissionConfig {
        steady_per_sec: 5,
        grace_per_sec: 3,
        grace_secs: 60,
    };

    #[test]
    fn grace_and_steady_caps_apply() {
        let mut admission = AnnounceAdmission::new();
        assert!(admission.admit(LIMITED, false, 0));
        assert!(admission.admit(LIMITED, false, 0));
        assert!(admission.admit(LIMITED, false, 0));
        assert!(!admission.admit(LIMITED, false, 0));

        assert!(admission.admit(LIMITED, false, 60_000));
        assert!(admission.admit(LIMITED, false, 60_000));
        assert!(admission.admit(LIMITED, false, 60_000));
        assert!(admission.admit(LIMITED, false, 60_000));
        assert!(admission.admit(LIMITED, false, 60_000));
        assert!(!admission.admit(LIMITED, false, 60_000));
    }

    #[test]
    fn path_responses_are_exempt() {
        let mut admission = AnnounceAdmission::new();
        for _ in 0..10 {
            assert!(admission.admit(LIMITED, true, 0));
        }
    }

    #[test]
    fn disabled_is_unlimited() {
        let mut admission = AnnounceAdmission::new();
        for _ in 0..100 {
            assert!(admission.admit(AnnounceAdmissionConfig::DISABLED, false, 0));
        }
    }
}
