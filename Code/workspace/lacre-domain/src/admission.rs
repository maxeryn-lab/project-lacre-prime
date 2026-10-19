//! Optional admission control, configured by the operator
//! (see spec/LACRE-WIRE-v2.md).
//!
//! This is a mechanism of the node, NOT a guarantee of the protocol. Lacre
//! guarantees transit integrity; it does not promise availability, and it is
//! not a gateway (Prime section 5). A deployment that needs ceilings sets
//! them (Prime 9.6); one that does not, runs without them, and the startup
//! log says so. There are no default values: a limit that is not configured
//! does not exist.
//!
//! The gate never waits. `try_admit` either has room or answers "busy";
//! there is no queue, so no queue without a bound. It counts work that is
//! RUNNING, not requests: a computation cannot be cancelled once started
//! (the Core is synchronous), so it keeps its permit until it finishes even
//! if the client disconnected.
//!
//! Richer admission (client puzzles that make an attacker pay before the
//! Core spends anything) is a Profile that runs before the Core, Annex 15
//! vector 1. That Profile is not part of this module.

use crate::domain::DomainError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Counters of running work. `None` for a limit means "no limit configured".
#[derive(Debug)]
pub struct AdmissionGate {
    running: AtomicUsize,
    running_heavy: AtomicUsize,
    max_running: Option<usize>,
    max_heavy: Option<usize>,
}

#[derive(Clone, Copy)]
enum Kind {
    Any,
    Heavy,
}

/// Held while the work runs; releases its place when dropped.
#[derive(Debug)]
pub struct Permit {
    gate: Arc<AdmissionGate>,
    heavy: bool,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let counter = if self.heavy { &self.gate.running_heavy } else { &self.gate.running };
        counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn busy() -> DomainError {
    DomainError::Unavailable("the node is running the maximum number of operations it was configured for; retry shortly".to_string())
}

impl AdmissionGate {
    pub fn new(max_running: Option<usize>, max_heavy: Option<usize>) -> Arc<Self> {
        Arc::new(AdmissionGate {
            running: AtomicUsize::new(0),
            running_heavy: AtomicUsize::new(0),
            max_running,
            max_heavy,
        })
    }

    /// A place for one operation of any cost, taken before the work is
    /// handed to a blocking thread (so the thread queue cannot grow without
    /// bound while the gate is full).
    pub fn try_admit(self: &Arc<Self>) -> Result<Permit, DomainError> {
        self.take(Kind::Any)
    }

    /// An additional place for an operation whose algorithm is declared
    /// `Heavy`. Counts separately from `try_admit`.
    pub fn try_admit_heavy(self: &Arc<Self>) -> Result<Permit, DomainError> {
        self.take(Kind::Heavy)
    }

    fn take(self: &Arc<Self>, kind: Kind) -> Result<Permit, DomainError> {
        let (counter, max, heavy) = match kind {
            Kind::Any => (&self.running, self.max_running, false),
            Kind::Heavy => (&self.running_heavy, self.max_heavy, true),
        };
        match max {
            None => {
                counter.fetch_add(1, Ordering::AcqRel);
            }
            Some(max) => {
                counter
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < max).then_some(n + 1))
                    .map_err(|_| busy())?;
            }
        }
        Ok(Permit { gate: self.clone(), heavy })
    }

    /// Operations running now (any cost). Test and diagnostics only.
    pub fn running(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }

    pub fn running_heavy(&self) -> usize {
        self.running_heavy.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_limits_nothing_is_refused() {
        let g = AdmissionGate::new(None, None);
        let permits: Vec<_> = (0..1000).map(|_| g.try_admit().unwrap()).collect();
        assert_eq!(g.running(), 1000);
        drop(permits);
        assert_eq!(g.running(), 0);
    }

    #[test]
    fn at_the_limit_it_answers_busy_without_waiting_and_recovers_on_drop() {
        let g = AdmissionGate::new(Some(2), None);
        let a = g.try_admit().unwrap();
        let _b = g.try_admit().unwrap();
        let start = std::time::Instant::now();
        assert!(matches!(g.try_admit(), Err(DomainError::Unavailable(_))));
        assert!(start.elapsed() < std::time::Duration::from_millis(50), "the gate must not wait");
        drop(a);
        assert!(g.try_admit().is_ok(), "a released place is usable again");
    }

    #[test]
    fn heavy_places_count_separately() {
        let g = AdmissionGate::new(Some(10), Some(1));
        let _h = g.try_admit_heavy().unwrap();
        assert!(matches!(g.try_admit_heavy(), Err(DomainError::Unavailable(_))));
        let _any = g.try_admit().expect("heavy being full does not block ordinary work");
        assert_eq!((g.running(), g.running_heavy()), (1, 1));
    }

    #[test]
    fn many_threads_never_exceed_the_limit() {
        let g = AdmissionGate::new(Some(3), None);
        let max_seen = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (g, max_seen) = (g.clone(), max_seen.clone());
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        if let Ok(p) = g.try_admit() {
                            max_seen.fetch_max(g.running(), Ordering::SeqCst);
                            drop(p);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(max_seen.load(Ordering::SeqCst) <= 3);
        assert_eq!(g.running(), 0);
    }
}
