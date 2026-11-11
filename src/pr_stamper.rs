//! Path-request stamp generation without threads or heap, ported from the
//! trusted `rns-transport` stamper (Transport.py:1466-1493, :4018-4051 at
//! 1.6.0): one search at a time, a bounded queue that coalesces by
//! destination, and a bounded first-in-first-out cache of finished stamps.
//! The host drives the search in bounded steps with its own RNG. The running
//! job stays at the head of the queue holding only its deadline and attempt
//! count, so a node that cannot afford a stamper sizes both bounds to zero.

use crate::stamps::{NETWORK_STAMP_SIZE, NetworkStampSearch, Progress, StampPolicy};
use crate::tables::{Hash16, InterfaceId, Queue};

/// Python `STAMPER_PR_QUEUE_LENGTH`.
pub const STAMPER_PR_QUEUE_LENGTH: usize = 32;
/// Queue slots for Python's waiting jobs plus the one being searched, which
/// Python's worker has already taken off its queue.
pub const STAMPER_PR_QUEUE_SLOTS: usize = STAMPER_PR_QUEUE_LENGTH + 1;
/// Python `pr_stamp_cache_max`.
pub const PR_STAMP_CACHE_MAX: usize = 256;

pub type PathRequestStamp = [u8; NETWORK_STAMP_SIZE];

/// Where a stamped path request goes once its stamp is ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathRequestTarget {
    /// One interface, as `request_path(on_interface=...)`.
    Interface(InterfaceId),
    /// Every outbound interface except the given one.
    AllExcept(InterfaceId),
}

/// One queued generation job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathRequestStampJob {
    pub destination_hash: Hash16,
    pub tag: [u8; 16],
    pub target: PathRequestTarget,
    /// Python `PR_VALUE`, fixed point.
    pub value_fp: u16,
    /// Python `PR_STAMP_TIMEOUT`, in milliseconds from the start of the search.
    pub timeout_ms: u32,
}

impl PathRequestStampJob {
    /// Python keys on the destination, plus the interface when one is given.
    fn key(&self) -> (Hash16, Option<InterfaceId>) {
        match self.target {
            PathRequestTarget::Interface(id) => (self.destination_hash, Some(id)),
            PathRequestTarget::AllExcept(_) => (self.destination_hash, None),
        }
    }

    /// Python `pr_stamp_material`: destination hash then tag.
    pub fn material(&self) -> [u8; 32] {
        pr_stamp_material(&self.destination_hash, &self.tag)
    }
}

/// Python `pr_stamp_material`: destination hash then tag.
pub fn pr_stamp_material(destination_hash: &Hash16, tag: &[u8; 16]) -> [u8; 32] {
    let mut material = [0u8; 32];
    material[..16].copy_from_slice(destination_hash);
    material[16..].copy_from_slice(tag);
    material
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachedStamp {
    material: [u8; 32],
    stamp: PathRequestStamp,
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Started {
    deadline_ms: u64,
    attempts: u64,
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    job: PathRequestStampJob,
    started: Option<Started>,
}

/// The stamper queue refused a job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueFull;

/// Outcome of one [`PathRequestStamper::step`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StamperStep {
    Idle,
    Searching {
        destination_hash: Hash16,
        attempts: u64,
    },
    Ready {
        job: PathRequestStampJob,
        stamp: PathRequestStamp,
    },
    /// Generation hit the timeout; the request is not sent.
    TimedOut {
        job: PathRequestStampJob,
    },
}

/// `Q` queue slots, the running job included, and a cache of at most `C` stamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathRequestStamper<const Q: usize, const C: usize> {
    #[doc(hidden)]
    pub queue: Queue<Slot, Q>,
    #[doc(hidden)]
    pub cache: Queue<CachedStamp, C>,
}

impl<const Q: usize, const C: usize> PathRequestStamper<Q, C> {
    pub const fn new() -> Self {
        Self {
            queue: Queue::new(),
            cache: Queue::new(),
        }
    }

    pub fn clear(&mut self) {
        self.queue.clear();
        self.cache.clear();
    }

    /// Python `pr_stamp_cache.get(material)`.
    pub fn cached(&self, destination_hash: &Hash16, tag: &[u8; 16]) -> Option<PathRequestStamp> {
        let material = pr_stamp_material(destination_hash, tag);
        self.cache
            .iter()
            .find(|entry| entry.material == material)
            .map(|entry| entry.stamp)
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Jobs waiting, not counting the one being searched.
    pub fn queue_len(&self) -> usize {
        self.queue.len() - usize::from(self.active_job().is_some())
    }

    /// A job is queued or being searched.
    pub fn pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// The job being searched, if any.
    pub fn active_job(&self) -> Option<PathRequestStampJob> {
        self.queue
            .peek()
            .filter(|slot| slot.started.is_some())
            .map(|slot| slot.job)
    }

    /// Python `WorkerQueues.put`: drop waiting jobs with the same key, then
    /// refuse when the queue is still full. The running search is untouched.
    pub fn enqueue(&mut self, job: PathRequestStampJob) -> Result<(), QueueFull> {
        let key = job.key();
        let mut offset = self.queue.len();
        while offset > 0 {
            offset -= 1;
            if self
                .queue
                .iter()
                .nth(offset)
                .is_some_and(|slot| slot.started.is_none() && slot.job.key() == key)
            {
                self.queue.remove(offset);
            }
        }
        if self.queue.len() >= Q {
            return Err(QueueFull);
        }
        self.queue.push_drop_oldest(Slot { job, started: None });
        Ok(())
    }

    /// Python `pr_stamp_cache[material] = stamp`, evicting the oldest past `C`.
    pub fn insert_cached(&mut self, material: [u8; 32], stamp: PathRequestStamp) {
        if let Some(entry) = self
            .cache
            .iter_mut()
            .find(|entry| entry.material == material)
        {
            entry.stamp = stamp;
            return;
        }
        self.cache.push_drop_oldest(CachedStamp { material, stamp });
    }

    /// Start the next job if idle, then test at most `attempt_budget`
    /// candidates filled by `fill` from the host's cryptographic RNG.
    pub fn step(
        &mut self,
        now_ms: u64,
        attempt_budget: u32,
        fill: impl FnMut(&mut PathRequestStamp),
    ) -> StamperStep {
        let Some(&slot) = self.queue.peek() else {
            return StamperStep::Idle;
        };
        let job = slot.job;
        let started = match slot.started {
            Some(started) => started,
            None => {
                // The trusted worker serves a stamp cached since the job was queued.
                if let Some(stamp) = self.cached(&job.destination_hash, &job.tag) {
                    self.queue.pop();
                    return StamperStep::Ready { job, stamp };
                }
                let timeout = StampPolicy::clamp_timeout_ms(job.timeout_ms);
                let started = Started {
                    deadline_ms: now_ms.saturating_add(u64::from(timeout)),
                    attempts: 0,
                };
                if let Some(head) = self.queue.get_mut(0) {
                    head.started = Some(started);
                }
                started
            }
        };
        if now_ms >= started.deadline_ms {
            self.queue.pop();
            return StamperStep::TimedOut { job };
        }
        // Rebuilt each step: the material is one partial SHA-256 block, so only
        // the attempt count has to persist.
        let cost = StampPolicy::clamp_cost_fp(job.value_fp);
        let progress = match NetworkStampSearch::new(&job.material(), cost, u64::MAX) {
            Ok(mut search) => search.step(attempt_budget, fill),
            Err(_) => Progress::Cancelled,
        };
        match progress {
            Progress::Searching { attempts } => {
                let attempts = started.attempts.saturating_add(attempts);
                if let Some(slot) = self.queue.get_mut(0) {
                    slot.started = Some(Started {
                        attempts,
                        ..started
                    });
                }
                StamperStep::Searching {
                    destination_hash: job.destination_hash,
                    attempts,
                }
            }
            Progress::Complete { stamp, .. } => {
                self.queue.pop();
                self.insert_cached(job.material(), stamp);
                StamperStep::Ready { job, stamp }
            }
            Progress::Exhausted | Progress::Cancelled => {
                self.queue.pop();
                StamperStep::TimedOut { job }
            }
        }
    }
}

impl<const Q: usize, const C: usize> Default for PathRequestStamper<Q, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(dest: u8, target: PathRequestTarget, value_fp: u16) -> PathRequestStampJob {
        PathRequestStampJob {
            destination_hash: [dest; 16],
            tag: [0x11; 16],
            target,
            value_fp,
            timeout_ms: 15_000,
        }
    }

    fn counter(seed: &mut u64) -> impl FnMut(&mut PathRequestStamp) + '_ {
        move |candidate| {
            *seed += 1;
            candidate[..8].copy_from_slice(&seed.to_le_bytes());
        }
    }

    #[test]
    fn search_past_the_timeout_sends_nothing_and_caches_nothing() {
        let mut stamper = PathRequestStamper::<4, 4>::new();
        let mut slow = job(1, PathRequestTarget::Interface(3), 60 * 256);
        slow.timeout_ms = 50;
        stamper.enqueue(slow).unwrap();
        let mut seed = 0;
        assert!(matches!(
            stamper.step(1_000, 1, counter(&mut seed)),
            StamperStep::Searching { .. }
        ));
        assert_eq!(
            stamper.step(1_050, 1, counter(&mut seed)),
            StamperStep::TimedOut { job: slow }
        );
        assert_eq!(stamper.cache_len(), 0);
        assert!(!stamper.pending());
    }

    #[test]
    fn same_key_jobs_coalesce_and_the_queue_is_bounded() {
        let mut stamper = PathRequestStamper::<STAMPER_PR_QUEUE_SLOTS, 4>::new();
        stamper
            .enqueue(job(1, PathRequestTarget::Interface(1), 8))
            .unwrap();
        stamper
            .enqueue(job(1, PathRequestTarget::Interface(1), 9))
            .unwrap();
        stamper
            .enqueue(job(1, PathRequestTarget::AllExcept(1), 8))
            .unwrap();
        assert_eq!(stamper.queue_len(), 2);
        assert_eq!(stamper.queue.peek().unwrap().job.value_fp, 9);
        for dest in 2..=(STAMPER_PR_QUEUE_SLOTS as u8 - 1) {
            stamper
                .enqueue(job(dest, PathRequestTarget::AllExcept(1), 8))
                .unwrap();
        }
        assert_eq!(
            stamper.enqueue(job(0xEE, PathRequestTarget::AllExcept(1), 8)),
            Err(QueueFull)
        );
        // A same-key job still replaces its queued twin when full.
        assert_eq!(
            stamper.enqueue(job(2, PathRequestTarget::AllExcept(2), 8)),
            Ok(())
        );
        let mut empty = PathRequestStamper::<0, 0>::new();
        assert_eq!(
            empty.enqueue(job(1, PathRequestTarget::Interface(1), 8)),
            Err(QueueFull)
        );
    }

    #[test]
    fn cache_holds_its_bound_first_in_first_out() {
        let mut stamper = PathRequestStamper::<1, PR_STAMP_CACHE_MAX>::new();
        for i in 0..=PR_STAMP_CACHE_MAX as u16 {
            let mut dest = [0u8; 16];
            dest[..2].copy_from_slice(&i.to_be_bytes());
            stamper.insert_cached(pr_stamp_material(&dest, &[0; 16]), [1; 14]);
        }
        assert_eq!(stamper.cache_len(), PR_STAMP_CACHE_MAX);
        assert_eq!(stamper.cached(&[0; 16], &[0; 16]), None);
        let mut last = [0u8; 16];
        last[..2].copy_from_slice(&(PR_STAMP_CACHE_MAX as u16).to_be_bytes());
        assert_eq!(stamper.cached(&last, &[0; 16]), Some([1; 14]));
        // Re-inserting keeps the entry's place, as a Python dict does.
        let mut second = [0u8; 16];
        second[..2].copy_from_slice(&2u16.to_be_bytes());
        stamper.insert_cached(pr_stamp_material(&second, &[0; 16]), [2; 14]);
        let mut next = [0u8; 16];
        next[..2].copy_from_slice(&999u16.to_be_bytes());
        stamper.insert_cached(pr_stamp_material(&next, &[0; 16]), [3; 14]);
        assert_eq!(stamper.cached(&second, &[0; 16]), Some([2; 14]));
        next[..2].copy_from_slice(&1000u16.to_be_bytes());
        stamper.insert_cached(pr_stamp_material(&next, &[0; 16]), [3; 14]);
        assert_eq!(stamper.cached(&second, &[0; 16]), None);
    }

    #[test]
    fn a_job_whose_stamp_was_cached_meanwhile_is_ready_at_once() {
        let mut stamper = PathRequestStamper::<2, 2>::new();
        let queued = job(1, PathRequestTarget::Interface(2), 60 * 256);
        stamper.enqueue(queued).unwrap();
        stamper.insert_cached(queued.material(), [7; 14]);
        assert_eq!(
            stamper.step(0, 0, |_| unreachable!()),
            StamperStep::Ready {
                job: queued,
                stamp: [7; 14]
            }
        );
    }

    #[test]
    fn the_running_search_is_kept_and_takes_one_slot() {
        let mut stamper = PathRequestStamper::<2, 0>::new();
        let running = job(1, PathRequestTarget::Interface(1), 60 * 256);
        stamper.enqueue(running).unwrap();
        let mut seed = 0;
        assert!(matches!(
            stamper.step(0, 2, counter(&mut seed)),
            StamperStep::Searching { attempts: 2, .. }
        ));
        assert!(matches!(
            stamper.step(1, 3, counter(&mut seed)),
            StamperStep::Searching { attempts: 5, .. }
        ));
        // A same-key job waits behind the running one instead of replacing it.
        stamper
            .enqueue(job(1, PathRequestTarget::Interface(1), 8))
            .unwrap();
        assert_eq!(stamper.active_job(), Some(running));
        assert_eq!(stamper.queue_len(), 1);
        assert_eq!(
            stamper.enqueue(job(2, PathRequestTarget::Interface(1), 8)),
            Err(QueueFull)
        );
    }
}
