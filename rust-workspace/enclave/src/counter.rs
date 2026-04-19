//! Software monotonic counter.
//!
//! Atomic write semantics: write to temp, fsync, rename. Guarantees the counter
//! file is never in an ambiguous state even if the process crashes mid-update.
//!
//! Scaffold only — implementation lands on Day 5.

#![allow(dead_code)]

pub struct MonotonicCounter;

impl MonotonicCounter {
    pub fn read(&self) -> anyhow::Result<u64> {
        anyhow::bail!("MonotonicCounter::read not implemented")
    }

    pub fn check_and_increment(&self) -> anyhow::Result<u64> {
        anyhow::bail!("MonotonicCounter::check_and_increment not implemented")
    }
}
