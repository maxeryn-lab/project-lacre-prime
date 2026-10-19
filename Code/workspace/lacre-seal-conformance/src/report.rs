//! Result of a conformance run: one entry per check, grouped.

use std::fmt::Write as _;

/// Family of checks. A failure names its group so that a reviewer (and the
/// suite's own mutation harness) can tell *which* class of defect was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    Metadata,
    Vectors,
    Lengths,
    Sensitivity,
    Parameters,
    Robustness,
    Statelessness,
    Crossed,
    Journey,
    Slowness,
    Cost,
}

impl Group {
    pub fn name(self) -> &'static str {
        match self {
            Group::Metadata => "metadata",
            Group::Vectors => "vectors",
            Group::Lengths => "lengths",
            Group::Sensitivity => "sensitivity",
            Group::Parameters => "parameters",
            Group::Robustness => "robustness",
            Group::Statelessness => "statelessness",
            Group::Crossed => "crossed",
            Group::Journey => "journey",
            Group::Slowness => "slowness",
            Group::Cost => "cost",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub group: Group,
    pub name: String,
    /// `None` = passed.
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    checks: Vec<Check>,
}

impl Report {
    pub(crate) fn push(&mut self, c: Check) {
        self.checks.push(c);
    }

    pub(crate) fn extend(&mut self, other: Report) {
        self.checks.extend(other.checks);
    }

    pub fn checks(&self) -> &[Check] {
        &self.checks
    }

    pub fn total(&self) -> usize {
        self.checks.len()
    }

    pub fn failures(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| c.failure.is_some()).collect()
    }

    /// True only if at least one check ran and none failed. An empty report
    /// is not a pass.
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.failures().is_empty()
    }

    pub fn failed_groups(&self) -> Vec<Group> {
        let mut g: Vec<Group> = self.failures().iter().map(|c| c.group).collect();
        g.sort();
        g.dedup();
        g
    }

    pub fn summary(&self) -> String {
        let mut s = String::new();
        for c in &self.checks {
            match &c.failure {
                None => {
                    let _ = writeln!(s, "[ok]   {}: {}", c.group.name(), c.name);
                }
                Some(why) => {
                    let _ = writeln!(s, "[FAIL] {}: {} — {}", c.group.name(), c.name, why);
                }
            }
        }
        let _ = writeln!(s, "{} checks, {} failed", self.total(), self.failures().len());
        s
    }

    /// Panics with the full summary unless the report passed.
    pub fn assert_passed(&self) {
        assert!(self.passed(), "conformance failed:\n{}", self.summary());
    }
}
