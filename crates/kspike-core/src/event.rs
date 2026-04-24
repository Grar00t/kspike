//! Event bus — in-process pub/sub for module coordination.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Trace,
    Info,
    Notice,
    Warn,
    Alert,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    ModuleLoaded { name: String },
    ModuleUnloaded { name: String },
    SignalIngested { signal_id: uuid::Uuid },
    VerdictIssued { module: String, verdict: String },
    JudgeRuling { allowed: bool, reason: String },
    StrikeFired { module: String, target: String, authorized_by: String },
    DefenseApplied { module: String, target: String },
    EvidenceSealed { record_id: uuid::Uuid, hash: String },
    RoeBreach { rule: String, context: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub severity: Severity,
    pub kind: EventKind,
}

impl Event {
    pub fn new(severity: Severity, kind: EventKind) -> Self {
        Self { ts: Utc::now(), severity, kind }
    }
}

type Subscriber = Box<dyn Fn(&Event) + Send + Sync + 'static>;

#[derive(Default, Clone)]
pub struct EventBus {
    inner: Arc<Mutex<Vec<Subscriber>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe<F>(&self, f: F)
    where
        F: Fn(&Event) + Send + Sync + 'static,
    {
        self.inner.lock().unwrap().push(Box::new(f));
    }

    pub fn publish(&self, event: Event) {
        let subs = self.inner.lock().unwrap();
        for s in subs.iter() {
            s(&event);
        }
    }
}
