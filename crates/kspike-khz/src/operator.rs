//! Al-Jabr and Al-Muqabala as typed operators.

use serde::{Deserialize, Serialize};

/// A signed scalar in [-1.0, 1.0] representing a directional ethical delta.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Delta(pub f32);

impl Delta {
    pub fn new(v: f32) -> Self { Self(v.clamp(-1.0, 1.0)) }
    pub fn abs(self) -> f32 { self.0.abs() }
    pub fn is_zero(self) -> bool { self.0.abs() < f32::EPSILON }
}

/// Σ of harm contributions, each a Delta.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarmVector {
    pub components: Vec<(String, Delta)>, // (label, magnitude)
}

impl HarmVector {
    pub fn add(&mut self, label: impl Into<String>, d: Delta) {
        self.components.push((label.into(), d));
    }
    pub fn sigma(&self) -> f32 {
        self.components.iter().map(|(_,d)| d.0.abs()).sum::<f32>().min(1.0)
    }
}

/// Σ of necessity contributions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NecessityVector {
    pub components: Vec<(String, Delta)>,
}

impl NecessityVector {
    pub fn add(&mut self, label: impl Into<String>, d: Delta) {
        self.components.push((label.into(), d));
    }
    pub fn sigma(&self) -> f32 {
        self.components.iter().map(|(_,d)| d.0.abs()).sum::<f32>().min(1.0)
    }
}

/// Fitrah alignment score in [0.0, 1.0].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Phi(pub f32);

impl Phi {
    pub fn new(v: f32) -> Self { Self(v.clamp(0.0, 1.0)) }
    pub fn value(self) -> f32 { self.0 }
}

/// Al-Jabr (الجبر) — restore missing terms toward Fitrah equilibrium.
///
/// If the harm and necessity vectors leave gaps (no term covering a domain),
/// Al-Jabr inserts the default Fitrah anchor value for that domain so the
/// balance computation is not biased by silence.
pub fn al_jabr(h: &mut HarmVector, n: &mut NecessityVector, fitrah_floor: f32) {
    // Simple policy: if one side is empty while the other is populated,
    // inject a neutral anchor so the equation is well-formed.
    if h.components.is_empty() && !n.components.is_empty() {
        h.add("__aljabr_fitrah_floor__", Delta::new(fitrah_floor));
    }
    if n.components.is_empty() && !h.components.is_empty() {
        n.add("__aljabr_fitrah_floor__", Delta::new(fitrah_floor));
    }
}

/// Al-Muqabala (المقابلة) — move opposing terms across the equality to
/// reveal the net direction.
///
/// Returns (net_pressure_toward_action, net_pressure_against_action).
pub fn al_muqabala(h: &HarmVector, n: &NecessityVector) -> (f32, f32) {
    let harm = h.sigma();
    let necessity = n.sigma();
    // Against-action pressure grows with harm; for-action pressure grows with necessity.
    let against = harm;
    let r#for   = necessity;
    (r#for, against)
}
