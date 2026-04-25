//! The main explainer. Takes a JudgeRuling + the ModuleVerdict that prompted
//! it and returns a one-paragraph human-readable Explanation.

use kspike_core::{ModuleMeta, ModuleVerdict};
use kspike_judge::JudgeRuling;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Locale {
    Arabic,    // العربية النجدية الفصحى
    English,
    Bilingual, // ar then en, separated by `——`
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub locale: Locale,
    pub headline: String,
    pub paragraph: String,
    pub charter_principles: Vec<String>,
}

pub struct Explainer {
    pub locale: Locale,
}

impl Default for Explainer {
    fn default() -> Self { Self { locale: Locale::Arabic } }
}

impl Explainer {
    pub fn new(locale: Locale) -> Self { Self { locale } }

    pub fn explain(&self, meta: &ModuleMeta, verdict: &ModuleVerdict, ruling: &JudgeRuling) -> Explanation {
        // Try Casper first — falls back silently if unavailable.
        if let Some(e) = self.try_casper(meta, verdict, ruling) {
            return e;
        }
        crate::templates::render(self.locale, meta, verdict, ruling)
    }

    fn try_casper(&self, _meta: &ModuleMeta, _verdict: &ModuleVerdict, _ruling: &JudgeRuling) -> Option<Explanation> {
        if !kspike_casper_ffi::ffi::available() { return None; }
        // Round-trip a small JSON describing the situation.
        // Implementation kept brief; production would build a structured
        // request and parse the Casper response into the headline/paragraph.
        None
    }
}
