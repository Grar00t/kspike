//! Fitrah anchor sources.
//!
//! Per RULE_09 (FITRAH_ANCHOR), every balance must trace back to a declared
//! wisdom source. This module enumerates the accepted sources and exposes
//! a `FitrahAnchor` that a caller attaches to a balance request.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WisdomSource {
    Quran,
    Sunnah,
    Luqman,         // حكمة لقمان عليه السلام
    Khidr,          // المنهج اللدني — سورة الكهف
    Khawarizmi,     // الجبر والمقابلة
    IbnRushd,       // فصل المقال
    MaqasidSharia,  // الضروريات الخمس
    Quantum2026,    // modern Q-theoretic inputs
    ScientificConsensus,
    OperatorOverride, // the sovereign operator, logged explicitly
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitrahAnchor {
    pub primary: WisdomSource,
    pub secondary: Vec<WisdomSource>,
    pub citation: Option<String>, // e.g. "Q 31:13" or "Al-Jabr wa'l-Muqabala, ch.1"
    pub note: Option<String>,
}

impl FitrahAnchor {
    pub fn quran(citation: impl Into<String>) -> Self {
        Self {
            primary: WisdomSource::Quran,
            secondary: vec![],
            citation: Some(citation.into()),
            note: None,
        }
    }

    pub fn khawarizmi() -> Self {
        Self {
            primary: WisdomSource::Khawarizmi,
            secondary: vec![WisdomSource::Quran],
            citation: Some("Kitab al-Jabr wa'l-Muqabala".into()),
            note: None,
        }
    }

    pub fn operator(reason: impl Into<String>) -> Self {
        Self {
            primary: WisdomSource::OperatorOverride,
            secondary: vec![],
            citation: None,
            note: Some(reason.into()),
        }
    }
}
