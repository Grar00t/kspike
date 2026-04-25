//! Renders an Arabic-friendly view of the evidence ledger for non-technical operators.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerView {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub category_ar: String,
    pub category_en: String,
    pub summary_ar: String,
    pub seal_short: String,        // first 16 hex of self_hash
}

impl LedgerView {
    pub fn from_record(rec: &serde_json::Value) -> Option<Self> {
        let seq = rec.get("seq")?.as_u64()?;
        let ts: DateTime<Utc> = rec.get("ts")?.as_str()?.parse().ok()?;
        let cat = rec.get("category")?.as_str()?;
        let hash = rec.get("self_hash")?.as_str()?;
        Some(Self {
            seq, ts,
            category_ar: cat_arabic(cat).into(),
            category_en: cat.into(),
            summary_ar: summarise(cat, rec),
            seal_short: hash.chars().take(16).collect(),
        })
    }
}

fn cat_arabic(c: &str) -> &'static str {
    match c {
        "signal"   => "إشارة",
        "verdict"  => "حكم",
        "judge"    => "قضاء",
        "defense"  => "دفاع",
        "strike"   => "ضربة",
        "report"   => "تقرير",
        "roe"      => "ميثاق",
        _          => "حدث",
    }
}

fn summarise(cat: &str, rec: &serde_json::Value) -> String {
    let p = rec.get("payload");
    match cat {
        "signal" => p.and_then(|v| v.get("kind")).and_then(|k| k.as_str())
            .map(|k| format!("إشارة من نوع {k}")).unwrap_or_else(|| "إشارة".into()),
        "verdict" => p.and_then(|v| v.get("module")).and_then(|m| m.as_str())
            .map(|m| format!("حكم من {m}")).unwrap_or_else(|| "حكم".into()),
        "judge" => {
            let allowed = p.and_then(|v| v.get("allowed")).and_then(|b| b.as_bool()).unwrap_or(false);
            if allowed { "قضى القاضي بالتنفيذ".into() }
            else       { "قضى القاضي بالرفض".into() }
        }
        "defense" => p.and_then(|v| v.get("target")).and_then(|t| t.as_str())
            .map(|t| format!("دفاع طُبِّق ضد {t}")).unwrap_or_else(|| "دفاع".into()),
        "strike"  => p.and_then(|v| v.get("target")).and_then(|t| t.as_str())
            .map(|t| format!("ضربة على {t}")).unwrap_or_else(|| "ضربة".into()),
        _ => format!("حدث: {cat}"),
    }
}
