//! Deterministic Arabic + English templates. Rooted in the Charter so the
//! prose never drifts from the rules it explains.

use crate::explainer::{Explanation, Locale};
use kspike_core::{ModuleKind, ModuleMeta, ModuleVerdict};
use kspike_judge::JudgeRuling;

pub fn render(locale: Locale, meta: &ModuleMeta, verdict: &ModuleVerdict, ruling: &JudgeRuling) -> Explanation {
    let (kind_ar, kind_en) = kind_words(meta.kind);
    let action_ar = action_arabic(verdict);
    let action_en = action_english(verdict);
    let principles: Vec<String> = charter_anchor(verdict, ruling.allowed)
        .into_iter().map(String::from).collect();

    let (headline, paragraph) = match locale {
        Locale::Arabic => arabic_par(meta, kind_ar, &action_ar, ruling, &principles),
        Locale::English => english_par(meta, kind_en, &action_en, ruling, &principles),
        Locale::Bilingual => {
            let (ah, ap) = arabic_par(meta, kind_ar, &action_ar, ruling, &principles);
            let (eh, ep) = english_par(meta, kind_en, &action_en, ruling, &principles);
            (format!("{ah} —— {eh}"), format!("{ap}\n\n——\n\n{ep}"))
        }
    };
    Explanation { locale, headline, paragraph, charter_principles: principles }
}

fn kind_words(k: ModuleKind) -> (&'static str, &'static str) {
    match k {
        ModuleKind::Detector  => ("كاشف",   "detector"),
        ModuleKind::Defender  => ("مدافع",   "defender"),
        ModuleKind::Striker   => ("مهاجم",   "striker"),
        ModuleKind::Deception => ("خديعة",   "deception"),
        ModuleKind::Forensic  => ("جنائي",   "forensic"),
    }
}

fn action_arabic(v: &ModuleVerdict) -> String {
    match v {
        ModuleVerdict::Ignore => "تجاهل".into(),
        ModuleVerdict::Report { note, .. } => format!("تقرير: {note}"),
        ModuleVerdict::Defend { action, target, .. } => format!("دفاع «{action}» على {target}"),
        ModuleVerdict::RequestStrike { action, target, .. } => format!("طلب ضربة «{action}» تجاه {target}"),
    }
}

fn action_english(v: &ModuleVerdict) -> String {
    match v {
        ModuleVerdict::Ignore => "ignored".into(),
        ModuleVerdict::Report { note, .. } => format!("report: {note}"),
        ModuleVerdict::Defend { action, target, .. } => format!("defense \"{action}\" on {target}"),
        ModuleVerdict::RequestStrike { action, target, .. } => format!("strike request \"{action}\" against {target}"),
    }
}

fn charter_anchor(v: &ModuleVerdict, allowed: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    out.push("الإنسان أولاً");
    out.push("الصدق");
    if matches!(v, ModuleVerdict::Defend { .. }) { out.push("الرحمة"); }
    if matches!(v, ModuleVerdict::RequestStrike { .. }) {
        out.push("العدل"); out.push("الشجاعة");
        if !allowed { out.push("الحكمة"); }
    }
    out.push("السرية");
    out
}

fn arabic_par(meta: &ModuleMeta, kind_ar: &str, action_ar: &str,
              ruling: &JudgeRuling, principles: &[String]) -> (String, String)
{
    let head = if ruling.allowed {
        format!("القرار: تنفيذ {action_ar}")
    } else {
        format!("القرار: رفض — {action_ar}")
    };
    let body = format!(
        "أصدر {kind_ar} «{name}» قراراً ({verdict_ar}). راجعه القاضي وفق ميثاق KSpike وأنتج الحكم: «{reason}». \
         المبادئ المُسْتنَدة في هذا القرار: {principles}. \
         القرار مختوم في السجل بتسلسل وتوقيع لا يُنقَض، فإن أُخطئ — والكمال وَهْم — \
         فالاعتراف بالخطأ مكتوب قبل الفعل.",
        name = meta.name,
        verdict_ar = action_ar,
        reason = ruling.reason,
        principles = principles.join("، "),
    );
    (head, body)
}

fn english_par(meta: &ModuleMeta, kind_en: &str, action_en: &str,
               ruling: &JudgeRuling, principles: &[String]) -> (String, String)
{
    let head = if ruling.allowed {
        format!("Decision: apply {action_en}")
    } else {
        format!("Decision: deny — {action_en}")
    };
    let body = format!(
        "The {kind_en} \"{name}\" produced a verdict ({verdict_en}). The Judge reviewed it under \
         the KSpike Charter and ruled: \"{reason}\". Anchored principles: {principles}. \
         The decision is sealed in the ledger with an unfalsifiable signature; if mistaken — \
         and perfection is a mirage — the admission of error is written before the act.",
        name = meta.name,
        verdict_en = action_en,
        reason = ruling.reason,
        principles = principles.join(", "),
    );
    (head, body)
}
