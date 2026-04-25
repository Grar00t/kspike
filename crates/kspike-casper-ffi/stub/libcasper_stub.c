/* libcasper_stub.c — minimal C11 reference implementation of the Casper FFI.
 *
 * Implements the four-symbol contract from `include/casper_ffi.h`. The stub
 * embeds a deterministic policy:
 *
 *   • verdict_kind == "strike" AND proportionality > 5  → DENY
 *   • verdict_kind == "strike" AND attack_certainty < 0.80 → DENY
 *   • risk_level > 8                                       → DENY
 *   • else                                                  → ALLOW
 *
 * This lets KSpike's CasperJudge integration be exercised end-to-end
 * without the full Casper Engine. Real Casper replaces this with neural
 * inference grounded in the KHZ_Q charter.
 *
 * Build:
 *   cc -O2 -Wall -shared -fPIC -o libcasper.so libcasper_stub.c
 *
 * Place the resulting libcasper.so in the loader's library search path
 * (LD_LIBRARY_PATH or /usr/local/lib + ldconfig), then build KSpike with
 *
 *   cargo build --release -p kspike-casper-ffi --features link_casper
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_inited = 0;

static const char *g_version = "casper-stub-1.0";

int casper_init(const char *model_path) {
    (void)model_path;
    g_inited = 1;
    return 0;
}

const char *casper_version(void) { return g_version; }

void casper_shutdown(void) { g_inited = 0; }

/* Tiny zero-alloc JSON field extractor: finds `"key":` and returns the value
 * up to the next comma or closing brace. Not a real parser — sufficient for
 * the controlled schema we accept. */
static int extract_str(const char *src, const char *key, char *out, size_t cap) {
    char tag[64];
    int n = snprintf(tag, sizeof(tag), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(tag)) return -1;
    const char *p = strstr(src, tag);
    if (!p) return -1;
    p += n;
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i + 1 < cap) out[i++] = *p++;
        out[i] = 0;
        return (int)i;
    }
    /* numeric or boolean — copy until separator */
    size_t i = 0;
    while (*p && *p != ',' && *p != '}' && *p != ' ' && i + 1 < cap) out[i++] = *p++;
    out[i] = 0;
    return (int)i;
}

static double extract_num(const char *src, const char *key, double def) {
    char buf[32];
    if (extract_str(src, key, buf, sizeof(buf)) <= 0) return def;
    return strtod(buf, NULL);
}

int casper_judge_evaluate(const char *req_json, char *out, int out_cap) {
    if (!g_inited) return -1;
    if (!req_json || !out || out_cap <= 0) return -1;

    char verdict_kind[32] = {0};
    extract_str(req_json, "verdict_kind", verdict_kind, sizeof(verdict_kind));
    double prop  = extract_num(req_json, "proportionality",   0.0);
    double cert  = extract_num(req_json, "attack_certainty",  0.0);
    double risk  = extract_num(req_json, "risk_level",        0.0);
    double conf  = extract_num(req_json, "confidence",        0.0);
    (void)conf;

    const char *decision  = "allow";
    const char *rationale = "stub: no objection";

    if (strcmp(verdict_kind, "strike") == 0) {
        if (prop > 5.0) {
            decision  = "deny";
            rationale = "stub: proportionality exceeds Charter ceiling (>5)";
        } else if (cert < 0.80) {
            decision  = "deny";
            rationale = "stub: attack certainty below 0.80; mercy default";
        }
    }
    if (strcmp(decision, "allow") == 0 && risk > 8.0) {
        decision  = "deny";
        rationale = "stub: module risk_level > 8 requires manual override";
    }

    int n = snprintf(out, (size_t)out_cap,
                     "{\"decision\":\"%s\",\"rationale\":\"%s\"}",
                     decision, rationale);
    if (n < 0 || n >= out_cap) return -1;
    return n;
}
