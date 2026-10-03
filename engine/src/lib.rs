use hmac::{Hmac, KeyInit, Mac};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::LazyLock;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// Static regex compilation — paid once, not on every pipeline run.
static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").expect("RE_EMAIL")
});
static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").expect("RE_IPV4")
});
static RE_IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b|\b::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b").expect("RE_IPV6")
});
// Removed undelimited 12-char hex form which caused false positives on SHA fragments.
static RE_MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").expect("RE_MAC"));
static RE_HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
        .expect("RE_HOSTNAME")
});
static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").expect("RE_JWT")
});
static RE_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
        .expect("RE_UUID")
});
static RE_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\+\d{1,3}\s?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}").expect("RE_PHONE")
});
// Captures area/group/serial so `is_valid_ssn` can reject reserved ranges. The previous
// pattern used negative lookahead, which the `regex` crate does not support — it failed to
// compile, so the SSN step panicked on first use.
static RE_SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{3})[-\s]?(\d{2})[-\s]?(\d{4})\b").expect("RE_SSN"));
// Covers the 13-19 digit range that luhn_check accepts (Visa-13, Amex-15, Visa/MC-16,
// Maestro-19), with optional space/dash grouping. Luhn post-filter does the real validation.
static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}(?:[\s-]?\d){9,15}\b").expect("RE_CREDIT_CARD"));
static RE_API_KEY_GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk|pk|api|token|key|secret)[\-_][a-zA-Z0-9]{20,}\b")
        .expect("RE_API_KEY_GENERIC")
});
// Fixed: was r#"https?://[^\s<>"]+#"# which required a literal # at the end of every URL.
static RE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s<>"']+"#).expect("RE_URL"));
static RE_USERNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:@|user=|username=|/home/|/users/)([a-zA-Z0-9_-]{3,32})\b").expect("RE_USERNAME")
});
static RE_BASE64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").expect("RE_BASE64"));
static RE_OAUTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bya29\.[a-zA-Z0-9_-]{50,}\b").expect("RE_OAUTH"));

// --- Helper functions ---

fn floor_char_boundary(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    (0..=pos)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0)
}

fn ceil_char_boundary(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    (pos..=text.len())
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(text.len())
}

// Treats n as a Unicode character index, returns the corresponding byte index.
fn char_to_byte_idx(text: &str, n: usize) -> usize {
    text.char_indices()
        .nth(n)
        .map(|(i, _)| i)
        .unwrap_or(text.len())
}

// Repeats mask_char once per *character* of `original`. Using byte length here would emit
// too many mask characters for any non-ASCII value.
//
// `fixed_width` emits exactly that many mask characters instead, so the output does not
// disclose how long the redacted value was. `None` keeps the original length.
fn mask_all(original: &str, mask_char: &str, fixed_width: Option<usize>) -> String {
    mask_char.repeat(fixed_width.unwrap_or_else(|| original.chars().count()))
}

// Masks everything but the last `n` characters. Slicing by byte offset here would panic
// whenever the cut landed inside a multi-byte character.
//
// With `fixed_width`, the masked portion is always that many characters wide, so the total
// length no longer reveals the size of the original value.
fn mask_preserving_last_n(
    original: &str,
    n: usize,
    mask_char: &str,
    fixed_width: Option<usize>,
) -> String {
    let char_count = original.chars().count();
    if char_count <= n {
        // Nothing would be masked; emit a fixed-width mask rather than echoing the value back.
        return match fixed_width {
            Some(w) => mask_char.repeat(w),
            None => original.to_string(),
        };
    }
    let split = char_to_byte_idx(original, char_count - n);
    let mask_width = fixed_width.unwrap_or(char_count - n);
    format!("{}{}", mask_char.repeat(mask_width), &original[split..])
}

fn parse_ipv4(ip: &str) -> Option<u32> {
    let parts: Vec<u32> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 || parts.iter().any(|&p| p > 255) {
        return None;
    }
    Some((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
}

fn is_in_subnet(ip: &str, cidr: &str) -> bool {
    let (network, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let prefix_len: u32 = prefix.parse().unwrap_or(32);
    if prefix_len > 32 {
        return false;
    }
    let Some(ip_num) = parse_ipv4(ip) else {
        return false;
    };
    let Some(net_num) = parse_ipv4(network) else {
        return false;
    };
    if prefix_len == 0 {
        return true;
    }
    let mask = !0u32 << (32 - prefix_len);
    (ip_num & mask) == (net_num & mask)
}

fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let v = d * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

// Characters of surrounding text kept with each canonical entry for the UI tooltip.
const CONTEXT_WINDOW: usize = 20;
// Distinct contexts stored per canonical value.
const MAX_CONTEXTS: usize = 3;

/// Byte span of a JSON value, and whether it was a quoted string.
/// For a quoted string this is the span *inside* the quotes, so they survive redaction and
/// the surrounding JSON stays parseable. For every other value it is the whole token.
struct JsonValueSpan {
    start: usize,
    end: usize,
}

/// Finds the JSON value starting at or after `from`, tolerantly: the input is usually a log
/// line that merely *contains* JSON, not a whole well-formed document.
///
/// Replaces a regex of the form `"key"\s*:\s*"([^"]+)"`, which only ever saw double-quoted
/// strings and mis-terminated on an escaped quote.
fn scan_json_value(text: &str, from: usize) -> Option<JsonValueSpan> {
    let bytes = text.as_bytes();
    let mut i = from;
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }

    match bytes[i] {
        b'"' => {
            let inner_start = i + 1;
            let mut j = inner_start;
            while j < bytes.len() {
                match bytes[j] {
                    // Skip the escaped byte, so " does not end the string early.
                    b'\\' => j += 2,
                    b'"' => {
                        return Some(JsonValueSpan {
                            start: inner_start,
                            end: j,
                        });
                    }
                    _ => j += 1,
                }
            }
            None // unterminated string
        }
        open @ (b'{' | b'[') => {
            let close = if open == b'{' { b'}' } else { b']' };
            let mut depth = 0usize;
            let mut j = i;
            let mut in_string = false;
            while j < bytes.len() {
                let c = bytes[j];
                if in_string {
                    match c {
                        b'\\' => j += 1,
                        b'"' => in_string = false,
                        _ => {}
                    }
                } else {
                    match c {
                        b'"' => in_string = true,
                        _ if c == open => depth += 1,
                        _ if c == close => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(JsonValueSpan {
                                    start: i,
                                    end: j + 1,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                j += 1;
            }
            None // unbalanced
        }
        _ => {
            // Number, true, false, null, or any bare token: run to the first delimiter.
            let mut j = i;
            while j < bytes.len() && !matches!(bytes[j], b',' | b'}' | b']' | b'\n' | b'\r') {
                j += 1;
            }
            // Trailing whitespace is not part of the value.
            while j > i && (bytes[j - 1] as char).is_whitespace() {
                j -= 1;
            }
            if j > i {
                Some(JsonValueSpan { start: i, end: j })
            } else {
                None
            }
        }
    }
}

/// Byte span covering characters `start_char..end_char` of `slice`, clamped to its length.
/// Returns None when the range falls entirely outside the slice or is empty.
fn span_in(slice: &str, start_char: usize, end_char: usize) -> Option<(usize, usize)> {
    let char_count = slice.chars().count();
    if start_char >= char_count {
        return None;
    }
    let end_char = end_char.min(char_count);
    if start_char >= end_char {
        return None;
    }
    Some((
        char_to_byte_idx(slice, start_char),
        char_to_byte_idx(slice, end_char),
    ))
}

// Rejects the SSN ranges the SSA never issues: area 000, 666 or 900-999, group 00,
// serial 0000. Mirrors what the old lookahead pattern was trying to express.
fn is_valid_ssn(captures: &regex::Captures) -> bool {
    let group_of = |i: usize| captures.get(i).map(|m| m.as_str()).unwrap_or("");
    let (area, group, serial) = (group_of(1), group_of(2), group_of(3));
    if area.is_empty() || group.is_empty() || serial.is_empty() {
        return false;
    }
    !matches!(area, "000" | "666") && !area.starts_with('9') && group != "00" && serial != "0000"
}

// --- Data structures ---

/// Why a span of the current text is off-limits to the remaining steps.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionKind {
    /// Text a step already replaced. Re-matching it only corrupts the placeholder.
    Redacted,
    /// A value the user configured to keep, via an allowlist or a subnet exclusion.
    /// Honouring that across the whole pipeline is the point of the option.
    Exempt,
}

/// A byte range of the *current* text that later steps must leave alone.
///
/// Spans are translated forward through every rewrite, so by the end of the run they address
/// the final output. The list is kept sorted by `start` and non-overlapping.
#[derive(Serialize, Clone, Debug)]
pub struct ProtectedSpan {
    pub start: usize,
    pub end: usize,
    pub kind: ProtectionKind,
    /// Token prefix of the step that claimed it, so the UI can say which rule applied.
    pub rule: String,
}

/// What a detector's filter decided about a candidate match.
///
/// Replaces a plain `bool`, which conflated two very different rejections: "this is not
/// really an instance of this type" (a later step should still be free to match it) and
/// "the user asked to keep this" (nothing may touch it again).
enum MatchVerdict {
    Redact,
    /// Failed a validity check, e.g. Luhn or an SSN reserved range.
    NotAMatch,
    /// Excluded by user configuration.
    Exempt,
}

/// Candidate matches from one detector pass.
struct Candidates {
    /// Ranges to replace, ascending and non-overlapping, with the matched text.
    hits: Vec<(usize, usize, String)>,
    /// Ranges the user configured to keep.
    exempt: Vec<(usize, usize)>,
}

impl Candidates {
    fn from_hits(hits: Vec<(usize, usize, String)>) -> Self {
        Self {
            hits,
            exempt: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CanonicalEntry {
    pub id: String,
    pub r#type: String,
    pub original: String,
    pub fingerprint: String,
    pub occurrences: usize,
    pub contexts: Vec<String>,
    pub context_before: String,
    pub context_after: String,
    pub method: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StepConfig {
    pub id: String,
    pub r#type: String,
    pub enabled: bool,
    pub label: Option<String>,
    pub config: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineConfig {
    pub version: usize,
    pub steps: Vec<StepConfig>,
}

/// Naming and redaction settings for one detector pass.
struct PassSpec<'a> {
    /// Token prefix, e.g. "EMAIL" — becomes `<EMAIL_1>`.
    type_upper: &'a str,
    /// Canonical type recorded in the map, e.g. "email".
    type_lower: &'a str,
    config: &'a serde_json::Value,
}

// --- Engine ---

#[wasm_bindgen]
pub struct Engine {
    session_secret: [u8; 32],
    canonical_map: HashMap<String, CanonicalEntry>,
    next_ids: HashMap<String, usize>,
    /// Spans protected for the remainder of the current pipeline run.
    protected_spans: Vec<ProtectedSpan>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.session_secret.zeroize();
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl Engine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("getrandom failed");
        Self {
            session_secret: secret,
            canonical_map: HashMap::new(),
            next_ids: HashMap::new(),
            protected_spans: Vec::new(),
        }
    }

    pub fn run_pipeline(&mut self, input: &str, config_json: &str) -> Result<String, JsValue> {
        let config: PipelineConfig = serde_json::from_str(config_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid pipeline config: {}", e)))?;

        self.protected_spans.clear();
        self.canonical_map.clear();
        self.next_ids.clear();

        let mut current_text = input.to_string();
        for step in config.steps.iter().filter(|s| s.enabled) {
            current_text = self.execute_step(step, &current_text)?;
        }
        Ok(current_text)
    }

    fn execute_step(&mut self, step: &StepConfig, text: &str) -> Result<String, JsValue> {
        let type_prefix = if let Some(label) = &step.label {
            if !label.is_empty() {
                // Cap label length to 64 chars to prevent oversized tokens.
                let capped: String = label.chars().take(64).collect();
                capped
                    .to_uppercase()
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { '_' })
                    .collect()
            } else {
                self.get_default_type_prefix(&step.r#type)
            }
        } else {
            self.get_default_type_prefix(&step.r#type)
        };

        match step.r#type.as_str() {
            "email" => self.redact_email(text, &step.config, &type_prefix),
            "regex" => self.redact_regex(text, &step.config, &type_prefix),
            "ipv4" => self.redact_ipv4(text, &step.config, &type_prefix),
            "ipv6" => self.redact_with_regex(text, &RE_IPV6, &type_prefix, "ipv6", &step.config),
            "mac" => self.redact_with_regex(text, &RE_MAC, &type_prefix, "mac", &step.config),
            "hostname" => {
                self.redact_with_regex(text, &RE_HOSTNAME, &type_prefix, "hostname", &step.config)
            }
            "jwt" => self.redact_with_regex(text, &RE_JWT, &type_prefix, "jwt", &step.config),
            "uuid" => self.redact_with_regex(text, &RE_UUID, &type_prefix, "uuid", &step.config),
            "phone" => self.redact_with_regex(text, &RE_PHONE, &type_prefix, "phone", &step.config),
            "ssn" => self.redact_ssn(text, &step.config, &type_prefix),
            "credit_card" => self.redact_credit_card(text, &step.config, &type_prefix),
            "api_key" | "apikey" => self.redact_api_key(text, &step.config, &type_prefix),
            "url" => self.redact_with_regex(text, &RE_URL, &type_prefix, "url", &step.config),
            "username" => self.redact_username(text, &step.config, &type_prefix),
            "base64" => {
                self.redact_with_regex(text, &RE_BASE64, &type_prefix, "base64", &step.config)
            }
            "json_key" | "jsonKey" => self.redact_json_key(text, &step.config, &type_prefix),
            "query_param" | "queryParam" => {
                self.redact_query_param(text, &step.config, &type_prefix)
            }
            "http_header" | "header" => self.redact_http_header(text, &step.config, &type_prefix),
            "replace" => self.redact_replace(text, &step.config, &type_prefix),
            "partial_mask" | "partialMask" => {
                self.redact_partial_mask(text, &step.config, &type_prefix)
            }
            "oauth" => self.redact_with_regex(text, &RE_OAUTH, &type_prefix, "oauth", &step.config),
            _ => Ok(text.to_string()),
        }
    }

    fn get_default_type_prefix(&self, step_type: &str) -> String {
        match step_type {
            "email" => "EMAIL",
            "regex" => "REGEX",
            "ipv4" => "IPV4",
            "ipv6" => "IPV6",
            "mac" => "MAC",
            "hostname" => "HOSTNAME",
            "jwt" => "JWT",
            "uuid" => "UUID",
            "phone" => "PHONE",
            "ssn" => "SSN",
            "credit_card" => "CC",
            "api_key" | "apikey" => "APIKEY",
            "url" => "URL",
            "username" => "USERNAME",
            "base64" => "BASE64",
            "json_key" | "jsonKey" => "JSON",
            "query_param" | "queryParam" => "PARAM",
            "http_header" | "header" => "HEADER",
            "replace" => "REPLACE",
            "partial_mask" | "partialMask" => "MASK",
            "oauth" => "OAUTH",
            _ => "REDACTED",
        }
        .to_string()
    }

    // Collects the byte ranges a pass will replace. `capture_group` selects which group of the
    // match is redacted (0 = whole match). Matches already claimed by this pass are skipped.
    fn collect_hits(
        &self,
        text: &str,
        regex: &Regex,
        capture_group: usize,
        verdict_of: impl Fn(&Captures) -> MatchVerdict,
    ) -> Candidates {
        let mut hits = Vec::new();
        let mut exempt = Vec::new();

        for cap in regex.captures_iter(text) {
            let Some(m) = cap.get(capture_group) else {
                continue;
            };
            match verdict_of(&cap) {
                MatchVerdict::NotAMatch => continue,
                MatchVerdict::Exempt => {
                    // Protect the whole match, not just the capture group: allowlisting
                    // "corp.com" means keeping "ops@corp.com" intact, including the local
                    // part a later username step would otherwise mask.
                    let whole = cap.get(0).unwrap_or(m);
                    exempt.push((whole.start(), whole.end()));
                }
                MatchVerdict::Redact => {
                    if !self.is_protected(m.start(), m.end()) {
                        hits.push((m.start(), m.end(), m.as_str().to_string()));
                    }
                }
            }
        }

        Candidates { hits, exempt }
    }

    // Records a hit in the canonical map (collapsing repeat values onto one token) and returns
    // the placeholder id to substitute.
    fn register_hit(
        &mut self,
        text: &str,
        start: usize,
        end: usize,
        original: &str,
        spec: &PassSpec,
    ) -> String {
        let fingerprint = self.generate_fingerprint(original);
        // Clamp context to char boundaries to avoid UTF-8 panics.
        let ctx_start = floor_char_boundary(text, start.saturating_sub(CONTEXT_WINDOW));
        let ctx_end = ceil_char_boundary(text, end + CONTEXT_WINDOW);
        let context_before = text[ctx_start..start].to_string();
        let context_after = text[end..ctx_end].to_string();
        let context = format!("{}{}", context_before, context_after);

        let next_ids = &mut self.next_ids;
        let entry = self
            .canonical_map
            .entry(fingerprint.clone())
            .or_insert_with(|| {
                let count = next_ids.entry(spec.type_upper.to_string()).or_insert(1);
                let id = format!("{}_{}", spec.type_upper, count);
                *count += 1;
                CanonicalEntry {
                    id,
                    r#type: spec.type_lower.to_string(),
                    original: original.to_string(),
                    fingerprint,
                    occurrences: 0,
                    contexts: vec![],
                    context_before,
                    context_after,
                    method: spec.type_lower.to_string(),
                }
            });

        entry.occurrences += 1;
        if entry.contexts.len() < MAX_CONTEXTS && !entry.contexts.contains(&context) {
            entry.contexts.push(context);
        }
        entry.id.clone()
    }

    // Rebuilds the text in a single forward pass. The previous implementation called
    // `replace_range` per hit and tracked a running offset, which was O(n) per replacement.
    fn apply_hits(&mut self, text: &str, candidates: Candidates, spec: &PassSpec) -> String {
        let Candidates { hits, exempt } = candidates;

        if hits.is_empty() {
            // Nothing moves, so the existing spans stay valid as they are.
            self.record_spans(&exempt, ProtectionKind::Exempt, spec.type_upper);
            return text.to_string();
        }

        let mut result = String::with_capacity(text.len());
        let mut cursor = 0usize;
        // (old offset, new offset) at the start of each copied run of untouched text, used to
        // translate surviving spans into the rewritten string's coordinates.
        let mut checkpoints: Vec<(usize, usize)> = Vec::with_capacity(hits.len() + 1);
        // Replacement spans, already in new coordinates.
        let mut written: Vec<(usize, usize)> = Vec::with_capacity(hits.len());

        for (start, end, original) in hits {
            // captures_iter yields ascending, non-overlapping matches; guard anyway so a
            // malformed hit list can never panic on a reversed slice.
            if start < cursor {
                continue;
            }
            checkpoints.push((cursor, result.len()));
            result.push_str(&text[cursor..start]);

            let canonical_id = self.register_hit(text, start, end, &original, spec);
            let replacement = self.apply_redaction_mode(&original, &canonical_id, spec.config);
            let written_start = result.len();
            result.push_str(&replacement);
            written.push((written_start, result.len()));
            cursor = end;
        }
        checkpoints.push((cursor, result.len()));
        result.push_str(&text[cursor..]);

        // Every span that survives this pass sits in text that was copied verbatim, because
        // hits overlapping a protected span were dropped at collection time and a pass cannot
        // both redact and exempt the same range.
        let translate = |offset: usize| -> usize {
            let i = checkpoints.partition_point(|(old, _)| *old <= offset);
            let (old, new) = checkpoints[i.saturating_sub(1)];
            new + offset.saturating_sub(old)
        };

        let mut next: Vec<ProtectedSpan> = self
            .protected_spans
            .drain(..)
            .map(|span| ProtectedSpan {
                start: translate(span.start),
                end: translate(span.end),
                ..span
            })
            .collect();

        next.extend(exempt.iter().map(|(start, end)| ProtectedSpan {
            start: translate(*start),
            end: translate(*end),
            kind: ProtectionKind::Exempt,
            rule: spec.type_upper.to_string(),
        }));
        next.extend(written.into_iter().map(|(start, end)| ProtectedSpan {
            start,
            end,
            kind: ProtectionKind::Redacted,
            rule: spec.type_upper.to_string(),
        }));

        self.protected_spans = Self::normalise_spans(next);
        result
    }

    /// Adds spans that need no translation, because the text did not change.
    fn record_spans(&mut self, spans: &[(usize, usize)], kind: ProtectionKind, rule: &str) {
        if spans.is_empty() {
            return;
        }
        let mut next = std::mem::take(&mut self.protected_spans);
        next.extend(spans.iter().map(|(start, end)| ProtectedSpan {
            start: *start,
            end: *end,
            kind,
            rule: rule.to_string(),
        }));
        self.protected_spans = Self::normalise_spans(next);
    }

    /// Sorts by start and merges touching or overlapping spans, so the list stays sorted by
    /// both ends and `is_protected` can binary-search it.
    ///
    /// Overlaps in practice only come from two steps exempting the same range, which carry the
    /// same kind; a redacted span and an exempt span always occupy disjoint text.
    fn normalise_spans(mut spans: Vec<ProtectedSpan>) -> Vec<ProtectedSpan> {
        spans.retain(|s| s.end > s.start);
        spans.sort_by_key(|s| (s.start, s.end));

        let mut merged: Vec<ProtectedSpan> = Vec::with_capacity(spans.len());
        for span in spans {
            match merged.last_mut() {
                Some(last) if span.start <= last.end => {
                    last.end = last.end.max(span.end);
                    // Prefer Exempt when reporting: it is the one the user asked for.
                    if span.kind == ProtectionKind::Exempt {
                        last.kind = ProtectionKind::Exempt;
                        last.rule = span.rule;
                    }
                }
                _ => merged.push(span),
            }
        }
        merged
    }

    // Single entry point for every regex-driven detector.
    fn redact_matches(
        &mut self,
        text: &str,
        regex: &Regex,
        capture_group: usize,
        spec: &PassSpec,
        verdict_of: impl Fn(&Captures) -> MatchVerdict,
    ) -> Result<String, JsValue> {
        let candidates = self.collect_hits(text, regex, capture_group, verdict_of);
        Ok(self.apply_hits(text, candidates, spec))
    }

    fn redact_with_regex_filtered(
        &mut self,
        text: &str,
        regex: &Regex,
        type_upper: &str,
        type_lower: &str,
        config: &serde_json::Value,
        verdict_of: impl Fn(&Captures) -> MatchVerdict,
    ) -> Result<String, JsValue> {
        let spec = PassSpec {
            type_upper,
            type_lower,
            config,
        };
        self.redact_matches(text, regex, 0, &spec, verdict_of)
    }

    fn redact_with_regex(
        &mut self,
        text: &str,
        regex: &Regex,
        type_upper: &str,
        type_lower: &str,
        config: &serde_json::Value,
    ) -> Result<String, JsValue> {
        let spec = PassSpec {
            type_upper,
            type_lower,
            config,
        };
        self.redact_matches(text, regex, 0, &spec, |_| MatchVerdict::Redact)
    }

    fn redact_captures(
        &mut self,
        text: &str,
        regex: &Regex,
        capture_group: usize,
        type_upper: &str,
        type_lower: &str,
        config: &serde_json::Value,
    ) -> Result<String, JsValue> {
        let spec = PassSpec {
            type_upper,
            type_lower,
            config,
        };
        self.redact_matches(text, regex, capture_group, &spec, |_| MatchVerdict::Redact)
    }

    // --- Detectors with domain/subnet filtering ---

    fn redact_email(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        let allowed_domains: Vec<String> = config
            .get("allowedDomains")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if allowed_domains.is_empty() {
            return self.redact_with_regex(text, &RE_EMAIL, type_prefix, "email", config);
        }

        self.redact_with_regex_filtered(text, &RE_EMAIL, type_prefix, "email", config, |cap| {
            let domain = cap[0]
                .split_once('@')
                .map(|(_, d)| d)
                .unwrap_or("")
                .to_lowercase();
            let allowed = allowed_domains
                .iter()
                .any(|ad| domain == *ad || domain.ends_with(&format!(".{}", ad)));
            // The user asked to keep these, so protect them from the rest of the pipeline.
            if allowed {
                MatchVerdict::Exempt
            } else {
                MatchVerdict::Redact
            }
        })
    }

    fn redact_ipv4(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        let excluded_subnets: Vec<String> = config
            .get("excludeSubnets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if excluded_subnets.is_empty() {
            return self.redact_with_regex(text, &RE_IPV4, type_prefix, "ipv4", config);
        }

        self.redact_with_regex_filtered(text, &RE_IPV4, type_prefix, "ipv4", config, |cap| {
            let excluded = excluded_subnets
                .iter()
                .any(|cidr| is_in_subnet(&cap[0], cidr));
            if excluded {
                MatchVerdict::Exempt
            } else {
                MatchVerdict::Redact
            }
        })
    }

    fn redact_credit_card(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        self.redact_with_regex_filtered(
            text,
            &RE_CREDIT_CARD,
            type_prefix,
            "credit_card",
            config,
            // A failed Luhn check means this was never a card number, so later steps stay
            // free to match the same digits.
            |cap| {
                if luhn_check(&cap[0]) {
                    MatchVerdict::Redact
                } else {
                    MatchVerdict::NotAMatch
                }
            },
        )
    }

    fn redact_ssn(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        self.redact_with_regex_filtered(text, &RE_SSN, type_prefix, "ssn", config, |cap| {
            if is_valid_ssn(cap) {
                MatchVerdict::Redact
            } else {
                MatchVerdict::NotAMatch
            }
        })
    }

    fn redact_regex(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        let pattern = config
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Regex pattern not provided"))?;
        if pattern.is_empty() {
            return Ok(text.to_string());
        }
        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return Ok(text.to_string()),
        };
        self.redact_with_regex(text, &regex, type_prefix, "regex", config)
    }

    fn redact_api_key(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        let regex = if let Some(prefix) = config.get("prefix").and_then(|v| v.as_str()) {
            if !prefix.is_empty() {
                let pattern = format!(r"\b{}[\-_]?[a-zA-Z0-9]{{20,}}\b", regex::escape(prefix));
                match Regex::new(&pattern) {
                    Ok(r) => r,
                    Err(_) => return Ok(text.to_string()),
                }
            } else {
                RE_API_KEY_GENERIC.clone()
            }
        } else {
            RE_API_KEY_GENERIC.clone()
        };
        self.redact_with_regex(text, &regex, type_prefix, "api_key", config)
    }

    fn redact_replace(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        let search = config
            .get("search")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Search string not provided"))?;
        if search.is_empty() {
            return Ok(text.to_string());
        }
        let regex = Regex::new(&regex::escape(search)).unwrap();
        self.redact_with_regex(text, &regex, type_prefix, "replace", config)
    }

    /// Masks a character range by position rather than by pattern.
    ///
    /// `scope` selects what the offsets are relative to:
    /// - `"line"` — the range is applied to **every** line, which is what you want for
    ///   fixed-width columns such as leading timestamps.
    /// - `"document"` (default, kept for existing recipes) — one range, counted from the
    ///   start of the whole input. Only ever masks a single span.
    fn redact_partial_mask(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        // Offsets are Unicode character indices, not bytes, to avoid UTF-8 boundary panics.
        let start_char = config.get("start").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let end_char = config.get("end").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        if start_char >= end_char {
            return Ok(text.to_string());
        }

        let per_line = matches!(
            config
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("document"),
            "line" | "per_line" | "perLine"
        );

        // This step masks by definition, so pin the mode rather than inheriting the
        // placeholder default from apply_redaction_mode. maskChar and maskLength still apply.
        let mut mask_config = config.clone();
        if let Some(obj) = mask_config.as_object_mut() {
            obj.insert("mode".to_string(), serde_json::Value::from("mask"));
            obj.remove("replacement");
        }
        let spec = PassSpec {
            type_upper: type_prefix,
            type_lower: "partial_mask",
            config: &mask_config,
        };

        // Resolve the byte spans to mask, in ascending order, so apply_hits can do its
        // single forward pass. In document scope that is at most one span.
        let mut hits: Vec<(usize, usize, String)> = Vec::new();
        if per_line {
            let mut line_start = 0usize;
            // split_inclusive keeps the newline, so byte offsets stay aligned with `text`.
            for line in text.split_inclusive('\n') {
                let content = line.strip_suffix('\n').unwrap_or(line);
                let content = content.strip_suffix('\r').unwrap_or(content);
                if let Some((s, e)) = span_in(content, start_char, end_char) {
                    hits.push((line_start + s, line_start + e, content[s..e].to_string()));
                }
                line_start += line.len();
            }
        } else if let Some((s, e)) = span_in(text, start_char, end_char) {
            hits.push((s, e, text[s..e].to_string()));
        }

        hits.retain(|(s, e, _)| !self.is_protected(*s, *e));
        Ok(self.apply_hits(text, Candidates::from_hits(hits), &spec))
    }

    fn redact_username(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        // Group 1 is the username itself; the leading @ / user= / /home/ marker is left in place.
        self.redact_captures(text, &RE_USERNAME, 1, type_prefix, "username", config)
    }

    // Reads a list of names from config and returns them as an escaped regex alternation.
    fn names_alternation(config: &serde_json::Value, field: &str) -> Option<String> {
        let pattern = config
            .get(field)?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(regex::escape)
            .collect::<Vec<_>>()
            .join("|");
        if pattern.is_empty() {
            None
        } else {
            Some(pattern)
        }
    }

    // Builds a detector from a name list, redacting capture group 1. Returns the text unchanged
    // when no names are configured.
    fn redact_named_targets(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
        type_lower: &str,
        field: &str,
        pattern_for: impl Fn(&str) -> String,
    ) -> Result<String, JsValue> {
        let Some(alternation) = Self::names_alternation(config, field) else {
            return Ok(text.to_string());
        };
        let regex = match Regex::new(&pattern_for(&alternation)) {
            Ok(r) => r,
            Err(_) => return Ok(text.to_string()),
        };
        self.redact_captures(text, &regex, 1, type_prefix, type_lower, config)
    }

    fn redact_json_key(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        let Some(alternation) = Self::names_alternation(config, "keys") else {
            return Ok(text.to_string());
        };
        // Match only the key and its colon; the value's extent is then found by scanning, so
        // numbers, booleans, null, nested objects/arrays and escaped quotes all work. The
        // previous regex (`"key"\s*:\s*"([^"]+)"`) saw only plain strings and terminated
        // early on the first escaped quote.
        let key_regex = match Regex::new(&format!(r#"(?i)"(?:{})"\s*:"#, alternation)) {
            Ok(r) => r,
            Err(_) => return Ok(text.to_string()),
        };

        let hits: Vec<(usize, usize, String)> = key_regex
            .find_iter(text)
            .filter_map(|m| {
                let span = scan_json_value(text, m.end())?;
                if span.end <= span.start || self.is_protected(span.start, span.end) {
                    return None;
                }
                Some((span.start, span.end, text[span.start..span.end].to_string()))
            })
            .collect();

        let spec = PassSpec {
            type_upper: type_prefix,
            type_lower: "json_key",
            config,
        };
        Ok(self.apply_hits(text, Candidates::from_hits(hits), &spec))
    }

    fn redact_query_param(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        self.redact_named_targets(text, config, type_prefix, "query_param", "names", |names| {
            format!(r#"(?i)[?&](?:{})=([^&\s#]+)"#, names)
        })
    }

    fn redact_http_header(
        &mut self,
        text: &str,
        config: &serde_json::Value,
        type_prefix: &str,
    ) -> Result<String, JsValue> {
        self.redact_named_targets(text, config, type_prefix, "http_header", "names", |names| {
            format!(r#"(?i)\b(?:{}):\s*([^\r\n]+)"#, names)
        })
    }

    /// True when `start..end` overlaps anything an earlier step redacted or exempted.
    fn is_protected(&self, start: usize, end: usize) -> bool {
        // The list is sorted and non-overlapping, so the first span that could overlap is the
        // first whose end is past `start`.
        let from = self.protected_spans.partition_point(|s| s.end <= start);
        self.protected_spans
            .get(from)
            .is_some_and(|s| s.start < end)
    }

    /// `maskLength` > 0 pins the mask to a fixed number of characters. Absent or 0 keeps the
    /// original value's length (the historical behaviour).
    fn fixed_mask_width(config: &serde_json::Value) -> Option<usize> {
        config
            .get("maskLength")
            .and_then(|v| v.as_u64())
            .filter(|n| *n > 0)
            .map(|n| n as usize)
    }

    fn mask_char(config: &serde_json::Value) -> &str {
        config
            .get("maskChar")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
    }

    fn apply_redaction_mode(
        &self,
        original: &str,
        canonical_id: &str,
        config: &serde_json::Value,
    ) -> String {
        if let Some(replacement) = config.get("replacement").and_then(|v| v.as_str()) {
            if !replacement.is_empty() {
                return replacement.to_string();
            }
        }
        match config
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("placeholder")
        {
            "mask" => mask_all(
                original,
                Self::mask_char(config),
                Self::fixed_mask_width(config),
            ),
            "preserveLastN" => {
                let n = config
                    .get("preserveCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(4) as usize;
                mask_preserving_last_n(
                    original,
                    n,
                    Self::mask_char(config),
                    Self::fixed_mask_width(config),
                )
            }
            _ => format!("<{}>", canonical_id),
        }
    }

    fn generate_fingerprint(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.session_secret).unwrap();
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Spans of the final output that were deliberately kept, as
    /// `[{ start, end, kind, rule }]` in byte offsets.
    ///
    /// Because every pass translates its spans forward, these already address the string
    /// `run_pipeline` returned. Only exemptions are reported: redacted spans are visible as
    /// placeholders already.
    pub fn get_exempt_spans_json(&self) -> String {
        let exempt: Vec<&ProtectedSpan> = self
            .protected_spans
            .iter()
            .filter(|s| s.kind == ProtectionKind::Exempt)
            .collect();
        serde_json::to_string(&exempt).unwrap_or_else(|_| "[]".to_string())
    }

    pub fn get_canonical_map_json(&self) -> String {
        let redaction_count: usize = self.canonical_map.values().map(|e| e.occurrences).sum();
        let wrapper = serde_json::json!({
            "meta": {
                "engine_version": env!("CARGO_PKG_VERSION"),
                "redaction_count": redaction_count
            },
            "canonical": self.canonical_map
        });
        serde_json::to_string(&wrapper)
            .unwrap_or_else(|_| r#"{"meta":{},"canonical":{}}"#.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(step_type: &str, config: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "id": "s1", "type": step_type, "enabled": true, "label": null, "config": config
        })
    }

    fn pipeline(steps: Vec<serde_json::Value>) -> String {
        serde_json::json!({ "version": 1, "steps": steps }).to_string()
    }

    fn run(input: &str, steps: Vec<serde_json::Value>) -> String {
        Engine::new().run_pipeline(input, &pipeline(steps)).unwrap()
    }

    fn run_with_map(input: &str, steps: Vec<serde_json::Value>) -> (String, serde_json::Value) {
        let mut engine = Engine::new();
        let out = engine.run_pipeline(input, &pipeline(steps)).unwrap();
        let map = serde_json::from_str(&engine.get_canonical_map_json()).unwrap();
        (out, map)
    }

    // --- Mask helpers (regression: these used byte offsets and panicked on non-ASCII) ---

    #[test]
    fn mask_all_counts_characters_not_bytes() {
        assert_eq!(mask_all("café", "*", None), "****");
        assert_eq!(mask_all("abc", "*", None), "***");
        assert_eq!(mask_all("", "*", None), "");
    }

    #[test]
    fn preserve_last_n_does_not_split_multibyte_chars() {
        // Previously panicked: byte index 4 falls inside 'é' (bytes 3..5).
        assert_eq!(mask_preserving_last_n("café", 1, "*", None), "***é");
        assert_eq!(
            mask_preserving_last_n("naïve-café", 3, "*", None),
            "*******afé"
        );
    }

    #[test]
    fn preserve_last_n_returns_original_when_shorter_than_n() {
        assert_eq!(mask_preserving_last_n("ab", 4, "*", None), "ab");
        assert_eq!(mask_preserving_last_n("abcd", 4, "*", None), "abcd");
    }

    #[test]
    fn non_ascii_input_survives_every_redaction_mode() {
        for mode in ["placeholder", "mask", "preserveLastN"] {
            let out = run(
                "héllo wörld naïve-café ☃ end",
                vec![step(
                    "replace",
                    serde_json::json!({
                        "search": "naïve-café", "mode": mode, "preserveCount": 1
                    }),
                )],
            );
            assert!(
                !out.contains("naïve-café"),
                "mode {} left the value: {}",
                mode,
                out
            );
        }
    }

    // --- Luhn / credit card ---

    #[test]
    fn luhn_accepts_known_test_cards_and_rejects_corruption() {
        assert!(luhn_check("4111111111111111")); // Visa, 16
        assert!(luhn_check("378282246310005")); // Amex, 15
        assert!(luhn_check("4222222222222")); // Visa, 13
        assert!(!luhn_check("4111111111111112")); // bad check digit
        assert!(!luhn_check("411111111111")); // 12 digits, too short
    }

    #[test]
    fn credit_card_detects_13_15_and_16_digit_cards() {
        // Regression: the pattern only matched 16 digits, so Amex and 13-digit Visa
        // were never redacted even though luhn_check accepted 13-19.
        for card in ["4111111111111111", "378282246310005", "4222222222222"] {
            let out = run(
                &format!("card {} end", card),
                vec![step("credit_card", serde_json::json!({}))],
            );
            assert!(
                !out.contains(card),
                "card {} was not redacted: {}",
                card,
                out
            );
        }
    }

    #[test]
    fn credit_card_ignores_luhn_invalid_digit_runs() {
        let out = run(
            "ref 1234567812345678 end",
            vec![step("credit_card", serde_json::json!({}))],
        );
        assert!(
            out.contains("1234567812345678"),
            "luhn-invalid number should survive: {}",
            out
        );
    }

    #[test]
    fn credit_card_handles_grouped_digits() {
        let out = run(
            "4111 1111 1111 1111",
            vec![step("credit_card", serde_json::json!({}))],
        );
        assert_eq!(out, "<CC_1>");
    }

    // --- Username step honours redaction config (previously hardcoded a placeholder) ---

    #[test]
    fn username_step_respects_mask_mode() {
        let out = run(
            "hello @alicesmith bye",
            vec![step(
                "username",
                serde_json::json!({ "mode": "mask", "maskChar": "#" }),
            )],
        );
        assert_eq!(out, "hello @########## bye");
    }

    #[test]
    fn username_step_keeps_the_marker_and_redacts_only_the_name() {
        let out = run(
            "path /home/alice end",
            vec![step("username", serde_json::json!({}))],
        );
        assert_eq!(out, "path /home/<USERNAME_1> end");
    }

    // --- SSN (regression: the pattern used unsupported lookahead and panicked on first use) ---

    #[test]
    fn ssn_regex_compiles() {
        // RE_SSN is a LazyLock, so a bad pattern only panics when first dereferenced —
        // which is why this went unnoticed. Force it here.
        assert!(RE_SSN.is_match("123-45-6789"));
    }

    #[test]
    fn ssn_step_redacts_valid_numbers_in_each_separator_style() {
        for ssn in ["123-45-6789", "123 45 6789", "123456789"] {
            let out = run(
                &format!("ssn {} end", ssn),
                vec![step("ssn", serde_json::json!({}))],
            );
            assert!(!out.contains(ssn), "{} was not redacted: {}", ssn, out);
        }
    }

    #[test]
    fn ssn_step_skips_ranges_that_are_never_issued() {
        for invalid in [
            "000-45-6789",
            "666-45-6789",
            "900-45-6789",
            "987-65-4321",
            "123-00-6789",
            "123-45-0000",
        ] {
            let out = run(
                &format!("v {} end", invalid),
                vec![step("ssn", serde_json::json!({}))],
            );
            assert!(
                out.contains(invalid),
                "{} should not be treated as an SSN: {}",
                invalid,
                out
            );
        }
    }

    #[test]
    fn every_builtin_detector_pattern_compiles() {
        // Guards against another unsupported-syntax regex slipping in behind a LazyLock.
        let probe = "a@b.co 10.0.0.1 00:11:22:33:44:55 host.example.com \
                     eyJhbGciOiJ9.eyJzdWIifQ.sig 123e4567-e89b-12d3-a456-426614174000 \
                     555-123-4567 123-45-6789 4111111111111111 sk_abcdefghij1234567890 \
                     https://x.test/p?q=1 @alice ya29.aaaa /home/bob";
        for step_type in [
            "email",
            "ipv4",
            "ipv6",
            "mac",
            "hostname",
            "jwt",
            "uuid",
            "phone",
            "ssn",
            "credit_card",
            "apikey",
            "url",
            "username",
            "base64",
            "oauth",
        ] {
            let out = run(probe, vec![step(step_type, serde_json::json!({}))]);
            assert!(!out.is_empty(), "{} produced no output", step_type);
        }
    }

    // --- Canonical map behaviour ---

    #[test]
    fn repeated_values_share_one_token_and_count_occurrences() {
        let (out, map) = run_with_map(
            "a@x.com then b@x.com then a@x.com",
            vec![step("email", serde_json::json!({}))],
        );
        assert_eq!(out, "<EMAIL_1> then <EMAIL_2> then <EMAIL_1>");
        assert_eq!(map["meta"]["redaction_count"], 3);
        let entries: Vec<_> = map["canonical"].as_object().unwrap().values().collect();
        assert_eq!(entries.len(), 2, "two distinct values expected");
    }

    #[test]
    fn fingerprints_differ_between_sessions_for_the_same_value() {
        let (_, a) = run_with_map("a@x.com", vec![step("email", serde_json::json!({}))]);
        let (_, b) = run_with_map("a@x.com", vec![step("email", serde_json::json!({}))]);
        let key_a = a["canonical"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let key_b = b["canonical"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        assert_ne!(
            key_a, key_b,
            "per-session HMAC secret should change the fingerprint"
        );
    }

    #[test]
    fn context_is_captured_without_panicking_on_multibyte_neighbours() {
        let (_, map) = run_with_map(
            "☃☃☃☃☃☃☃☃☃☃ a@x.com ☃☃☃☃☃☃☃☃☃☃",
            vec![step("email", serde_json::json!({}))],
        );
        let entry = map["canonical"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        assert!(entry["context_before"].as_str().unwrap().contains('☃'));
        assert!(entry["context_after"].as_str().unwrap().contains('☃'));
    }

    // --- Filters ---

    #[test]
    fn email_allowed_domains_are_skipped_including_subdomains() {
        let out = run(
            "keep me@corp.com and me@eu.corp.com but not me@other.com",
            vec![step(
                "email",
                serde_json::json!({ "allowedDomains": ["corp.com"] }),
            )],
        );
        assert!(out.contains("me@corp.com"));
        assert!(out.contains("me@eu.corp.com"));
        assert!(!out.contains("me@other.com"));
    }

    #[test]
    fn ipv4_excluded_subnets_are_skipped() {
        let out = run(
            "10.1.2.3 and 8.8.8.8",
            vec![step(
                "ipv4",
                serde_json::json!({ "excludeSubnets": ["10.0.0.0/8"] }),
            )],
        );
        assert!(out.contains("10.1.2.3"));
        assert!(!out.contains("8.8.8.8"));
    }

    #[test]
    fn subnet_matching_handles_edges() {
        assert!(is_in_subnet("10.0.0.1", "10.0.0.0/8"));
        assert!(!is_in_subnet("11.0.0.1", "10.0.0.0/8"));
        assert!(is_in_subnet("1.2.3.4", "0.0.0.0/0"));
        assert!(is_in_subnet("1.2.3.4", "1.2.3.4/32"));
        assert!(!is_in_subnet("not-an-ip", "10.0.0.0/8"));
        assert!(!is_in_subnet("10.0.0.1", "10.0.0.0/33"));
    }

    // --- Structural detectors ---

    #[test]
    fn json_key_redacts_only_the_configured_keys() {
        let out = run(
            r#"{"password":"hunter2","user":"alice"}"#,
            vec![step("jsonKey", serde_json::json!({ "keys": ["password"] }))],
        );
        assert!(!out.contains("hunter2"));
        assert!(out.contains("alice"));
    }

    #[test]
    fn query_param_and_header_steps_redact_values() {
        let out = run(
            "GET /a?token=abc123&x=1",
            vec![step(
                "queryParam",
                serde_json::json!({ "names": ["token"] }),
            )],
        );
        assert!(!out.contains("abc123"), "{}", out);
        assert!(out.contains("x=1"));

        let out = run(
            "Authorization: Bearer xyz\r\nAccept: */*",
            vec![step(
                "header",
                serde_json::json!({ "names": ["Authorization"] }),
            )],
        );
        assert!(!out.contains("Bearer xyz"), "{}", out);
        assert!(out.contains("Accept: */*"));
    }

    #[test]
    fn named_target_steps_are_noops_when_no_names_configured() {
        let input = r#"{"password":"hunter2"}"#;
        for (t, field) in [
            ("jsonKey", "keys"),
            ("queryParam", "names"),
            ("header", "names"),
        ] {
            assert_eq!(run(input, vec![step(t, serde_json::json!({}))]), input);
            assert_eq!(
                run(input, vec![step(t, serde_json::json!({ field: [] }))]),
                input
            );
        }
    }

    // --- Config robustness ---

    #[test]
    fn invalid_user_regex_is_ignored_rather_than_failing_the_run() {
        let out = run(
            "keep this",
            vec![step(
                "regex",
                serde_json::json!({ "pattern": "([unclosed" }),
            )],
        );
        assert_eq!(out, "keep this");
    }

    #[test]
    fn empty_and_unknown_steps_pass_text_through() {
        assert_eq!(
            run(
                "text",
                vec![step("regex", serde_json::json!({ "pattern": "" }))]
            ),
            "text"
        );
        assert_eq!(
            run("text", vec![step("not_a_real_step", serde_json::json!({}))]),
            "text"
        );
        assert_eq!(run("text", vec![]), "text");
    }

    // Note: the Err path of run_pipeline builds a JsValue, which aborts off-wasm.
    // Covering it needs wasm-bindgen-test under a headless browser.

    #[test]
    fn disabled_steps_are_skipped() {
        let cfg = serde_json::json!({ "version": 1, "steps": [
            { "id": "a", "type": "email", "enabled": false, "label": null, "config": {} }
        ]})
        .to_string();
        assert_eq!(
            Engine::new().run_pipeline("a@x.com", &cfg).unwrap(),
            "a@x.com"
        );
    }

    #[test]
    fn custom_label_drives_the_token_prefix_and_is_sanitised() {
        let cfg = serde_json::json!({ "version": 1, "steps": [
            { "id": "a", "type": "email", "enabled": true, "label": "My Step!", "config": {} }
        ]})
        .to_string();
        assert_eq!(
            Engine::new().run_pipeline("a@x.com", &cfg).unwrap(),
            "<MY_STEP__1>"
        );
    }

    #[test]
    fn replacement_override_beats_the_mode() {
        let out = run(
            "a@x.com",
            vec![step(
                "email",
                serde_json::json!({
                    "mode": "mask", "replacement": "[GONE]"
                }),
            )],
        );
        assert_eq!(out, "[GONE]");
    }

    #[test]
    fn empty_mask_char_falls_back_to_asterisk() {
        let out = run(
            "a@x.com",
            vec![step(
                "email",
                serde_json::json!({
                    "mode": "mask", "maskChar": ""
                }),
            )],
        );
        assert_eq!(out, "*".repeat("a@x.com".len()));
    }

    // --- jsonKey: value scanning (was a plain-string-only regex) ---

    #[test]
    fn json_key_redacts_non_string_values() {
        let out = run(
            r#"{"port":8080,"active":true,"note":null,"ratio":-1.5e3,"keep":"me"}"#,
            vec![step(
                "jsonKey",
                serde_json::json!({ "keys": ["port", "active", "note", "ratio"] }),
            )],
        );
        assert_eq!(
            out,
            r#"{"port":<JSON_1>,"active":<JSON_2>,"note":<JSON_3>,"ratio":<JSON_4>,"keep":"me"}"#
        );
    }

    #[test]
    fn json_key_handles_escaped_quotes_in_string_values() {
        // The old pattern `"([^"]+)"` stopped at the backslash-escaped quote and produced
        // `"<JSON_1>"nter2"`, leaking the tail of the secret.
        let out = run(
            r#"{"password":"hu\"nter2"}"#,
            vec![step("jsonKey", serde_json::json!({ "keys": ["password"] }))],
        );
        assert_eq!(out, r#"{"password":"<JSON_1>"}"#);
        assert!(!out.contains("nter2"));
    }

    #[test]
    fn json_key_redacts_whole_nested_structures() {
        let out = run(
            r#"{"data":{"a":[1,{"b":"x"}]},"keep":1}"#,
            vec![step("jsonKey", serde_json::json!({ "keys": ["data"] }))],
        );
        assert_eq!(out, r#"{"data":<JSON_1>,"keep":1}"#);
    }

    #[test]
    fn json_key_keeps_quotes_so_string_values_stay_parseable() {
        let out = run(
            r#"{"password":"hunter2","user":"alice"}"#,
            vec![step("jsonKey", serde_json::json!({ "keys": ["password"] }))],
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn json_key_tolerates_malformed_json() {
        for input in [
            r#"{"password":"unterminated"#,
            r#"{"data":{"unbalanced":1"#,
            r#"{"password":}"#,
            r#"log line "password": trailing"#,
        ] {
            // Must not panic and must not mangle text it cannot parse a value out of.
            let out = run(
                input,
                vec![step(
                    "jsonKey",
                    serde_json::json!({ "keys": ["password", "data"] }),
                )],
            );
            assert!(!out.is_empty(), "empty output for {}", input);
        }
    }

    #[test]
    fn json_key_matches_keys_case_insensitively_with_spacing() {
        let out = run(
            r#"{"PassWord"  :   "hunter2"}"#,
            vec![step("jsonKey", serde_json::json!({ "keys": ["password"] }))],
        );
        assert!(!out.contains("hunter2"), "{}", out);
    }

    // --- Fixed-width masking (mask output no longer discloses value length) ---

    #[test]
    fn mask_length_pins_the_output_width() {
        let short = run(
            "a@b.co",
            vec![step(
                "email",
                serde_json::json!({ "mode": "mask", "maskLength": 8 }),
            )],
        );
        let long = run(
            "a.very.long.address@example.com",
            vec![step(
                "email",
                serde_json::json!({ "mode": "mask", "maskLength": 8 }),
            )],
        );
        assert_eq!(short, "********");
        assert_eq!(long, "********");
    }

    #[test]
    fn mask_length_absent_preserves_value_length() {
        let out = run(
            "a@b.co",
            vec![step("email", serde_json::json!({ "mode": "mask" }))],
        );
        assert_eq!(out, "******");
    }

    #[test]
    fn mask_length_applies_to_preserve_last_n() {
        let out = run(
            "4111111111111111",
            vec![step(
                "credit_card",
                serde_json::json!({ "mode": "preserveLastN", "preserveCount": 4, "maskLength": 6 }),
            )],
        );
        assert_eq!(out, "******1111");
    }

    #[test]
    fn mask_length_still_masks_values_shorter_than_preserve_count() {
        // Without a fixed width the value is echoed back verbatim, which is the documented
        // fallback; with one, it must not leak.
        let out = mask_preserving_last_n("ab", 4, "*", Some(6));
        assert_eq!(out, "******");
        assert_eq!(mask_preserving_last_n("ab", 4, "*", None), "ab");
    }

    #[test]
    fn mask_length_zero_is_treated_as_unset() {
        let out = run(
            "a@b.co",
            vec![step(
                "email",
                serde_json::json!({ "mode": "mask", "maskLength": 0 }),
            )],
        );
        assert_eq!(out, "******");
    }

    // --- partialMask scope ---

    #[test]
    fn partial_mask_line_scope_applies_to_every_line() {
        let out = run(
            "2026-01-01 alpha\n2026-01-02 beta\n2026-01-03 gamma",
            vec![step(
                "partialMask",
                serde_json::json!({ "start": 0, "end": 10, "scope": "line", "maskChar": "#" }),
            )],
        );
        assert_eq!(out, "########## alpha\n########## beta\n########## gamma");
    }

    #[test]
    fn partial_mask_document_scope_remains_a_single_span() {
        let out = run(
            "2026-01-01 alpha\n2026-01-02 beta",
            vec![step(
                "partialMask",
                serde_json::json!({ "start": 0, "end": 10, "maskChar": "#" }),
            )],
        );
        assert_eq!(out, "########## alpha\n2026-01-02 beta");
    }

    #[test]
    fn partial_mask_line_scope_clamps_to_short_lines() {
        let out = run(
            "abcdefgh\nab\n\nabcdefgh",
            vec![step(
                "partialMask",
                serde_json::json!({ "start": 2, "end": 6, "scope": "line", "maskChar": "*" }),
            )],
        );
        // Short lines are masked only as far as they go; the empty line is untouched.
        assert_eq!(out, "ab****gh\nab\n\nab****gh");
    }

    #[test]
    fn partial_mask_line_scope_preserves_crlf() {
        let out = run(
            "abcdef\r\nabcdef",
            vec![step(
                "partialMask",
                serde_json::json!({ "start": 0, "end": 3, "scope": "line", "maskChar": "#" }),
            )],
        );
        assert_eq!(out, "###def\r\n###def");
    }

    #[test]
    fn partial_mask_line_scope_handles_multibyte_columns() {
        let out = run(
            "héllo wörld\ncafés anyone",
            vec![step(
                "partialMask",
                serde_json::json!({ "start": 0, "end": 5, "scope": "line", "maskChar": "#" }),
            )],
        );
        assert_eq!(out, "##### wörld\n##### anyone");
    }

    // --- Cross-step interaction (documented current behaviour, not yet protected) ---

    #[test]
    fn allowlisted_email_survives_later_steps() {
        // An allowlisted value is protected for the rest of the run, including the local part
        // a username step would mask and the domain a hostname step would match.
        let out = run(
            "reporter ops@corp.com end",
            vec![
                step(
                    "email",
                    serde_json::json!({ "allowedDomains": ["corp.com"] }),
                ),
                serde_json::json!({
                    "id": "s2", "type": "username", "enabled": true, "label": null, "config": {}
                }),
                serde_json::json!({
                    "id": "s3", "type": "hostname", "enabled": true, "label": null, "config": {}
                }),
            ],
        );
        assert_eq!(out, "reporter ops@corp.com end");
    }

    #[test]
    fn exemption_is_scoped_to_the_matched_span_not_the_value() {
        // Allowlisting the domain keeps the address intact, but an unrelated hostname using
        // the same domain is still redacted.
        let out = run(
            "mail ops@corp.com host api.corp.com",
            vec![
                step(
                    "email",
                    serde_json::json!({ "allowedDomains": ["corp.com"] }),
                ),
                serde_json::json!({
                    "id": "s2", "type": "hostname", "enabled": true, "label": null, "config": {}
                }),
            ],
        );
        assert_eq!(out, "mail ops@corp.com host <HOSTNAME_1>");
    }

    #[test]
    fn excluded_subnet_survives_later_steps() {
        let out = run(
            "internal 10.4.1.9 and 8.8.8.8",
            vec![
                step(
                    "ipv4",
                    serde_json::json!({ "excludeSubnets": ["10.0.0.0/8"] }),
                ),
                serde_json::json!({
                    "id": "s2", "type": "regex", "enabled": true, "label": "Digits",
                    "config": { "pattern": r"\d+\.\d+\.\d+\.\d+" }
                }),
            ],
        );
        assert_eq!(out, "internal 10.4.1.9 and <IPV4_1>");
    }

    #[test]
    fn emitted_placeholders_are_not_matched_again() {
        // The token a step wrote is protected, so a later rule cannot chew into it.
        let out = run(
            "a@x.com",
            vec![
                step("email", serde_json::json!({})),
                serde_json::json!({
                    "id": "s2", "type": "regex", "enabled": true, "label": "Second",
                    "config": { "pattern": "EMAIL_1" }
                }),
            ],
        );
        assert_eq!(out, "<EMAIL_1>");
    }

    #[test]
    fn a_validity_rejection_does_not_protect_the_text() {
        // A non-Luhn digit run was never a card, so a later rule may still redact it.
        let out = run(
            "ref 1234567812345678 end",
            vec![
                step("credit_card", serde_json::json!({})),
                serde_json::json!({
                    "id": "s2", "type": "regex", "enabled": true, "label": "Digits",
                    "config": { "pattern": r"\d{16}" }
                }),
            ],
        );
        assert_eq!(out, "ref <DIGITS_1> end");
    }

    #[test]
    fn protection_survives_length_changing_rewrites() {
        // The exempt span sits after a replacement that shortens the text, so its offsets must
        // be translated, not just carried.
        let out = run(
            "token sk_abcdefghij1234567890 keep ops@corp.com tail",
            vec![
                step("apikey", serde_json::json!({})),
                step(
                    "email",
                    serde_json::json!({ "allowedDomains": ["corp.com"] }),
                ),
                serde_json::json!({
                    "id": "s3", "type": "hostname", "enabled": true, "label": null, "config": {}
                }),
            ],
        );
        assert_eq!(out, "token <APIKEY_1> keep ops@corp.com tail");
    }

    #[test]
    fn exempt_spans_are_reported_in_final_output_coordinates() {
        let mut engine = Engine::new();
        let cfg = pipeline(vec![
            step("apikey", serde_json::json!({})),
            step(
                "email",
                serde_json::json!({ "allowedDomains": ["corp.com"] }),
            ),
        ]);
        let out = engine
            .run_pipeline("k sk_abcdefghij1234567890 m ops@corp.com", &cfg)
            .unwrap();
        let spans: serde_json::Value =
            serde_json::from_str(&engine.get_exempt_spans_json()).unwrap();
        let span = &spans[0];
        let (start, end) = (
            span["start"].as_u64().unwrap() as usize,
            span["end"].as_u64().unwrap() as usize,
        );
        assert_eq!(&out[start..end], "ops@corp.com");
        assert_eq!(span["kind"], "exempt");
        assert_eq!(span["rule"], "EMAIL");
    }

    #[test]
    fn protection_holds_at_the_very_start_and_end_of_the_text() {
        let out = run(
            "ops@corp.com",
            vec![
                step(
                    "email",
                    serde_json::json!({ "allowedDomains": ["corp.com"] }),
                ),
                serde_json::json!({
                    "id": "s2", "type": "hostname", "enabled": true, "label": null, "config": {}
                }),
            ],
        );
        assert_eq!(out, "ops@corp.com");
    }

    #[test]
    fn adjacent_protected_spans_do_not_block_the_text_between_them() {
        // Two tokens written back to back must not merge into a span that swallows the
        // separator, or a later step could never match anything in between.
        let out = run(
            "a@x.com b@y.com middle c@z.com",
            vec![
                step("email", serde_json::json!({})),
                serde_json::json!({
                    "id": "s2", "type": "regex", "enabled": true, "label": "Mid",
                    "config": { "pattern": "middle" }
                }),
            ],
        );
        assert_eq!(out, "<EMAIL_1> <EMAIL_2> <MID_1> <EMAIL_3>");
    }

    #[test]
    fn repeated_exemption_of_the_same_span_is_idempotent() {
        // Two email steps with the same allowlist exempt the same range twice; the merged
        // span list must stay well formed.
        let out = run(
            "ops@corp.com and api.corp.com",
            vec![
                step(
                    "email",
                    serde_json::json!({ "allowedDomains": ["corp.com"] }),
                ),
                serde_json::json!({
                    "id": "s2", "type": "email", "enabled": true, "label": null,
                    "config": { "allowedDomains": ["corp.com"] }
                }),
                serde_json::json!({
                    "id": "s3", "type": "hostname", "enabled": true, "label": null, "config": {}
                }),
            ],
        );
        assert_eq!(out, "ops@corp.com and <HOSTNAME_1>");
    }

    #[test]
    fn many_protected_spans_stay_fast_across_steps() {
        // is_protected binary-searches the sorted span list; a linear scan here would make
        // the second step quadratic in the number of redactions from the first.
        let input = (0..5_000)
            .map(|i| format!("user{}@example.com ", i))
            .collect::<String>();
        let out = run(
            &input,
            vec![
                step("email", serde_json::json!({})),
                serde_json::json!({
                    "id": "s2", "type": "regex", "enabled": true, "label": "Tok",
                    "config": { "pattern": "EMAIL_[0-9]+" }
                }),
            ],
        );
        assert!(
            out.contains("<EMAIL_5000>"),
            "tokens must survive the second step"
        );
        assert!(
            !out.contains("<TOK_"),
            "protected tokens must not be re-matched"
        );
    }

    // --- Multi-step pipelines ---

    #[test]
    fn steps_run_in_order_and_each_gets_its_own_token_space() {
        let out = run(
            "mail a@x.com ip 8.8.8.8",
            vec![
                step("email", serde_json::json!({})),
                serde_json::json!({ "id": "s2", "type": "ipv4", "enabled": true, "label": null, "config": {} }),
            ],
        );
        assert_eq!(out, "mail <EMAIL_1> ip <IPV4_1>");
    }

    #[test]
    fn partial_mask_uses_character_offsets() {
        let out = run(
            "héllo world",
            vec![step(
                "partialMask",
                serde_json::json!({
                    "start": 0, "end": 5, "maskChar": "#"
                }),
            )],
        );
        assert_eq!(out, "##### world");
    }

    #[test]
    fn partial_mask_is_a_noop_for_degenerate_ranges() {
        for (s, e) in [(0, 0), (5, 2), (99, 120)] {
            assert_eq!(
                run(
                    "short",
                    vec![step(
                        "partialMask",
                        serde_json::json!({ "start": s, "end": e })
                    )]
                ),
                "short",
                "range {}..{} should be a no-op",
                s,
                e
            );
        }
    }

    #[test]
    fn large_input_with_many_matches_completes_quickly() {
        // Guards the single-pass rewrite against the previous O(n*m) replace_range loop.
        let input = (0..5_000)
            .map(|i| format!("user{}@example.com ", i))
            .collect::<String>();
        let out = run(&input, vec![step("email", serde_json::json!({}))]);
        assert!(!out.contains("@example.com"));
        assert!(out.contains("<EMAIL_5000>"));
    }
}
