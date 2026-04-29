use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use hmac::{Hmac, Mac};
use sha2::Sha256;
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
static RE_MAC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").expect("RE_MAC")
});
static RE_HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").expect("RE_HOSTNAME")
});
static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").expect("RE_JWT")
});
static RE_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").expect("RE_UUID")
});
static RE_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\+\d{1,3}\s?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}").expect("RE_PHONE")
});
// Improved SSN: excludes provably invalid area codes (000, 666, 900-999) and groups (00) / serials (0000).
static RE_SSN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b").expect("RE_SSN")
});
// Simplified to standard 16-digit cards; Luhn post-filter handles validation.
static RE_CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\d{4}[\s-]?){3}\d{4}\b").expect("RE_CREDIT_CARD")
});
static RE_API_KEY_GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk|pk|api|token|key|secret)[\-_][a-zA-Z0-9]{20,}\b").expect("RE_API_KEY_GENERIC")
});
// Fixed: was r#"https?://[^\s<>"]+#"# which required a literal # at the end of every URL.
static RE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s<>"']+"#).expect("RE_URL")
});
static RE_USERNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:@|user=|username=|/home/|/users/)([a-zA-Z0-9_-]{3,32})\b").expect("RE_USERNAME")
});
static RE_BASE64: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").expect("RE_BASE64")
});
static RE_OAUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bya29\.[a-zA-Z0-9_-]{50,}\b").expect("RE_OAUTH")
});

// --- Helper functions ---

fn floor_char_boundary(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    (0..=pos).rev().find(|&i| text.is_char_boundary(i)).unwrap_or(0)
}

fn ceil_char_boundary(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    (pos..=text.len()).find(|&i| text.is_char_boundary(i)).unwrap_or(text.len())
}

// Treats n as a Unicode character index, returns the corresponding byte index.
fn char_to_byte_idx(text: &str, n: usize) -> usize {
    text.char_indices().nth(n).map(|(i, _)| i).unwrap_or(text.len())
}

fn parse_ipv4(ip: &str) -> Option<u32> {
    let parts: Vec<u32> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 || parts.iter().any(|&p| p > 255) {
        return None;
    }
    Some((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
}

fn is_in_subnet(ip: &str, cidr: &str) -> bool {
    let mut parts = cidr.splitn(2, '/');
    let network = parts.next().unwrap_or("");
    let prefix_len: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(32);
    if prefix_len > 32 { return false; }
    let Some(ip_num) = parse_ipv4(ip) else { return false; };
    let Some(net_num) = parse_ipv4(network) else { return false; };
    if prefix_len == 0 { return true; }
    let mask = !0u32 << (32 - prefix_len);
    (ip_num & mask) == (net_num & mask)
}

fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 { return false; }
    let sum: u32 = digits.iter().rev().enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let v = d * 2;
                if v > 9 { v - 9 } else { v }
            } else { d }
        })
        .sum();
    sum % 10 == 0
}

// --- Data structures ---

#[derive(Clone, Debug)]
struct ClaimedRegion {
    start: usize,
    end: usize,
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

// --- Engine ---

#[wasm_bindgen]
pub struct Engine {
    session_secret: [u8; 32],
    canonical_map: HashMap<String, CanonicalEntry>,
    next_ids: HashMap<String, usize>,
    claimed_regions: Vec<ClaimedRegion>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.session_secret.zeroize();
    }
}

#[wasm_bindgen]
impl Engine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("getrandom failed");
        Self {
            session_secret: secret,
            canonical_map: HashMap::new(),
            next_ids: HashMap::new(),
            claimed_regions: Vec::new(),
        }
    }

    pub fn run_pipeline(&mut self, input: &str, config_json: &str) -> Result<String, JsValue> {
        let config: PipelineConfig = serde_json::from_str(config_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid pipeline config: {}", e)))?;

        self.claimed_regions.clear();
        self.canonical_map.clear();
        self.next_ids.clear();

        let mut current_text = input.to_string();
        for step in config.steps.iter().filter(|s| s.enabled) {
            current_text = self.execute_step(step, &current_text)?;
        }
        Ok(current_text)
    }

    fn execute_step(&mut self, step: &StepConfig, text: &str) -> Result<String, JsValue> {
        self.claimed_regions.clear();

        let type_prefix = if let Some(label) = &step.label {
            if !label.is_empty() {
                // Cap label length to 64 chars to prevent oversized tokens.
                let capped: String = label.chars().take(64).collect();
                capped.to_uppercase()
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
            "hostname" => self.redact_with_regex(text, &RE_HOSTNAME, &type_prefix, "hostname", &step.config),
            "jwt" => self.redact_with_regex(text, &RE_JWT, &type_prefix, "jwt", &step.config),
            "uuid" => self.redact_with_regex(text, &RE_UUID, &type_prefix, "uuid", &step.config),
            "phone" => self.redact_with_regex(text, &RE_PHONE, &type_prefix, "phone", &step.config),
            "ssn" => self.redact_with_regex(text, &RE_SSN, &type_prefix, "ssn", &step.config),
            "credit_card" => self.redact_credit_card(text, &step.config, &type_prefix),
            "api_key" | "apikey" => self.redact_api_key(text, &step.config, &type_prefix),
            "url" => self.redact_with_regex(text, &RE_URL, &type_prefix, "url", &step.config),
            "username" => self.redact_username(text, &step.config, &type_prefix),
            "base64" => self.redact_with_regex(text, &RE_BASE64, &type_prefix, "base64", &step.config),
            "json_key" | "jsonKey" => self.redact_json_key(text, &step.config, &type_prefix),
            "query_param" | "queryParam" => self.redact_query_param(text, &step.config, &type_prefix),
            "http_header" | "header" => self.redact_http_header(text, &step.config, &type_prefix),
            "replace" => self.redact_replace(text, &step.config, &type_prefix),
            "partial_mask" | "partialMask" => self.redact_partial_mask(text, &step.config, &type_prefix),
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
        }.to_string()
    }

    // Core replacement engine. Accepts an optional extra filter — callers pass |_| true when unused.
    fn redact_with_regex_filtered(
        &mut self,
        text: &str,
        regex: &Regex,
        type_upper: &str,
        type_lower: &str,
        config: &serde_json::Value,
        extra_filter: impl Fn(&str) -> bool,
    ) -> Result<String, JsValue> {
        let mut result = text.to_string();
        let mut offset: isize = 0;

        let matches: Vec<(usize, usize, String)> = regex.find_iter(text)
            .filter_map(|m| {
                let matched = m.as_str();
                if !extra_filter(matched) { return None; }
                let start = m.start();
                let end = m.end();
                if self.is_region_claimed(start, end) { None } else { Some((start, end, matched.to_string())) }
            })
            .collect();

        for (start, end, original) in matches {
            let fingerprint = self.generate_fingerprint(&original);
            // Clamp context to char boundaries to avoid UTF-8 panics.
            let ctx_start = floor_char_boundary(text, start.saturating_sub(20));
            let ctx_end = ceil_char_boundary(text, (end + 20).min(text.len()));
            let context_before = text[ctx_start..start].to_string();
            let context_after = text[end..ctx_end].to_string();
            let context = format!("{}{}", context_before, context_after);

            let entry = self.canonical_map.entry(fingerprint.clone()).or_insert_with(|| {
                let r_type = type_upper.to_string();
                let count = self.next_ids.entry(r_type.clone()).or_insert(1);
                let id = format!("{}_{}", r_type, count);
                *count += 1;
                CanonicalEntry {
                    id,
                    r#type: type_lower.to_string(),
                    original: original.clone(),
                    fingerprint: fingerprint.clone(),
                    occurrences: 0,
                    contexts: vec![],
                    context_before: context_before.clone(),
                    context_after: context_after.clone(),
                    method: type_lower.to_string(),
                }
            });

            entry.occurrences += 1;
            if entry.contexts.len() < 3 && !entry.contexts.contains(&context) {
                entry.contexts.push(context);
            }

            let canonical_id = entry.id.clone();
            let replacement = self.apply_redaction_mode(&original, &canonical_id, config);
            let actual_start = (start as isize + offset) as usize;
            let actual_end = (end as isize + offset) as usize;
            result.replace_range(actual_start..actual_end, &replacement);
            offset += replacement.len() as isize - (end - start) as isize;
            self.claimed_regions.push(ClaimedRegion { start, end });
        }
        Ok(result)
    }

    fn redact_with_regex(
        &mut self,
        text: &str,
        regex: &Regex,
        type_upper: &str,
        type_lower: &str,
        config: &serde_json::Value,
    ) -> Result<String, JsValue> {
        self.redact_with_regex_filtered(text, regex, type_upper, type_lower, config, |_| true)
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
        let mut result = text.to_string();
        let mut offset: isize = 0;

        let matches: Vec<(usize, usize, String)> = regex.captures_iter(text)
            .filter_map(|cap| {
                cap.get(capture_group).and_then(|m| {
                    let start = m.start();
                    let end = m.end();
                    if self.is_region_claimed(start, end) { None } else { Some((start, end, m.as_str().to_string())) }
                })
            })
            .collect();

        for (start, end, original) in matches {
            let fingerprint = self.generate_fingerprint(&original);
            let ctx_start = floor_char_boundary(text, start.saturating_sub(20));
            let ctx_end = ceil_char_boundary(text, (end + 20).min(text.len()));
            let context_before = text[ctx_start..start].to_string();
            let context_after = text[end..ctx_end].to_string();
            let context = format!("{}{}", context_before, context_after);

            let entry = self.canonical_map.entry(fingerprint.clone()).or_insert_with(|| {
                let r_type = type_upper.to_string();
                let count = self.next_ids.entry(r_type.clone()).or_insert(1);
                let id = format!("{}_{}", r_type, count);
                *count += 1;
                CanonicalEntry {
                    id,
                    r#type: type_lower.to_string(),
                    original: original.clone(),
                    fingerprint: fingerprint.clone(),
                    occurrences: 0,
                    contexts: vec![],
                    context_before: context_before.clone(),
                    context_after: context_after.clone(),
                    method: type_lower.to_string(),
                }
            });

            entry.occurrences += 1;
            if entry.contexts.len() < 3 && !entry.contexts.contains(&context) {
                entry.contexts.push(context);
            }

            let canonical_id = entry.id.clone();
            let replacement = self.apply_redaction_mode(&original, &canonical_id, config);
            let actual_start = (start as isize + offset) as usize;
            let actual_end = (end as isize + offset) as usize;
            result.replace_range(actual_start..actual_end, &replacement);
            offset += replacement.len() as isize - (end - start) as isize;
            self.claimed_regions.push(ClaimedRegion { start, end });
        }
        Ok(result)
    }

    // --- Detectors with domain/subnet filtering ---

    fn redact_email(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let allowed_domains: Vec<String> = config.get("allowedDomains")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect())
            .unwrap_or_default();

        if allowed_domains.is_empty() {
            return self.redact_with_regex(text, &RE_EMAIL, type_prefix, "email", config);
        }

        self.redact_with_regex_filtered(text, &RE_EMAIL, type_prefix, "email", config, |matched| {
            let domain = matched.splitn(2, '@').nth(1).unwrap_or("").to_lowercase();
            !allowed_domains.iter().any(|ad| domain == *ad || domain.ends_with(&format!(".{}", ad)))
        })
    }

    fn redact_ipv4(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let excluded_subnets: Vec<String> = config.get("excludeSubnets")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect())
            .unwrap_or_default();

        if excluded_subnets.is_empty() {
            return self.redact_with_regex(text, &RE_IPV4, type_prefix, "ipv4", config);
        }

        self.redact_with_regex_filtered(text, &RE_IPV4, type_prefix, "ipv4", config, |matched| {
            !excluded_subnets.iter().any(|cidr| is_in_subnet(matched, cidr))
        })
    }

    fn redact_credit_card(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        self.redact_with_regex_filtered(text, &RE_CREDIT_CARD, type_prefix, "credit_card", config, |matched| {
            luhn_check(matched)
        })
    }

    fn redact_regex(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let pattern = config.get("pattern").and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Regex pattern not provided"))?;
        if pattern.is_empty() { return Ok(text.to_string()); }
        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return Ok(text.to_string()),
        };
        self.redact_with_regex(text, &regex, type_prefix, "regex", config)
    }

    fn redact_api_key(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
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

    fn redact_replace(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let search = config.get("search").and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Search string not provided"))?;
        if search.is_empty() { return Ok(text.to_string()); }
        let regex = Regex::new(&regex::escape(search)).unwrap();
        self.redact_with_regex(text, &regex, type_prefix, "replace", config)
    }

    fn redact_partial_mask(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        // start/end are treated as Unicode character indices to avoid UTF-8 byte-boundary panics.
        let start_char = config.get("start").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let end_char = config.get("end").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let mask_char = config.get("maskChar").and_then(|v| v.as_str()).unwrap_or("*");

        let char_count = text.chars().count();
        if start_char >= char_count || start_char >= end_char { return Ok(text.to_string()); }
        let end_char = end_char.min(char_count);

        let byte_start = char_to_byte_idx(text, start_char);
        let byte_end = char_to_byte_idx(text, end_char);

        if self.is_region_claimed(byte_start, byte_end) { return Ok(text.to_string()); }

        let original = &text[byte_start..byte_end];
        let fingerprint = self.generate_fingerprint(original);

        let entry = self.canonical_map.entry(fingerprint.clone()).or_insert_with(|| {
            let r_type = type_prefix.to_string();
            let count = self.next_ids.entry(r_type.clone()).or_insert(1);
            let id = format!("{}_{}", r_type, count);
            *count += 1;
            CanonicalEntry {
                id,
                r#type: "partial_mask".to_string(),
                original: original.to_string(),
                fingerprint: fingerprint.clone(),
                occurrences: 0,
                contexts: vec![],
                context_before: text[..byte_start].chars().rev().take(20).collect::<String>().chars().rev().collect(),
                context_after: text[byte_end..].chars().take(20).collect(),
                method: "partial_mask".to_string(),
            }
        });
        entry.occurrences += 1;

        let char_len = original.chars().count();
        let replacement = mask_char.repeat(char_len);
        let mut result = text.to_string();
        result.replace_range(byte_start..byte_end, &replacement);
        self.claimed_regions.push(ClaimedRegion { start: byte_start, end: byte_end });
        Ok(result)
    }

    fn redact_username(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let mut result = text.to_string();
        let mut offset: isize = 0;

        let matches: Vec<(usize, usize, String)> = RE_USERNAME.captures_iter(text)
            .filter_map(|cap| {
                cap.get(1).and_then(|m| {
                    let start = m.start();
                    let end = m.end();
                    if self.is_region_claimed(start, end) { None } else { Some((start, end, m.as_str().to_string())) }
                })
            })
            .collect();

        for (start, end, original) in matches {
            let fingerprint = self.generate_fingerprint(&original);
            let ctx_start = floor_char_boundary(text, start.saturating_sub(20));
            let ctx_end = ceil_char_boundary(text, (end + 20).min(text.len()));
            let context_before = text[ctx_start..start].to_string();
            let context_after = text[end..ctx_end].to_string();
            let context = format!("{}{}", context_before, context_after);

            let entry = self.canonical_map.entry(fingerprint.clone()).or_insert_with(|| {
                let r_type = type_prefix.to_string();
                let count = self.next_ids.entry(r_type.clone()).or_insert(1);
                let id = format!("{}_{}", r_type, count);
                *count += 1;
                CanonicalEntry {
                    id,
                    r#type: "username".to_string(),
                    original: original.clone(),
                    fingerprint: fingerprint.clone(),
                    occurrences: 0,
                    contexts: vec![],
                    context_before: context_before.clone(),
                    context_after: context_after.clone(),
                    method: "username".to_string(),
                }
            });

            entry.occurrences += 1;
            if entry.contexts.len() < 3 && !entry.contexts.contains(&context) {
                entry.contexts.push(context);
            }

            let replacement = format!("<{}>", entry.id);
            let actual_start = (start as isize + offset) as usize;
            let actual_end = (end as isize + offset) as usize;
            result.replace_range(actual_start..actual_end, &replacement);
            offset += replacement.len() as isize - (end - start) as isize;
            self.claimed_regions.push(ClaimedRegion { start, end });
        }
        Ok(result)
    }

    fn redact_json_key(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let keys = config.get("keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if keys.is_empty() { return Ok(text.to_string()); }
        let keys_pattern = keys.iter().filter_map(|v| v.as_str()).map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
        if keys_pattern.is_empty() { return Ok(text.to_string()); }
        let pattern = format!(r#"(?i)"(?:{})"\s*:\s*"([^"]+)""#, keys_pattern);
        let regex = Regex::new(&pattern).unwrap();
        self.redact_captures(text, &regex, 1, type_prefix, "json_key", config)
    }

    fn redact_query_param(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let names = config.get("names").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if names.is_empty() { return Ok(text.to_string()); }
        let names_pattern = names.iter().filter_map(|v| v.as_str()).map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
        if names_pattern.is_empty() { return Ok(text.to_string()); }
        let pattern = format!(r#"(?i)[?&](?:{})=(?P<val>[^&\s#]+)"#, names_pattern);
        let regex = Regex::new(&pattern).unwrap();
        self.redact_captures(text, &regex, 1, type_prefix, "query_param", config)
    }

    fn redact_http_header(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let names = config.get("names").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if names.is_empty() { return Ok(text.to_string()); }
        let names_pattern = names.iter().filter_map(|v| v.as_str()).map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
        if names_pattern.is_empty() { return Ok(text.to_string()); }
        let pattern = format!(r#"(?i)\b(?:{}):\s*(?P<val>[^\r\n]+)"#, names_pattern);
        let regex = Regex::new(&pattern).unwrap();
        self.redact_captures(text, &regex, 1, type_prefix, "http_header", config)
    }

    fn is_region_claimed(&self, start: usize, end: usize) -> bool {
        self.claimed_regions.iter().any(|r| !(end <= r.start || start >= r.end))
    }

    fn apply_redaction_mode(&self, original: &str, canonical_id: &str, config: &serde_json::Value) -> String {
        if let Some(replacement) = config.get("replacement").and_then(|v| v.as_str()) {
            if !replacement.is_empty() { return replacement.to_string(); }
        }
        match config.get("mode").and_then(|v| v.as_str()).unwrap_or("placeholder") {
            "mask" => {
                let mask_char = config.get("maskChar").and_then(|v| v.as_str()).unwrap_or("*");
                mask_char.repeat(original.len())
            }
            "preserveLastN" => {
                let n = config.get("preserveCount").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                if original.len() <= n { return original.to_string(); }
                let mask_char = config.get("maskChar").and_then(|v| v.as_str()).unwrap_or("*");
                format!("{}{}", mask_char.repeat(original.len() - n), &original[original.len() - n..])
            }
            _ => format!("<{}>", canonical_id),
        }
    }

    fn generate_fingerprint(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.session_secret).unwrap();
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
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
        serde_json::to_string(&wrapper).unwrap_or_else(|_| r#"{"meta":{},"canonical":{}}"#.to_string())
    }
}
