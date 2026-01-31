use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

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

#[wasm_bindgen]
pub struct Engine {
    session_secret: [u8; 32],
    canonical_map: HashMap<String, CanonicalEntry>,
    next_ids: HashMap<String, usize>,
    claimed_regions: Vec<ClaimedRegion>,
}

#[wasm_bindgen]
impl Engine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("failed to generate session secret");
        
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

        // Reset all state for new pipeline run to ensure fresh statistics
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
        // Reset claimed regions for current step. Since the string is modified sequentially,
        // previous coordinates are no longer valid for the modified text.
        self.claimed_regions.clear();

        // Store the custom label for this step's type prefix
        let type_prefix = if let Some(label) = &step.label {
            if !label.is_empty() {
                // Convert label to uppercase and replace spaces/special chars with underscores
                label.to_uppercase()
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { '_' })
                    .collect::<String>()
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
            "ipv6" => self.redact_ipv6(text, &step.config, &type_prefix),
            "mac" => self.redact_mac(text, &step.config, &type_prefix),
            "hostname" => self.redact_hostname(text, &step.config, &type_prefix),
            "jwt" => self.redact_jwt(text, &step.config, &type_prefix),
            "uuid" => self.redact_uuid(text, &step.config, &type_prefix),
            "phone" => self.redact_phone(text, &step.config, &type_prefix),
            "ssn" => self.redact_ssn(text, &step.config, &type_prefix),
            "credit_card" => self.redact_credit_card(text, &step.config, &type_prefix),
            "api_key" | "apikey" => self.redact_api_key(text, &step.config, &type_prefix),
            "url" => self.redact_url(text, &step.config, &type_prefix),
            "username" => self.redact_username(text, &step.config, &type_prefix),
            "base64" => self.redact_base64(text, &step.config, &type_prefix),
            "json_key" | "jsonKey" => self.redact_json_key(text, &step.config, &type_prefix),
            "query_param" | "queryParam" => self.redact_query_param(text, &step.config, &type_prefix),
            "http_header" | "header" => self.redact_http_header(text, &step.config, &type_prefix),
            "replace" => self.redact_replace(text, &step.config, &type_prefix),
            "partial_mask" | "partialMask" => self.redact_partial_mask(text, &step.config, &type_prefix),
            "oauth" => self.redact_oauth(text, &step.config, &type_prefix),
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

    fn redact_replace(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let search = config.get("search")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Search string not provided"))?;

        if search.is_empty() {
            return Ok(text.to_string());
        }

        // Use regex for find/replace to handle overlapping issues easily via claimed regions
        let pattern = regex::escape(search);
        let regex = Regex::new(&pattern).unwrap();

        self.redact_with_regex(text, &regex, type_prefix, "replace", config)
    }

    fn redact_partial_mask(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let start = config.get("start").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let end = config.get("end").and_then(|v| v.as_u64()).unwrap_or(text.len() as u64) as usize;
        
        let mask_char = config.get("maskChar").and_then(|v| v.as_str()).unwrap_or("*");
        
        if start >= text.len() || start >= end {
            return Ok(text.to_string());
        }
        
        let end_bounded = if end > text.len() { text.len() } else { end };
        let original = &text[start..end_bounded];
        
        if self.is_region_claimed(start, end_bounded) {
            return Ok(text.to_string());
        }

        let mut result = text.to_string();
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
            }
        });

        entry.occurrences += 1;
        let replacement = mask_char.repeat(original.len());
        
        result.replace_range(start..end_bounded, &replacement);
        
        self.claimed_regions.push(ClaimedRegion {
            start,
            end: end_bounded,
        });

        Ok(result)
    }

    fn redact_oauth(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let oauth_regex = Regex::new(r"(?i)\bya29\.[a-zA-Z0-9_-]{50,}\b").unwrap();
        self.redact_with_regex(text, &oauth_regex, type_prefix, "oauth", _config)
    }

    fn redact_json_key(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let keys = config.get("keys")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if keys.is_empty() {
            return Ok(text.to_string());
        }

        let keys_pattern = keys.iter()
            .filter_map(|v| v.as_str())
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|");

        if keys_pattern.is_empty() {
            return Ok(text.to_string());
        }

        // Matches "key": "value" or "key":"value" - captures the value
        let pattern = format!(r#"(?i)"(?:{})"\s*:\s*"([^"]+)""#, keys_pattern);
        let regex = Regex::new(&pattern).unwrap();

        self.redact_captures(text, &regex, 1, type_prefix, "json_key", config)
    }

    fn redact_query_param(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let names = config.get("names")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if names.is_empty() {
            return Ok(text.to_string());
        }

        let names_pattern = names.iter()
            .filter_map(|v| v.as_str())
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|");

        if names_pattern.is_empty() {
            return Ok(text.to_string());
        }

        // Matches ?name=value or &name=value - captures the value
        let pattern = format!(r#"(?i)[?&](?:{})=(?P<val>[^&\s#]+)"#, names_pattern);
        let regex = Regex::new(&pattern).unwrap();

        self.redact_captures(text, &regex, 1, type_prefix, "query_param", config)
    }

    fn redact_http_header(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let names = config.get("names")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if names.is_empty() {
            return Ok(text.to_string());
        }

        let names_pattern = names.iter()
            .filter_map(|v| v.as_str())
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|");

        if names_pattern.is_empty() {
            return Ok(text.to_string());
        }

        // Matches Name: value
        let pattern = format!(r#"(?i)\b(?:{}):\s*(?P<val>[^\r\n]+)"#, names_pattern);
        let regex = Regex::new(&pattern).unwrap();

        self.redact_captures(text, &regex, 1, type_prefix, "http_header", config)
    }

    fn redact_captures(&mut self, text: &str, regex: &Regex, capture_group: usize, type_upper: &str, type_lower: &str, config: &serde_json::Value) -> Result<String, JsValue> {
        let mut result = text.to_string();
        let mut offset: i32 = 0;
        
        let matches: Vec<(usize, usize, String)> = regex.captures_iter(text)
            .filter_map(|cap| {
                cap.get(capture_group).and_then(|m| {
                    let start = m.start();
                    let end = m.end();
                    if self.is_region_claimed(start, end) {
                        None
                    } else {
                        Some((start, end, m.as_str().to_string()))
                    }
                })
            })
            .collect();

        for (start, end, original) in matches {
            let fingerprint = self.generate_fingerprint(&original);
            let context_start = if start >= 20 { start - 20 } else { 0 };
            let context_end = if end + 20 <= text.len() { end + 20 } else { text.len() };
            let context = text[context_start..context_end].to_string();
            
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
                }
            });

            entry.occurrences += 1;
            if entry.contexts.len() < 3 && !entry.contexts.contains(&context) {
                entry.contexts.push(context);
            }
            
            let canonical_id = entry.id.clone();
            let replacement = self.apply_redaction_mode(&original, &canonical_id, config);
            
            let actual_start = (start as i32 + offset) as usize;
            let actual_end = (end as i32 + offset) as usize;
            
            result.replace_range(actual_start..actual_end, &replacement);
            offset += replacement.len() as i32 - (end - start) as i32;
            
            self.claimed_regions.push(ClaimedRegion {
                start,
                end,
            });
        }

        Ok(result)
    }

    fn redact_email(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        self.redact_with_regex(text, &email_regex, type_prefix, "email", _config)
    }

    fn redact_regex(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let pattern = config.get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Regex pattern not provided in config"))?;

        if pattern.is_empty() {
            return Ok(text.to_string());
        }

        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return Ok(text.to_string()),
        };

        self.redact_with_regex(text, &regex, type_prefix, "regex", config)
    }

    fn redact_ipv4(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let ipv4_regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
        self.redact_with_regex(text, &ipv4_regex, type_prefix, "ipv4", _config)
    }

    fn redact_jwt(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let jwt_regex = Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
        self.redact_with_regex(text, &jwt_regex, type_prefix, "jwt", _config)
    }

    fn redact_uuid(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let uuid_regex = Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap();
        self.redact_with_regex(text, &uuid_regex, type_prefix, "uuid", _config)
    }

    fn redact_phone(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let phone_regex = Regex::new(r"(?:\+\d{1,3}\s?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}").unwrap();
        self.redact_with_regex(text, &phone_regex, type_prefix, "phone", _config)
    }

    fn redact_ssn(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let ssn_regex = Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap();
        self.redact_with_regex(text, &ssn_regex, type_prefix, "ssn", _config)
    }

    fn redact_credit_card(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let cc_regex = Regex::new(r"\b(?:\d{4}[\s-]?){3}\d{4,7}\b").unwrap();
        self.redact_with_regex(text, &cc_regex, type_prefix, "credit_card", _config)
    }

    fn redact_api_key(&mut self, text: &str, config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let regex = if let Some(prefix) = config.get("prefix").and_then(|v| v.as_str()) {
            if !prefix.is_empty() {
                let pattern = format!(r#"\b{}{}[a-zA-Z0-9]{{20,}}\b"#, regex::escape(prefix), r"[\-_]?");
                Regex::new(&pattern).unwrap()
            } else {
                Regex::new(r"\b(?:sk|pk|api|token|key|secret)[\-_][a-zA-Z0-9]{20,}\b").unwrap()
            }
        } else {
            Regex::new(r"\b(?:sk|pk|api|token|key|secret)[\-_][a-zA-Z0-9]{20,}\b").unwrap()
        };
        self.redact_with_regex(text, &regex, type_prefix, "api_key", config)
    }

    fn redact_url(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        let url_regex = Regex::new(r#"https?://[^\s<>"]+#"#).unwrap();
        self.redact_with_regex(text, &url_regex, type_prefix, "url", _config)
    }

    fn redact_ipv6(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        // Matches full and compressed IPv6 addresses
        let ipv6_regex = Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b|\b::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b").unwrap();
        self.redact_with_regex(text, &ipv6_regex, type_prefix, "ipv6", _config)
    }

    fn redact_mac(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        // Matches MAC addresses in various formats: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF
        let mac_regex = Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b[0-9a-f]{12}\b").unwrap();
        self.redact_with_regex(text, &mac_regex, type_prefix, "mac", _config)
    }

    fn redact_hostname(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        // Matches hostnames and FQDNs (but not URLs which are handled separately)
        let hostname_regex = Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap();
        self.redact_with_regex(text, &hostname_regex, type_prefix, "hostname", _config)
    }

    fn redact_username(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        // Heuristic: matches common username patterns like @username, user=, username:, /home/username
        let username_regex = Regex::new(r"(?:@|user=|username=|/home/|/users/)([a-zA-Z0-9_-]{3,32})\b").unwrap();
        
        let mut result = text.to_string();
        let mut offset: i32 = 0;
        
        let matches: Vec<(usize, usize, String)> = username_regex.captures_iter(text)
            .filter_map(|cap| {
                cap.get(1).and_then(|m| {
                    let start = m.start();
                    let end = m.end();
                    if self.is_region_claimed(start, end) {
                        None
                    } else {
                        Some((start, end, m.as_str().to_string()))
                    }
                })
            })
            .collect();

        for (start, end, original) in matches {
            let fingerprint = self.generate_fingerprint(&original);
            
            // Capture context
            let context_start = if start >= 20 { start - 20 } else { 0 };
            let context_end = if end + 20 <= text.len() { end + 20 } else { text.len() };
            let context = text[context_start..context_end].to_string();
            
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
                }
            });

            entry.occurrences += 1;
            
            if entry.contexts.len() < 3 && !entry.contexts.contains(&context) {
                entry.contexts.push(context);
            }
            
            let replacement = format!("<{}>", entry.id);
            let actual_start = (start as i32 + offset) as usize;
            let actual_end = (end as i32 + offset) as usize;
            
            result.replace_range(actual_start..actual_end, &replacement);
            offset += replacement.len() as i32 - (end - start) as i32;
            
            self.claimed_regions.push(ClaimedRegion {
                start,
                end,
            });
        }

        Ok(result)
    }

    fn redact_base64(&mut self, text: &str, _config: &serde_json::Value, type_prefix: &str) -> Result<String, JsValue> {
        // Matches base64 strings (minimum 20 chars to avoid false positives)
        // Looks for entropy and base64 character set
        let base64_regex = Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").unwrap();
        self.redact_with_regex(text, &base64_regex, type_prefix, "base64", _config)
    }

    fn redact_with_regex(&mut self, text: &str, regex: &Regex, type_upper: &str, type_lower: &str, config: &serde_json::Value) -> Result<String, JsValue> {
        let mut result = text.to_string();
        let mut offset: i32 = 0; // Track offset due to replacements
        
        let matches: Vec<(usize, usize, String)> = regex.find_iter(text)
            .filter_map(|m| {
                let start = m.start();
                let end = m.end();
                // Check if this region overlaps with any claimed region
                if self.is_region_claimed(start, end) {
                    None
                } else {
                    Some((start, end, m.as_str().to_string()))
                }
            })
            .collect();

        for (start, end, original) in matches {
            let fingerprint = self.generate_fingerprint(&original);
            
            // Capture context (20 chars before and after)
            let context_start = if start >= 20 { start - 20 } else { 0 };
            let context_end = if end + 20 <= text.len() { end + 20 } else { text.len() };
            let context = text[context_start..context_end].to_string();
            
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
                }
            });

            entry.occurrences += 1;
            
            // Add context if not already present (limit to 3 contexts per entry)
            if entry.contexts.len() < 3 && !entry.contexts.contains(&context) {
                entry.contexts.push(context);
            }
            
            // Clone the ID to avoid borrow checker issues
            let canonical_id = entry.id.clone();
            let replacement = self.apply_redaction_mode(&original, &canonical_id, config);
            
            // Calculate actual position in result string (accounting for previous replacements)
            let actual_start = (start as i32 + offset) as usize;
            let actual_end = (end as i32 + offset) as usize;
            
            // Replace in result string
            result.replace_range(actual_start..actual_end, &replacement);
            
            // Update offset for next replacement
            offset += replacement.len() as i32 - (end - start) as i32;
            
            // Claim this region in the original text coordinates
            self.claimed_regions.push(ClaimedRegion {
                start,
                end,
            });
        }

        Ok(result)
    }
    
    fn is_region_claimed(&self, start: usize, end: usize) -> bool {
        self.claimed_regions.iter().any(|region| {
            // Check for any overlap
            !(end <= region.start || start >= region.end)
        })
    }
    
    fn apply_redaction_mode(&self, original: &str, canonical_id: &str, config: &serde_json::Value) -> String {
        // If static replacement is provided in config (e.g. for Simple Replace), use it
        if let Some(replacement) = config.get("replacement").and_then(|v| v.as_str()) {
            if !replacement.is_empty() {
                return replacement.to_string();
            }
        }

        let mode = config.get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("placeholder");
        
        match mode {
            "mask" => {
                let mask_char = config.get("maskChar")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                mask_char.repeat(original.len())
            },
            "preserveLastN" => {
                let n = config.get("preserveCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(4) as usize;
                
                if original.len() <= n {
                    original.to_string()
                } else {
                    let mask_char = config.get("maskChar")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*");
                    let mask_len = original.len() - n;
                    format!("{}{}", mask_char.repeat(mask_len), &original[original.len() - n..])
                }
            },
            _ => format!("<{}>", canonical_id), // "placeholder" mode (default)
        }
    }

    fn generate_fingerprint(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.session_secret).unwrap();
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn get_canonical_map_json(&self) -> String {
        // Wrap the canonical map in the expected structure
        let wrapper = serde_json::json!({
            "meta": {},
            "canonical": self.canonical_map
        });
        
        match serde_json::to_string(&wrapper) {
            Ok(json) => json,
            Err(_) => String::from(r#"{"meta":{},"canonical":{}}"#),
        }
    }
}
