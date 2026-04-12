use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Listening address, e.g. "0.0.0.0:443"
    pub listen: String,

    /// Map of name → secret string.
    /// Secret formats:
    ///   - 32 hex chars  → classic (all protocols)
    ///   - "dd" + 32 hex → secure intermediate only
    ///   - "ee" + 32 hex + ascii_domain → FakeTLS (recommended)
    pub users: HashMap<String, String>,

    /// Optional: host to forward non-proxy clients to (FakeTLS spoofing).
    /// Defaults to "www.google.com"
    #[serde(default = "default_mask_host")]
    pub mask_host: String,

}

fn default_mask_host() -> String {
    "www.google.com".to_string()
}

#[derive(Debug, Clone)]
pub enum SecretMode {
    /// Plain 16-byte secret — all protocols allowed
    Classic(Vec<u8>),
    /// "dd" prefix — secure intermediate only
    Secure(Vec<u8>),
    /// "ee" prefix — FakeTLS, carries domain
    FakeTls { secret: Vec<u8>, domain: String },
}

impl SecretMode {
    pub fn raw_secret(&self) -> &[u8] {
        match self {
            SecretMode::Classic(s) | SecretMode::Secure(s) => s,
            SecretMode::FakeTls { secret, .. } => secret,
        }
    }
}

pub fn parse_secret(s: &str) -> Result<SecretMode> {
    if let Some(rest) = s.strip_prefix("ee") {
        // FakeTLS: next 32 hex chars = 16-byte secret, remainder = hex-encoded domain
        if rest.len() < 32 {
            bail!("FakeTLS secret too short");
        }
        let secret = hex::decode(&rest[..32]).context("invalid hex in FakeTLS secret")?;
        let domain = if rest.len() > 32 {
            let domain_hex = &rest[32..];
            let bytes = hex::decode(domain_hex).context("invalid hex domain")?;
            String::from_utf8(bytes).context("domain not valid UTF-8")?
        } else {
            String::new()
        };
        Ok(SecretMode::FakeTls { secret, domain })
    } else if let Some(rest) = s.strip_prefix("dd") {
        let secret = hex::decode(rest).context("invalid hex in dd secret")?;
        Ok(SecretMode::Secure(secret))
    } else {
        let secret = hex::decode(s).context("invalid hex in classic secret")?;
        Ok(SecretMode::Classic(secret))
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).context("parse config")
    }

    /// Parse all user secrets upfront.
    pub fn parsed_secrets(&self) -> Result<HashMap<String, SecretMode>> {
        self.users
            .iter()
            .map(|(name, raw)| {
                let mode = parse_secret(raw)?;
                Ok((name.clone(), mode))
            })
            .collect()
    }
}
