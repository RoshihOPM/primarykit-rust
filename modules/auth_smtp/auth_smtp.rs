//! Opt-in SMTP provider adapter for the durable auth_http outbox.
//!
//! TLS is mandatory; credentials and encryption keys come from environment
//! or a production secret manager. Never log tokens, credentials or URLs
//! containing verification/reset fragments.

use super::auth_http::{identity_outbox::OutboxKeyring, TokenDelivery};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::{env, sync::Arc};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SmtpConfigError {
    #[error("missing required SMTP or identity configuration: {0}")]
    Missing(&'static str),
    #[error("invalid SMTP relay hostname")]
    Relay,
    #[error("invalid sender address")]
    Sender,
    #[error("invalid public HTTPS application origin")]
    PublicOrigin,
    #[error("invalid identity email encryption key")]
    OutboxKey,
    #[error("unable to configure required SMTP TLS")]
    Transport,
}

/// Avoid implementing Debug: the configuration contains a password.
#[derive(Clone)]
pub struct SmtpConfig {
    relay_host: String,
    username: String,
    password: String,
    sender: Mailbox,
    public_origin: Url,
}

impl SmtpConfig {
    pub fn new(
        relay_host: String,
        username: String,
        password: String,
        sender: String,
        public_origin: String,
    ) -> Result<Self, SmtpConfigError> {
        // Only hostnames are accepted. Lettre's relay() verifies server TLS
        // certificates; a caller cannot disable TLS with a custom URL.
        if relay_host.len() > 253
            || relay_host.is_empty()
            || relay_host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            || username.trim().is_empty()
            || password.is_empty()
        {
            return Err(SmtpConfigError::Relay);
        }

        let sender = sender.parse().map_err(|_| SmtpConfigError::Sender)?;
        let public_origin =
            Url::parse(&public_origin).map_err(|_| SmtpConfigError::PublicOrigin)?;
        // Fail closed: don't allow credentials in URLs, arbitrary paths,
        // query strings, or fragments controlled by the deployment.
        if public_origin.scheme() != "https"
            || public_origin.host_str().is_none()
            || !public_origin.username().is_empty()
            || public_origin.password().is_some()
            || public_origin.query().is_some()
            || public_origin.fragment().is_some()
            || public_origin.path() != "/"
        {
            return Err(SmtpConfigError::PublicOrigin);
        }

        Ok(Self {
            relay_host,
            username,
            password,
            sender,
            public_origin,
        })
    }

    pub fn from_env() -> Result<Self, SmtpConfigError> {
        fn required(key: &'static str) -> Result<String, SmtpConfigError> {
            env::var(key).map_err(|_| SmtpConfigError::Missing(key))
        }

        Self::new(
            required("SMTP_RELAY_HOST")?,
            required("SMTP_USERNAME")?,
            required("SMTP_PASSWORD")?,
            required("SMTP_FROM")?,
            required("IDENTITY_PUBLIC_ORIGIN")?,
        )
    }

    fn link(&self, purpose: &'static str, token: &str) -> Result<Url, ()> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(());
        }
        let path = match purpose {
            "verify" => "/verify-email",
            "reset" => "/reset-password",
            _ => return Err(()),
        };
        let mut url = self.public_origin.clone();
        url.set_path(path);
        // Fragments are not sent as HTTP request targets or Referer values.
        // The frontend must read the fragment, POST the token to the API,
        // then clear the fragment from browser history immediately.
        url.set_fragment(Some(&format!("token={token}")));
        Ok(url)
    }

    fn message(&self, purpose: &'static str, recipient: &str, token: &str) -> Result<Message, ()> {
        let recipient: Mailbox = recipient.parse().map_err(|_| ())?;
        let (subject, instruction) = match purpose {
            "verify" => ("Verify your email address", "To verify your email address"),
            "reset" => ("Reset your password", "To reset your password"),
            _ => return Err(()),
        };
        let link = self.link(purpose, token)?;
        Message::builder()
            .from(self.sender.clone())
            .to(recipient)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(format!(
                "{instruction}, open the following secure link:\n{link}\n\n\
                 If you did not request this message, ignore it.\n"
            ))
            .map_err(|_| ())
    }

    /// Creates a callback that is directly compatible with auth_http's
    /// transactional outbox worker. Delivery errors cause a bounded retry.
    pub fn delivery(&self) -> Result<TokenDelivery, SmtpConfigError> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&self.relay_host)
            .map_err(|_| SmtpConfigError::Transport)?
            .credentials(Credentials::new(
                self.username.clone(),
                self.password.clone(),
            ))
            .build();
        let transport = Arc::new(transport);
        let config = Arc::new(self.clone());

        Ok(Arc::new(move |purpose, to, token| {
            let transport = Arc::clone(&transport);
            let config = Arc::clone(&config);
            Box::pin(async move {
                let message = config.message(purpose, &to, &token)?;
                // Do not interpolate the SMTP error into logs; some providers
                // include the address/command and may expose sensitive context.
                transport.send(message).await.map_err(|_| ())?;
                Ok(())
            })
        }))
    }
}

fn decode_key_hex(value: &str) -> Result<[u8; 32], SmtpConfigError> {
    if value.len() != 64 {
        return Err(SmtpConfigError::OutboxKey);
    }
    let bytes = hex::decode(value).map_err(|_| SmtpConfigError::OutboxKey)?;
    bytes.try_into().map_err(|_| SmtpConfigError::OutboxKey)
}

/// Parse the active key and any decrypt-only previous keys. The previous
/// format is a comma-separated list of ID=64hex entries, without whitespace.
fn parse_outbox_keys(
    active_id: &str,
    active_hex: &str,
    previous_spec: &str,
) -> Result<Arc<OutboxKeyring>, SmtpConfigError> {
    let mut previous = Vec::new();
    if !previous_spec.is_empty() {
        for entry in previous_spec.split(',') {
            let (id, value) = entry.split_once('=').ok_or(SmtpConfigError::OutboxKey)?;
            previous.push((id.to_owned(), decode_key_hex(value)?));
        }
    }
    let ring = OutboxKeyring::new(active_id, decode_key_hex(active_hex)?, previous)
        .map_err(|_| SmtpConfigError::OutboxKey)?;
    Ok(Arc::new(ring))
}

/// Load versioned encryption keys from environment. ID defaults to "legacy"
/// to support deployments upgrading from the original unversioned key.
/// A rotation sets a *new* ID and active key, then lists older keys under
/// IDENTITY_OUTBOX_PREVIOUS_KEYS="legacy=<old-hex>,v2=<older-hex>".
/// Do not log the values of any encryption variables.
pub fn outbox_keys_from_env() -> Result<Arc<OutboxKeyring>, SmtpConfigError> {
    let active_id = env::var("IDENTITY_OUTBOX_KEY_ID").unwrap_or_else(|_| "legacy".to_owned());
    let active_key = env::var("IDENTITY_OUTBOX_KEY_HEX")
        .map_err(|_| SmtpConfigError::Missing("IDENTITY_OUTBOX_KEY_HEX"))?;
    let previous = env::var("IDENTITY_OUTBOX_PREVIOUS_KEYS").unwrap_or_default();
    parse_outbox_keys(&active_id, &active_key, &previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SmtpConfig {
        SmtpConfig::new(
            "smtp.example.org".to_owned(),
            "smtp-user".to_owned(),
            "private-test-password".to_owned(),
            "Example <no-reply@example.org>".to_owned(),
            "https://app.example.org/".to_owned(),
        )
        .expect("test configuration")
    }

    #[test]
    fn versioned_outbox_key_configuration_rejects_malformed_or_duplicate_keys() {
        let initial = "11".repeat(32);
        let older = "22".repeat(32);
        let keys = parse_outbox_keys("v2", &initial, &format!("legacy={older}"))
            .expect("valid active and previous keys");
        assert_eq!(keys.active_id(), "v2");
        assert!(parse_outbox_keys("v2", &initial, &format!("v2={older}")).is_err());
        assert!(parse_outbox_keys("invalid id", &initial, "").is_err());
        assert!(parse_outbox_keys("v2", "invalid", "").is_err());
        assert!(parse_outbox_keys("v2", &initial, "legacy=invalid").is_err());
        assert!(parse_outbox_keys("v2", &initial, "legacy=invalid,").is_err());
        assert!(
            parse_outbox_keys("v2", &initial, &format!("legacy={older},legacy={older}")).is_err()
        );
    }

    #[test]
    fn requires_https_origin_and_relay_host() {
        for origin in [
            "http://app.example.org/",
            "https://user:password@app.example.org/",
            "https://app.example.org/path",
            "https://app.example.org/?redirect=bad",
            "https://app.example.org/#fragment",
        ] {
            assert!(SmtpConfig::new(
                "smtp.example.org".into(),
                "user".into(),
                "pass".into(),
                "from@example.org".into(),
                origin.into(),
            )
            .is_err());
        }
        assert!(SmtpConfig::new(
            "smtp.example.org:25".into(),
            "user".into(),
            "pass".into(),
            "from@example.org".into(),
            "https://app.example.org/".into(),
        )
        .is_err());
    }

    #[test]
    fn reset_and_verification_secrets_use_fragment_not_query() {
        let cfg = config();
        let secret = "a".repeat(64);
        let link = cfg.link("verify", &secret).expect("verification link");
        assert_eq!(link.scheme(), "https");
        assert_eq!(link.path(), "/verify-email");
        assert_eq!(link.query(), None);
        assert_eq!(link.fragment(), Some(format!("token={secret}").as_str()));

        let reset = cfg.link("reset", &secret).expect("reset link");
        assert_eq!(reset.path(), "/reset-password");
        assert!(cfg.link("unknown", &secret).is_err());
        assert!(cfg.link("verify", "unsafe#link").is_err());
    }

    #[test]
    fn valid_message_does_not_use_untrusted_headers() {
        let cfg = config();
        let secret = "b".repeat(64);
        let message = cfg
            .message("reset", "person@example.org", &secret)
            .expect("message");
        let raw = String::from_utf8(message.formatted()).expect("RFC email");
        assert!(raw.contains("Reset your password"));
        assert!(raw.contains("https://app.example.org/reset-password#token="));
        assert!(!raw.contains("Bcc:"));
        assert!(cfg
            .message("reset", "bad@example.org\r\nBcc: bad@example.org", &secret)
            .is_err());
    }
}
