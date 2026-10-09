//! Per-session Ed25519-signed connection tickets.
//!
//! The portal mints a signed ticket on authorizeConnectionLaunch(); the host
//! binary verifies it locally using a cached public key (pushed via the
//! enrollment/heartbeat response).
//!
//! SECURITY: Private key material must NEVER be logged, committed, or echoed.
//! The private key is stored in the RUSTDESK_TICKET_SIGNING_KEY environment
//! variable (base64-encoded 32-byte ed25519 secret key). The public key is
//! derived and pushed to devices via the heartbeat response.

use base64::engine::{
    general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use lazy_static::lazy_static;
use sodiumoxide::crypto::sign::{verify_detached, PublicKey, Signature};
use std::convert::TryInto;
use std::sync::Mutex;

/// Error types for ticket validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    /// Ticket has expired (issued_at or expires_at outside tolerance).
    Expired,
    /// Ticket device_id doesn't match the host device.
    DeviceMismatch,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Ticket was already used (nonce replay).
    Replayed,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketError::Expired => write!(f, "ticket expired"),
            TicketError::DeviceMismatch => write!(f, "device mismatch"),
            TicketError::InvalidSignature => write!(f, "invalid signature"),
            TicketError::Replayed => write!(f, "ticket replayed"),
        }
    }
}

impl std::error::Error for TicketError {}

lazy_static! {
    static ref TICKET_PUBLIC_KEY: Mutex<String> = Mutex::new(String::new());
}

const TICKET_EXPIRY_SKEW_SECONDS: i64 = 30;

fn is_ticket_expired(now_unix: i64, expires_unix: i64) -> bool {
    now_unix > expires_unix.saturating_add(TICKET_EXPIRY_SKEW_SECONDS)
}

/// Verify an Ed25519-signed connection ticket.
///
/// The ticket format is: `1.<base64url(payload)>.<base64(signature)>`
/// where the payload is a JSON object containing:
/// - device_id: The target device ID
/// - token_id: The connection_authorization_token's id
/// - issued_at: ISO 8601 UTC timestamp
/// - expires_at: ISO 8601 UTC expiry timestamp
/// - nonce: Single-use random value
///
/// The canonical signing string is: `version.device_id.token_id.issued_at.expires_at.nonce`
pub fn verify_ticket(
    ticket: &str,
    local_device_id: &str,
    consumed_nonces: &mut Vec<String>,
) -> Result<(), TicketError> {
    // 1. Check ticket prefix
    let ticket = ticket
        .strip_prefix("1.")
        .ok_or(TicketError::InvalidSignature)?;

    // 2. Parse payload and signature
    let parts: Vec<&str> = ticket.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(TicketError::InvalidSignature);
    }
    let signature_b64 = parts[0];
    let payload_b64url = parts[1];

    // Decode base64url payload
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64url)
        .map_err(|_| TicketError::InvalidSignature)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_json).map_err(|_| TicketError::InvalidSignature)?;

    // Extract fields
    let device_id = payload["device_id"]
        .as_str()
        .ok_or(TicketError::InvalidSignature)?;
    let _token_id = payload["token_id"]
        .as_str()
        .ok_or(TicketError::InvalidSignature)?;
    let _issued_at = payload["issued_at"]
        .as_str()
        .ok_or(TicketError::InvalidSignature)?;
    let expires_at = payload["expires_at"]
        .as_str()
        .ok_or(TicketError::InvalidSignature)?;
    let nonce = payload["nonce"]
        .as_str()
        .ok_or(TicketError::InvalidSignature)?;

    // 3. Reject tickets more than 30 seconds past expiry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| TicketError::InvalidSignature)?;
    let expires_unix = expires.timestamp();
    let now_unix = now.as_secs() as i64;
    if is_ticket_expired(now_unix, expires_unix) {
        return Err(TicketError::Expired);
    }

    // 4. Device ID match
    if device_id != local_device_id {
        return Err(TicketError::DeviceMismatch);
    }

    // 5. Verify signature against cached public key
    let pub_key_str = TICKET_PUBLIC_KEY.lock().unwrap().clone();
    if pub_key_str.is_empty() {
        // Default-deny: no public key cached yet.
        // Devices must complete a successful heartbeat to receive the public key
        // before any connections are accepted.
        log::warn!(
            "No ticket public key cached — connection rejected (default-deny until heartbeat)"
        );
        return Err(TicketError::InvalidSignature);
    }
    let pub_key = PublicKey(
        STANDARD
            .decode(&pub_key_str)
            .map_err(|_| TicketError::InvalidSignature)?
            .try_into()
            .map_err(|_| TicketError::InvalidSignature)?,
    );
    let message = serialize_ticket_for_signing(&payload);
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| TicketError::InvalidSignature)?;
    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| TicketError::InvalidSignature)?;
    let signature = Signature::new(sig_bytes);
    if !verify_detached(&signature, message.as_bytes(), &pub_key) {
        return Err(TicketError::InvalidSignature);
    }

    // 6. Single-use (nonce replay detection)
    if consumed_nonces.contains(&nonce.to_string()) {
        return Err(TicketError::Replayed);
    }
    consumed_nonces.push(nonce.to_string());

    Ok(())
}

/// Serialize a ticket to a canonical string for signing.
/// Format: version.device_id.token_id.issued_at.expires_at.nonce
pub fn serialize_ticket_for_signing(payload: &serde_json::Value) -> String {
    let version = "1";
    let device_id = payload["device_id"].as_str().unwrap_or("");
    let token_id = payload["token_id"].as_str().unwrap_or("");
    let issued_at = payload["issued_at"].as_str().unwrap_or("");
    let expires_at = payload["expires_at"].as_str().unwrap_or("");
    let nonce = payload["nonce"].as_str().unwrap_or("");
    format!(
        "{}.{}.{}.{}.{}.{}",
        version, device_id, token_id, issued_at, expires_at, nonce
    )
}

/// Update the cached verification public key (called from heartbeat response).
pub fn set_ticket_public_key(base64_key: &str) {
    let mut key = TICKET_PUBLIC_KEY.lock().unwrap();
    *key = base64_key.to_owned();
    log::info!(
        "Ticket verification public key updated (len={})",
        base64_key.len()
    );
}

#[cfg(test)]
mod tests {
    use super::{is_ticket_expired, verify_ticket, TicketError};
    use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

    #[test]
    fn ticket_expiring_in_future_is_valid() {
        assert!(!is_ticket_expired(1_000, 1_090));
    }

    #[test]
    fn ticket_within_expiry_skew_is_valid() {
        assert!(!is_ticket_expired(1_030, 1_000));
    }

    #[test]
    fn ticket_beyond_expiry_skew_is_expired() {
        assert!(is_ticket_expired(1_031, 1_000));
    }

    #[test]
    fn unpadded_base64url_payload_is_parsed() {
        let payload = serde_json::json!({
            "device_id": "different-device",
            "token_id": "test-token",
            "issued_at": "2026-10-09T00:00:00.000Z",
            "expires_at": "2999-10-09T00:01:30.000Z",
            "nonce": "test-nonce",
        });
        let encoded = URL_SAFE_NO_PAD.encode(payload.to_string());
        assert!(!encoded.contains('='));
        let ticket = format!("1.{}.AA==", encoded);
        let result = verify_ticket(&ticket, "expected-device", &mut Vec::new());
        assert_eq!(result, Err(TicketError::DeviceMismatch));
    }
}
