//! A deliberately thin CyberArk Central Credential Provider (AIM web service) reader.
//!
//! One request shape: `GET /AIMWebService/api/Accounts` with an application id, a safe and an
//! object name. The Central Credential Provider identifies the calling application by client
//! certificate, allowed machine, path or hash; the application id on its own is a weak factor and
//! not a secret, but it is still kept out of every error message, because an error message is the
//! one thing in this tool that reliably reaches a CI log. Mutual TLS is configured once for every
//! provider through [`crate::http`].
//!
//! The query, regular-expression and folder lookup modes are out of scope. So is
//! `FailRequestOnPasswordChange`. A reference names one account and one property, which is the
//! shape that can be read in a config file and audited in a diff.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::http;
use crate::reference::CcpRef;
use crate::{Error, Result};

/// Base address of the Central Credential Provider, for example `https://ccp.example`.
pub const URL_VAR: &str = "SEALREF_CCP_URL";

/// The application id registered in CyberArk.
pub const APP_ID_VAR: &str = "SEALREF_CCP_APP_ID";

/// The AIM web service path under the base address.
pub const API_PATH: &str = "/AIMWebService/api/Accounts";

/// Central Credential Provider connection settings.
pub struct CcpConfig {
    url: String,
    app_id: String,
}

impl std::fmt::Debug for CcpConfig {
    /// The application id is a weak authentication factor, so it is redacted like a credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CcpConfig")
            .field("url", &self.url)
            .field("app_id", &"<redacted>")
            .finish()
    }
}

impl CcpConfig {
    /// Read `SEALREF_CCP_URL` and `SEALREF_CCP_APP_ID`.
    pub fn from_env() -> Result<Self> {
        let url = env_value(URL_VAR).ok_or_else(|| Error::Ccp(format!("{URL_VAR} is not set")))?;
        let app_id =
            env_value(APP_ID_VAR).ok_or_else(|| Error::Ccp(format!("{APP_ID_VAR} is not set")))?;
        Ok(CcpConfig {
            url: http::normalise_base_url(&url),
            app_id,
        })
    }

    /// The request URL for one account.
    ///
    /// Kept separate from the call so the query construction is testable, and so no caller is ever
    /// tempted to put the result in an error: it carries the application id.
    pub fn request_url(&self, reference: &CcpRef) -> String {
        format!(
            "{}{API_PATH}?AppID={}&Safe={}&Object={}",
            self.url,
            http::percent_encode(&self.app_id),
            http::percent_encode(&reference.safe),
            http::percent_encode(&reference.object)
        )
    }

    /// Read one property of one account.
    pub fn read_field(&self, reference: &CcpRef) -> Result<Zeroizing<String>> {
        let response = http::agent()?.get(&self.request_url(reference)).call();
        let response = match http::check(response) {
            Ok(response) => response,
            Err(http::Failure::Status { code, response }) => {
                // CyberArk's ErrorMsg echoes the application id, the safe and the requesting
                // machine, so only the stable vendor error code is reported.
                let vendor = response
                    .into_string()
                    .ok()
                    .and_then(|body| error_code(&body))
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default();
                return Err(Error::Ccp(format!(
                    "{} returned HTTP {code}{vendor} for {}{}",
                    self.url,
                    reference.locator(),
                    http::redirect_note(code)
                )));
            }
            Err(http::Failure::Transport(reason)) => {
                return Err(Error::Ccp(format!(
                    "cannot reach {} for {}: {reason}",
                    self.url,
                    reference.locator()
                )))
            }
        };
        let body =
            Zeroizing::new(response.into_string().map_err(|_| {
                Error::Ccp(format!("unreadable response for {}", reference.locator()))
            })?);
        extract_field(&body, &reference.field, &reference.locator())
    }
}

#[derive(Deserialize)]
struct CcpError {
    #[serde(rename = "ErrorCode")]
    error_code: Option<String>,
}

/// Pull the stable `ErrorCode` out of a CyberArk error body, if it has one.
pub fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<CcpError>(body)
        .ok()
        .and_then(|e| e.error_code)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 32
                && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Pull one property out of an AIM web service response body.
///
/// Split out from the HTTP call so the response contract is testable without a live Central
/// Credential Provider.
pub fn extract_field(body: &str, field: &str, locator: &str) -> Result<Zeroizing<String>> {
    let parsed: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        Error::Ccp(format!(
            "{locator}: response is not a CyberArk account: {e}"
        ))
    })?;
    let object = parsed
        .as_object()
        .ok_or_else(|| Error::Ccp(format!("{locator}: response is not a CyberArk account")))?;
    let value = object.get(field).ok_or_else(|| {
        Error::Ccp(format!(
            "{locator}: the account has no property \"{field}\""
        ))
    })?;
    match value {
        serde_json::Value::String(s) => Ok(Zeroizing::new(s.clone())),
        serde_json::Value::Null => Err(Error::Ccp(format!(
            "{locator}: property \"{field}\" is null"
        ))),
        _ => Err(Error::Ccp(format!(
            "{locator}: property \"{field}\" is not a string"
        ))),
    }
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::Reference;

    const BODY: &str = r#"{
        "Content": "hunter2",
        "UserName": "svc_app",
        "Address": "db01.example",
        "Safe": "MySafe",
        "Folder": "Root",
        "Name": "pg-main",
        "PasswordChangeInProcess": false,
        "Empty": null
    }"#;

    fn config() -> CcpConfig {
        CcpConfig {
            url: "https://ccp.example".to_string(),
            app_id: "myapp".to_string(),
        }
    }

    fn reference(text: &str) -> CcpRef {
        match Reference::parse(text).unwrap() {
            Reference::Ccp(c) => c,
            other => panic!("expected a ccp reference, got {other:?}"),
        }
    }

    #[test]
    fn builds_the_request_url() {
        assert_eq!(
            config().request_url(&reference("seal:ccp:MySafe/pg-main#Content")),
            "https://ccp.example/AIMWebService/api/Accounts\
             ?AppID=myapp&Safe=MySafe&Object=pg-main"
        );
    }

    #[test]
    fn escapes_a_safe_name_with_a_space() {
        assert_eq!(
            config().request_url(&reference("seal:ccp:Prod Databases/pg-main#Content")),
            "https://ccp.example/AIMWebService/api/Accounts\
             ?AppID=myapp&Safe=Prod%20Databases&Object=pg-main"
        );
    }

    #[test]
    fn extracts_the_password_property() {
        assert_eq!(
            &*extract_field(BODY, "Content", "MySafe/pg-main#Content").unwrap(),
            "hunter2"
        );
    }

    #[test]
    fn extracts_another_property() {
        assert_eq!(
            &*extract_field(BODY, "UserName", "MySafe/pg-main#UserName").unwrap(),
            "svc_app"
        );
    }

    #[test]
    fn rejects_a_missing_property() {
        let err = extract_field(BODY, "Nope", "MySafe/pg-main#Nope").unwrap_err();
        assert!(err.to_string().contains("has no property"));
    }

    #[test]
    fn rejects_a_non_string_property() {
        let err = extract_field(
            BODY,
            "PasswordChangeInProcess",
            "MySafe/pg-main#PasswordChangeInProcess",
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not a string"));
    }

    #[test]
    fn rejects_a_null_property() {
        let err = extract_field(BODY, "Empty", "MySafe/pg-main#Empty").unwrap_err();
        assert!(err.to_string().contains("is null"));
    }

    #[test]
    fn rejects_a_body_that_is_not_an_account() {
        assert!(extract_field("[1,2]", "Content", "x").is_err());
        assert!(extract_field("not json", "Content", "x").is_err());
    }

    #[test]
    fn reads_the_stable_error_code() {
        let body = r#"{"ErrorCode":"APPAP004E","ErrorMsg":"Password object matching query [Safe=MySafe;Object=pg-main] was not found (Diagnostic Info: 5)"}"#;
        assert_eq!(error_code(body).unwrap(), "APPAP004E");
    }

    #[test]
    fn ignores_an_error_code_that_is_not_a_code() {
        // Whatever ends up in the message must never reach stderr through this path.
        let body = r#"{"ErrorCode":"a very long sentence that is not a code at all"}"#;
        assert!(error_code(body).is_none());
        assert!(error_code(r#"{"ErrorMsg":"no code"}"#).is_none());
        assert!(error_code("not json").is_none());
    }

    #[test]
    fn debug_does_not_leak_the_application_id() {
        let rendered = format!("{:?}", config());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("myapp"));
    }
}
