use crate::support::config::{TrustApiConfig, TrustApiMode};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct Request<'a> {
    path: &'a str,
}

#[derive(Debug, Deserialize, Default)]
struct Response {
    trusted: Option<bool>,
    signer_subject: Option<String>,
    signer_thumbprint: Option<String>,
    is_signed: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ApiDecision {
    pub is_trusted: bool,
    pub is_signed: bool,
    pub signer_subject: Option<String>,
    pub signer_thumbprint: Option<String>,
}

fn decision_from_response(body: Response) -> ApiDecision {
    ApiDecision {
        is_trusted: body.trusted.unwrap_or(false),
        is_signed: body.is_signed.unwrap_or(body.trusted.unwrap_or(false)),
        signer_subject: body.signer_subject,
        signer_thumbprint: body.signer_thumbprint,
    }
}

pub fn verify(path: &str, cfg: &TrustApiConfig) -> Result<ApiDecision> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.max(500)))
        .build()
        .context("trust_api client build failed")?;

    let mut req = client.post(&cfg.endpoint).json(&Request { path });
    if let Some(key) = &cfg.api_key {
        req = req.header("Authorization", key);
    }

    let resp = req
        .send()
        .context("trust_api request failed")?
        .error_for_status()
        .context("trust_api non-success status")?;

    let body: Response = resp.json().context("trust_api JSON parse failed")?;
    Ok(decision_from_response(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    fn spawn_http_server(status: u16, body: &'static str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind http listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set timeout");
            let mut req_buf = [0u8; 8192];
            let n = stream.read(&mut req_buf).expect("read request");
            let req = String::from_utf8_lossy(&req_buf[..n]).to_string();

            let response = format!(
                "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                if status >= 400 { "ERROR" } else { "OK" },
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            req
        });

        (format!("http://{}/verify", addr), handle)
    }

    #[test]
    fn decision_parses_positive_response() {
        let body = Response {
            trusted: Some(true),
            signer_subject: Some("ACME Corp".into()),
            signer_thumbprint: Some("AA11".into()),
            is_signed: Some(true),
        };
        let decision = decision_from_response(body);
        assert!(decision.is_trusted);
        assert!(decision.is_signed);
        assert_eq!(decision.signer_subject.as_deref(), Some("ACME Corp"));
        assert_eq!(decision.signer_thumbprint.as_deref(), Some("AA11"));
    }

    #[test]
    fn verify_posts_path_and_parses_response() {
        let (endpoint, handle) = spawn_http_server(
            200,
            r#"{"trusted":true,"is_signed":true,"signer_subject":"ACME Corp","signer_thumbprint":"AA11"}"#,
        );

        let cfg = TrustApiConfig {
            enabled: true,
            endpoint,
            api_key: Some("Bearer token-1".to_string()),
            timeout_ms: 2000,
            mode: TrustApiMode::ApiOnly,
        };

        let decision = verify(r"C:\sample\tool.exe", &cfg).expect("verify");
        assert!(decision.is_trusted);
        assert!(decision.is_signed);
        assert_eq!(decision.signer_subject.as_deref(), Some("ACME Corp"));

        let request = handle.join().expect("join server");
        assert!(request.starts_with("POST /verify HTTP/1.1"));
        let request_lower = request.to_lowercase();
        assert!(request_lower.contains("authorization:"));
        assert!(request_lower.contains("authorization: bearer "));
        assert!(request.contains(r#""path":"C:\\sample\\tool.exe""#));
    }

    #[test]
    fn verify_rejects_non_success_status() {
        let (endpoint, handle) = spawn_http_server(503, r#"{"trusted":false}"#);

        let cfg = TrustApiConfig {
            enabled: true,
            endpoint,
            api_key: None,
            timeout_ms: 2000,
            mode: TrustApiMode::ApiOnly,
        };

        let err = verify(r"C:\sample\tool.exe", &cfg).expect_err("expected error");
        let msg = format!("{err:#}");
        assert!(msg.contains("non-success status"));
        let _ = handle.join();
    }
}
