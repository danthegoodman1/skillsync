use std::fmt;
use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::blocking::{Client, Response};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::config::Config;

const BODY_LIMIT: usize = 32 * 1024;
const TICKET_LIMIT: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ATTEMPTS: usize = 2;
const MAX_SERVICE_URL_BYTES: usize = 2_048;
const MAX_CUSTOM_HEADERS: usize = 16;
const MAX_CUSTOM_HEADER_NAME_BYTES: usize = 128;
const MAX_CUSTOM_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_CUSTOM_HEADER_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct JoiningServiceClient {
    base_url: Url,
    headers: HeaderMap,
    client: Client,
}

impl fmt::Debug for JoiningServiceClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoiningServiceClient")
            .field("base_url", &"[configured]")
            .field("headers", &"[redacted]")
            .finish()
    }
}

impl JoiningServiceClient {
    pub fn from_config(config: &Config) -> Result<Self, JoiningServiceError> {
        let base_url = config.effective_joining_service_url();
        Self::new(
            &base_url,
            config
                .joining
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.expose())),
        )
    }

    pub fn new<'a>(
        base_url: &str,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, JoiningServiceError> {
        Self::with_timeout(base_url, headers, REQUEST_TIMEOUT)
    }

    fn with_timeout<'a>(
        base_url: &str,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        timeout: Duration,
    ) -> Result<Self, JoiningServiceError> {
        if base_url.len() > MAX_SERVICE_URL_BYTES {
            return Err(JoiningServiceError::InvalidUrl);
        }
        let mut base_url = Url::parse(base_url).map_err(|_| JoiningServiceError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(JoiningServiceError::InvalidUrl);
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let mut parsed_headers = HeaderMap::new();
        let mut header_count = 0_usize;
        let mut header_bytes = 0_usize;
        for (name, value) in headers {
            if name.is_empty()
                || name.len() > MAX_CUSTOM_HEADER_NAME_BYTES
                || value.len() > MAX_CUSTOM_HEADER_VALUE_BYTES
            {
                return Err(JoiningServiceError::InvalidHeader);
            }
            header_count = header_count.saturating_add(1);
            header_bytes = header_bytes
                .saturating_add(name.len())
                .saturating_add(value.len());
            if header_count > MAX_CUSTOM_HEADERS || header_bytes > MAX_CUSTOM_HEADER_BYTES {
                return Err(JoiningServiceError::InvalidHeader);
            }
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| JoiningServiceError::InvalidHeader)?;
            let value =
                HeaderValue::from_str(value).map_err(|_| JoiningServiceError::InvalidHeader)?;
            if name == CONTENT_TYPE || name.as_str().eq_ignore_ascii_case("idempotency-key") {
                return Err(JoiningServiceError::ReservedHeader);
            }
            parsed_headers.insert(name, value);
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| JoiningServiceError::Client)?;
        Ok(Self {
            base_url,
            headers: parsed_headers,
            client,
        })
    }

    pub fn create(
        &self,
        inviter_ticket: &str,
        ttl: Duration,
    ) -> Result<CreatedInvitation, JoiningServiceError> {
        if inviter_ticket.is_empty() || inviter_ticket.len() > TICKET_LIMIT {
            return Err(JoiningServiceError::InvalidTicket);
        }
        let ttl_seconds = ttl.as_secs();
        if !(60..=900).contains(&ttl_seconds) {
            return Err(JoiningServiceError::InvalidTtl);
        }
        let request = CreateRequest {
            protocol: "skillsync/1",
            inviter_ticket,
            ttl_seconds,
        };
        let response: CreateResponse = self.post("v1/invitations", &request, 201)?;
        validate_code(&response.code)?;
        let join_nonce = decode_nonce(&response.join_nonce)?;
        validate_timestamp(&response.expires_at)?;
        Ok(CreatedInvitation {
            code: response.code,
            join_nonce,
            expires_at: response.expires_at,
        })
    }

    pub fn claim(&self, code: &str) -> Result<ClaimedInvitation, JoiningServiceError> {
        validate_code(code)?;
        let request = ClaimRequest { code };
        let response: ClaimResponse = self.post("v1/invitations/claim", &request, 200)?;
        if response.protocol != "skillsync/1"
            || response.inviter_ticket.is_empty()
            || response.inviter_ticket.len() > TICKET_LIMIT
        {
            return Err(JoiningServiceError::InvalidResponse);
        }
        validate_timestamp(&response.expires_at)?;
        Ok(ClaimedInvitation {
            inviter_ticket: response.inviter_ticket,
            join_nonce: decode_nonce(&response.join_nonce)?,
            expires_at: response.expires_at,
        })
    }

    fn post<T, R>(
        &self,
        path: &str,
        request: &T,
        expected_status: u16,
    ) -> Result<R, JoiningServiceError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let body = serde_json::to_vec(request).map_err(|_| JoiningServiceError::InvalidRequest)?;
        if body.len() > BODY_LIMIT {
            return Err(JoiningServiceError::BodyTooLarge);
        }
        let url = self
            .base_url
            .join(path)
            .map_err(|_| JoiningServiceError::InvalidUrl)?;
        let idempotency_key = Uuid::new_v4().to_string();
        let mut last_transport = None;
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .client
                .post(url.clone())
                .headers(self.headers.clone())
                .header(CONTENT_TYPE, "application/json")
                .header("Idempotency-Key", &idempotency_key)
                .body(body.clone())
                .send();
            match response {
                Ok(response) => {
                    let retryable =
                        response.status().as_u16() == 429 || response.status().is_server_error();
                    if retryable && attempt + 1 < MAX_ATTEMPTS {
                        continue;
                    }
                    match decode_response(response, expected_status) {
                        Ok(response) => return Ok(response),
                        Err(ResponseDecodeError::Retryable(error))
                            if attempt + 1 < MAX_ATTEMPTS =>
                        {
                            last_transport = Some(error);
                        }
                        Err(ResponseDecodeError::Retryable(error))
                        | Err(ResponseDecodeError::Final(error)) => return Err(error),
                    }
                }
                Err(error) => {
                    last_transport = Some(if error.is_timeout() {
                        JoiningServiceError::Timeout
                    } else {
                        JoiningServiceError::Unavailable
                    });
                }
            }
        }
        Err(last_transport.unwrap_or(JoiningServiceError::Unavailable))
    }
}

#[derive(Clone)]
pub struct CreatedInvitation {
    pub code: String,
    pub join_nonce: [u8; 32],
    pub expires_at: String,
}

impl fmt::Debug for CreatedInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedInvitation")
            .field("code", &"[redacted]")
            .field("join_nonce", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct ClaimedInvitation {
    pub inviter_ticket: String,
    pub join_nonce: [u8; 32],
    pub expires_at: String,
}

impl fmt::Debug for ClaimedInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedInvitation")
            .field("inviter_ticket", &"[redacted]")
            .field("join_nonce", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Serialize)]
struct CreateRequest<'a> {
    protocol: &'static str,
    inviter_ticket: &'a str,
    ttl_seconds: u64,
}

#[derive(Deserialize)]
struct CreateResponse {
    code: String,
    join_nonce: String,
    expires_at: String,
}

#[derive(Serialize)]
struct ClaimRequest<'a> {
    code: &'a str,
}

#[derive(Deserialize)]
struct ClaimResponse {
    protocol: String,
    inviter_ticket: String,
    join_nonce: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ServiceError,
}

#[derive(Deserialize)]
struct ServiceError {
    code: String,
    message: String,
}

enum ResponseDecodeError {
    Retryable(JoiningServiceError),
    Final(JoiningServiceError),
}

fn decode_response<R: for<'de> Deserialize<'de>>(
    mut response: Response,
    expected_status: u16,
) -> Result<R, ResponseDecodeError> {
    let status = response.status().as_u16();
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > BODY_LIMIT as u64) {
        return Err(ResponseDecodeError::Final(
            JoiningServiceError::BodyTooLarge,
        ));
    }
    let mut bytes = Vec::new();
    if let Err(error) = response
        .by_ref()
        .take((BODY_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
    {
        return Err(ResponseDecodeError::Retryable(
            if error.kind() == std::io::ErrorKind::TimedOut {
                JoiningServiceError::Timeout
            } else {
                JoiningServiceError::Unavailable
            },
        ));
    }
    if bytes.len() > BODY_LIMIT {
        return Err(ResponseDecodeError::Final(
            JoiningServiceError::BodyTooLarge,
        ));
    }
    if content_length.is_some_and(|length| length != bytes.len() as u64) {
        return Err(ResponseDecodeError::Retryable(
            JoiningServiceError::Unavailable,
        ));
    }
    if status == expected_status {
        return serde_json::from_slice(&bytes)
            .map_err(|_| ResponseDecodeError::Final(JoiningServiceError::InvalidResponse));
    }
    let envelope: ErrorEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| ResponseDecodeError::Final(JoiningServiceError::InvalidResponse))?;
    if envelope.error.code.is_empty()
        || envelope.error.code.len() > 128
        || envelope.error.message.is_empty()
        || envelope.error.message.len() > 1024
    {
        return Err(ResponseDecodeError::Final(
            JoiningServiceError::InvalidResponse,
        ));
    }
    Err(ResponseDecodeError::Final(JoiningServiceError::Service {
        status,
    }))
}

fn validate_code(code: &str) -> Result<(), JoiningServiceError> {
    if code.is_empty()
        || code.len() > 128
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err(JoiningServiceError::InvalidCode);
    }
    Ok(())
}

fn decode_nonce(value: &str) -> Result<[u8; 32], JoiningServiceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JoiningServiceError::InvalidResponse)?;
    bytes
        .try_into()
        .map_err(|_| JoiningServiceError::InvalidResponse)
}

fn validate_timestamp(value: &str) -> Result<(), JoiningServiceError> {
    if value.len() > 64
        || !value.ends_with('Z')
        || time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .is_err()
    {
        return Err(JoiningServiceError::InvalidResponse);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum JoiningServiceError {
    #[error("joining service URL is invalid")]
    InvalidUrl,
    #[error("joining service header is invalid")]
    InvalidHeader,
    #[error("joining service header is reserved")]
    ReservedHeader,
    #[error("joining service client could not be created")]
    Client,
    #[error("invitation TTL must be from 60 through 900 seconds")]
    InvalidTtl,
    #[error("inviter ticket is invalid")]
    InvalidTicket,
    #[error("joining code is invalid")]
    InvalidCode,
    #[error("joining request is invalid")]
    InvalidRequest,
    #[error("joining service body exceeds 32 KiB")]
    BodyTooLarge,
    #[error("joining service request timed out")]
    Timeout,
    #[error("joining service is unavailable")]
    Unavailable,
    #[error("joining service returned an invalid response")]
    InvalidResponse,
    #[error("joining service returned HTTP {status}")]
    Service { status: u16 },
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::*;

    struct Fixture {
        url: String,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Fixture {
        fn start(responses: Vec<(Duration, u16, Vec<u8>)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = requests.clone();
            let thread = thread::spawn(move || {
                for (delay, status, body) in responses {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request = read_request(&mut stream);
                    captured.lock().unwrap().push(request);
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                    let reason = match status {
                        200 => "OK",
                        201 => "Created",
                        429 => "Too Many Requests",
                        500 => "Internal Server Error",
                        503 => "Service Unavailable",
                        _ => "Error",
                    };
                    let header = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&body);
                }
            });
            Self {
                url,
                requests,
                thread: Some(thread),
            }
        }

        fn finish(mut self) -> Vec<Vec<u8>> {
            self.thread.take().unwrap().join().unwrap();
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let header_end = loop {
            if let Some(index) = request.windows(4).position(|item| item == b"\r\n\r\n") {
                break index + 4;
            }
            let mut bytes = [0_u8; 1024];
            let read = stream.read(&mut bytes).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&bytes[..read]);
        };
        let header = String::from_utf8_lossy(&request[..header_end]);
        let content_length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let mut bytes = [0_u8; 1024];
            let read = stream.read(&mut bytes).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&bytes[..read]);
        }
        request
    }

    fn nonce() -> String {
        URL_SAFE_NO_PAD.encode([7_u8; 32])
    }

    #[test]
    fn create_retries_with_one_idempotency_key_and_custom_headers() {
        let success = serde_json::to_vec(&serde_json::json!({
            "code": "furry-salamander",
            "join_nonce": nonce(),
            "expires_at": "2026-08-08T17:20:00Z"
        }))
        .unwrap();
        let unavailable =
            br#"{"error":{"code":"temporarily_unavailable","message":"retry"}}"#.to_vec();
        let fixture = Fixture::start(vec![
            (Duration::ZERO, 503, unavailable),
            (Duration::ZERO, 201, success),
        ]);
        let client =
            JoiningServiceClient::new(&fixture.url, [("Authorization", "Bearer private-token")])
                .unwrap();
        let invitation = client
            .create("endpointabc", Duration::from_secs(600))
            .unwrap();
        assert_eq!(invitation.code, "furry-salamander");
        assert_eq!(invitation.join_nonce, [7; 32]);
        let requests = fixture.finish();
        assert_eq!(requests.len(), 2);
        let text = requests
            .iter()
            .map(|request| String::from_utf8_lossy(request))
            .collect::<Vec<_>>();
        for request in &text {
            assert!(request.starts_with("POST /v1/invitations HTTP/1.1"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer private-token")
            );
            assert!(request.contains("\"ttl_seconds\":600"));
        }
        let keys = text
            .iter()
            .map(|request| {
                request
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(keys[0], keys[1]);
        assert!(Uuid::parse_str(keys[0].split_once(':').unwrap().1.trim()).is_ok());
        let debug = format!("{client:?} {invitation:?}");
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("furry-salamander"));
        assert!(!debug.contains(&nonce()));
    }

    #[test]
    fn claim_preserves_an_opaque_code_and_validates_the_payload() {
        let body = serde_json::to_vec(&serde_json::json!({
            "protocol": "skillsync/1",
            "inviter_ticket": "endpointopaque",
            "join_nonce": nonce(),
            "expires_at": "2026-08-08T17:20:00Z"
        }))
        .unwrap();
        let fixture = Fixture::start(vec![(Duration::ZERO, 200, body)]);
        let client = JoiningServiceClient::new(&fixture.url, []).unwrap();
        let claimed = client.claim("A._~-z9").unwrap();
        assert_eq!(claimed.inviter_ticket, "endpointopaque");
        assert_eq!(claimed.join_nonce, [7; 32]);
        let request = String::from_utf8(fixture.finish().remove(0)).unwrap();
        assert!(request.starts_with("POST /v1/invitations/claim HTTP/1.1"));
        assert!(request.contains("\"code\":\"A._~-z9\""));
        let debug = format!("{claimed:?}");
        assert!(!debug.contains("endpointopaque"));
        assert!(!debug.contains(&nonce()));
    }

    #[test]
    fn local_limits_reject_ttl_ticket_code_headers_and_credentials() {
        let client = JoiningServiceClient::new("http://127.0.0.1:9", []).unwrap();
        assert!(matches!(
            client.create("endpoint", Duration::from_secs(59)),
            Err(JoiningServiceError::InvalidTtl)
        ));
        assert!(matches!(
            client.create(&"x".repeat(TICKET_LIMIT + 1), Duration::from_secs(60)),
            Err(JoiningServiceError::InvalidTicket)
        ));
        assert!(matches!(
            client.claim("contains space"),
            Err(JoiningServiceError::InvalidCode)
        ));
        assert!(matches!(
            JoiningServiceClient::new("https://user:pass@example.test", []),
            Err(JoiningServiceError::InvalidUrl)
        ));
        assert!(matches!(
            JoiningServiceClient::new("https://example.test?token=secret", []),
            Err(JoiningServiceError::InvalidUrl)
        ));
        assert!(matches!(
            JoiningServiceClient::new("https://example.test", [("Idempotency-Key", "x")]),
            Err(JoiningServiceError::ReservedHeader)
        ));

        let exact_url = format!(
            "https://example.test/{}",
            "a".repeat(MAX_SERVICE_URL_BYTES - "https://example.test/".len())
        );
        assert!(JoiningServiceClient::new(&exact_url, []).is_ok());
        assert!(matches!(
            JoiningServiceClient::new(&format!("{exact_url}a"), []),
            Err(JoiningServiceError::InvalidUrl)
        ));

        let max_value = "v".repeat(MAX_CUSTOM_HEADER_VALUE_BYTES);
        let bounded = JoiningServiceClient::new(
            "https://example.test",
            [("Authorization", max_value.as_str())],
        )
        .unwrap();
        assert!(!format!("{bounded:?}").contains(&max_value));
        let oversized_value = "v".repeat(MAX_CUSTOM_HEADER_VALUE_BYTES + 1);
        assert!(matches!(
            JoiningServiceClient::new(
                "https://example.test",
                [("Authorization", oversized_value.as_str())]
            ),
            Err(JoiningServiceError::InvalidHeader)
        ));
        let headers = (0..=MAX_CUSTOM_HEADERS)
            .map(|index| (format!("X-Header-{index}"), "value".to_owned()))
            .collect::<Vec<_>>();
        assert!(
            JoiningServiceClient::new(
                "https://example.test",
                headers[..MAX_CUSTOM_HEADERS]
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
            )
            .is_ok()
        );
        assert!(matches!(
            JoiningServiceClient::new(
                "https://example.test",
                headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
            ),
            Err(JoiningServiceError::InvalidHeader)
        ));
        let max_name = "x".repeat(MAX_CUSTOM_HEADER_NAME_BYTES);
        assert!(
            JoiningServiceClient::new("https://example.test", [(max_name.as_str(), "value")])
                .is_ok()
        );
        let oversized_name = format!("{max_name}x");
        assert!(matches!(
            JoiningServiceClient::new("https://example.test", [(oversized_name.as_str(), "value")]),
            Err(JoiningServiceError::InvalidHeader)
        ));
        let aggregate = (0..3)
            .map(|index| (format!("X-Aggregate-{index}"), "v".repeat(6_000)))
            .collect::<Vec<_>>();
        assert!(matches!(
            JoiningServiceClient::new(
                "https://example.test",
                aggregate
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
            ),
            Err(JoiningServiceError::InvalidHeader)
        ));
    }

    #[test]
    fn response_limit_timeout_and_service_errors_are_bounded_and_redacted() {
        let fixture = Fixture::start(vec![(Duration::ZERO, 200, vec![b'x'; BODY_LIMIT + 1])]);
        let client = JoiningServiceClient::new(&fixture.url, []).unwrap();
        assert!(matches!(
            client.claim("opaque"),
            Err(JoiningServiceError::BodyTooLarge)
        ));
        fixture.finish();

        let body =
            br#"{"error":{"code":"join_unavailable","message":"secret-code funny-capybara"}}"#
                .to_vec();
        let fixture = Fixture::start(vec![
            (Duration::ZERO, 429, body.clone()),
            (Duration::ZERO, 429, body),
        ]);
        let client = JoiningServiceClient::new(&fixture.url, []).unwrap();
        let error = client.claim("opaque").unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("funny-capybara"));
        assert!(!rendered.contains("secret-code"));
        assert!(!rendered.contains("join_unavailable"));
        fixture.finish();

        let fixture = Fixture::start(vec![
            (Duration::from_millis(100), 200, Vec::new()),
            (Duration::from_millis(100), 200, Vec::new()),
        ]);
        let client = JoiningServiceClient::with_timeout(
            &fixture.url,
            std::iter::empty::<(&str, &str)>(),
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(matches!(
            client.claim("opaque"),
            Err(JoiningServiceError::Timeout)
        ));
        fixture.finish();
    }

    #[test]
    fn consumed_or_unknown_code_fails_closed_as_unavailable() {
        let body = br#"{"error":{"code":"join_unavailable","message":"The joining code is unavailable or expired."}}"#.to_vec();
        let fixture = Fixture::start(vec![(Duration::ZERO, 409, body)]);
        let client = JoiningServiceClient::new(&fixture.url, []).unwrap();
        assert!(matches!(
            client.claim("opaque"),
            Err(JoiningServiceError::Service { status: 409 })
        ));
        fixture.finish();
    }

    #[test]
    fn truncated_success_retries_with_the_same_idempotency_key() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": "skillsync/1",
            "inviter_ticket": "endpoint-retried",
            "join_nonce": nonce(),
            "expires_at": "2026-08-08T17:20:00Z"
        }))
        .unwrap();
        let served = response.clone();
        let thread = thread::spawn(move || {
            let mut requests = Vec::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                let declared = if attempt == 0 {
                    served.len() + 10
                } else {
                    served.len()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                stream.write_all(&served).unwrap();
            }
            requests
        });
        let client = JoiningServiceClient::new(&url, []).unwrap();
        assert_eq!(
            client.claim("opaque").unwrap().inviter_ticket,
            "endpoint-retried"
        );
        let requests = thread.join().unwrap();
        assert_eq!(requests.len(), 2);
        let keys = requests
            .iter()
            .map(|request| {
                String::from_utf8_lossy(request)
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(keys[0], keys[1]);
    }

    #[test]
    fn redirects_are_not_followed_with_configured_headers() {
        let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", first.local_addr().unwrap());
        let location = format!("http://{}/stolen", redirect_target.local_addr().unwrap());
        let thread = thread::spawn(move || {
            let (mut stream, _) = first.accept().unwrap();
            let request = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            request
        });
        let client =
            JoiningServiceClient::new(&url, [("Authorization", "Bearer must-not-cross-origin")])
                .unwrap();
        assert!(matches!(
            client.claim("opaque"),
            Err(JoiningServiceError::InvalidResponse)
        ));
        let first_request = String::from_utf8(thread.join().unwrap()).unwrap();
        assert!(first_request.contains("Bearer must-not-cross-origin"));
        assert!(matches!(
            redirect_target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
