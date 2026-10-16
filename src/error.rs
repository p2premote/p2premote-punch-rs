//! Shared business failures. Message text is never a control-flow protocol.
pub use crate::error_codes::ErrorCode;
use std::{error::Error as StdError, fmt, sync::Arc};

#[derive(Clone, Debug)]
struct SharedSource(Arc<dyn StdError + Send + Sync>);
impl fmt::Display for SharedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl StdError for SharedSource {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct AppError {
    code: ErrorCode,
    message: String,
    #[source]
    source: Option<SharedSource>,
}

impl AppError {
    pub fn with_boxed_source(
        code: ErrorCode,
        message: impl Into<String>,
        source: Box<dyn StdError + Send + Sync>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source: Some(SharedSource(Arc::from(source))),
        }
    }
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }
    pub fn with_source(
        code: ErrorCode,
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source: Some(SharedSource(Arc::new(source))),
        }
    }
    pub fn code(&self) -> ErrorCode {
        self.code.clone()
    }
    pub fn context(self, message: impl Into<String>) -> Self {
        Self::with_source(self.code(), message, self)
    }
    pub fn from_wire(code: &str, message: impl Into<String>) -> Self {
        if valid_code(code) {
            Self::new(ErrorCode::parse(code), message)
        } else {
            Self::new(
                ErrorCode::NativeDecodeInvalidPayload,
                "missing or invalid structured error code",
            )
        }
    }
}

pub fn valid_code(code: &str) -> bool {
    if code.is_empty() || code.len() > 64 {
        return false;
    }
    let mut count = 0;
    for part in code.split('.') {
        count += 1;
        if !part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return false;
        }
    }
    count == 3
}

pub fn effective_code(mut error: &(dyn StdError + 'static)) -> ErrorCode {
    loop {
        if let Some(coded) = error.downcast_ref::<AppError>() {
            return coded.code();
        }
        match error.source() {
            Some(source) => error = source,
            None => return ErrorCode::RuntimeExecutionUnclassified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_keeps_code_and_io_source() {
        let err = AppError::with_source(
            ErrorCode::TraversalPunchIoFailed,
            "socket failed",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )
        .context("device connection failed")
        .context("another language / 任意文案");
        assert_eq!(effective_code(&err), ErrorCode::TraversalPunchIoFailed);
        let mut source: &dyn StdError = &err;
        while source.downcast_ref::<std::io::Error>().is_none() {
            source = source.source().expect("I/O cause retained");
        }
    }
    #[test]
    fn unknown_codes_round_trip_without_retry() {
        let code: ErrorCode = serde_json::from_str("\"future.exchange.new_reason\"").unwrap();
        assert_eq!(code.as_str(), "future.exchange.new_reason");
        assert_eq!(code.retry_class(), "stop");
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            "\"future.exchange.new_reason\""
        );
        for invalid in ["", "timeout", "a.b", "a.b.c.d", "A.b.c", "a.b.bad-code"] {
            assert!(!valid_code(invalid));
        }
    }
    #[test]
    fn registry_vectors_match() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/error-codes-v1.json")).unwrap();
        for row in vectors["codes"].as_array().unwrap() {
            let code = ErrorCode::parse(row["code"].as_str().unwrap());
            assert!(code.is_known());
            assert_eq!(code.message(), row["message"].as_str().unwrap());
            assert_eq!(code.retry_class(), row["retry_class"].as_str().unwrap());
        }
    }
}
