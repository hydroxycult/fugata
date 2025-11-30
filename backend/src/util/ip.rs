use axum::http::HeaderMap;
use std::net::IpAddr;

use crate::config::ProxyMode;

pub fn extract_client_ip(
    headers: &HeaderMap,
    peer_ip: IpAddr,
    trusted_proxies: &[IpAddr],
    proxy_mode: &ProxyMode,
) -> String {
    match proxy_mode {
        ProxyMode::Direct => peer_ip.to_string(),
        ProxyMode::TrustedProxy => {
            if trusted_proxies.contains(&peer_ip) {
                extract_forwarded_for(headers).unwrap_or_else(|| peer_ip.to_string())
            } else {
                tracing::warn!(
                    peer_ip = %peer_ip,
                    "Untrusted peer attempted to use TrustedProxy mode, using peer IP"
                );
                peer_ip.to_string()
            }
        }
        ProxyMode::Auto => extract_forwarded_for(headers).unwrap_or_else(|| peer_ip.to_string()),
    }
}

fn extract_forwarded_for(headers: &HeaderMap) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(value) = xff.to_str() {
            if let Some(client_ip) = value.split(',').next() {
                let client_ip = client_ip.trim();
                if !client_ip.is_empty() {
                    return Some(client_ip.to_string());
                }
            }
        }
    }

    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(value) = xri.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers(xff: Option<&str>, xri: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(xff_val) = xff {
            headers.insert("x-forwarded-for", HeaderValue::from_str(xff_val).unwrap());
        }
        if let Some(xri_val) = xri {
            headers.insert("x-real-ip", HeaderValue::from_str(xri_val).unwrap());
        }
        headers
    }

    #[test]
    fn test_direct_mode_uses_peer_ip() {
        let headers = make_headers(Some("192.168.1.100"), None);
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec![];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::Direct);
        assert_eq!(result, "10.0.0.1", "Direct mode must use peer IP");
    }

    #[test]
    fn test_trusted_proxy_uses_xff() {
        let headers = make_headers(Some("203.0.113.1"), None);
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.1".parse().unwrap()];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::TrustedProxy);
        assert_eq!(
            result, "203.0.113.1",
            "Trusted proxy must use X-Forwarded-For"
        );
    }

    #[test]
    fn test_untrusted_proxy_ignores_xff() {
        let headers = make_headers(Some("192.168.1.100"), None);
        let peer_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let trusted = vec!["10.0.0.1".parse().unwrap()];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::TrustedProxy);
        assert_eq!(
            result, "203.0.113.50",
            "Untrusted peer must be ignored, use peer IP"
        );
    }

    #[test]
    fn test_xff_chain_takes_first() {
        let headers = make_headers(Some("198.51.100.1, 10.0.0.1, 10.0.0.2"), None);
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.1".parse().unwrap()];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::TrustedProxy);
        assert_eq!(result, "198.51.100.1", "Must take first IP from XFF chain");
    }

    #[test]
    fn test_x_real_ip_fallback() {
        let headers = make_headers(None, Some("198.51.100.5"));
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.1".parse().unwrap()];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::TrustedProxy);
        assert_eq!(result, "198.51.100.5", "Must fallback to X-Real-IP");
    }

    #[test]
    fn test_no_headers_uses_peer() {
        let headers = HeaderMap::new();
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.1".parse().unwrap()];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::TrustedProxy);
        assert_eq!(result, "10.0.0.1", "No headers must use peer IP");
    }

    #[test]
    fn test_auto_mode_uses_xff_unsafe() {
        let headers = make_headers(Some("192.168.1.100"), None);
        let peer_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let trusted = vec![];

        let result = extract_client_ip(&headers, peer_ip, &trusted, &ProxyMode::Auto);
        assert_eq!(
            result, "192.168.1.100",
            "Auto mode must use XFF even from untrusted"
        );
    }
}
