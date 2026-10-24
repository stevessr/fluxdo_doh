use rustls::crypto::CryptoProvider;
use rustls::CipherSuite;

/// 构建 TLS 加密提供者，cipher suite 顺序对齐 Chrome/BoringSSL：
/// TLS 1.3: AES_128_GCM → AES_256_GCM → CHACHA20_POLY1305
/// TLS 1.2: ECDHE_*_AES_128_GCM → ECDHE_*_AES_256_GCM → ECDHE_*_CHACHA20
///
/// Key exchange groups 优先 X25519MLKEM768，保留 X25519 等传统组回退。
/// ECH 和非 ECH 路径使用同一套后量子提供者，避免 ECH 模式意外禁用 PQC。
pub fn build_provider() -> CryptoProvider {
    #[cfg(feature = "pqc")]
    {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        // prefer-post-quantum 使 ClientHello 初始 key share 优先发送
        // X25519MLKEM768，而不是依赖服务器发起 HelloRetryRequest。
        provider.cipher_suites = reorder_cipher_suites_chrome_style(provider.cipher_suites);
        return provider;
    }

    #[cfg(not(feature = "pqc"))]
    {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites = reorder_cipher_suites_chrome_style(provider.cipher_suites);
        return provider;
    }
}

/// 将 cipher suites 重排为 Chrome/BoringSSL 风格。
///
/// Chrome 的 cipher suite 偏好（基于 BoringSSL）：
/// - TLS 1.3: AES-128-GCM(4865) → AES-256-GCM(4866) → ChaCha20(4867)
/// - TLS 1.2: ECDHE_ECDSA/RSA_AES_128_GCM → ECDHE_ECDSA/RSA_AES_256_GCM
///            → ECDHE_ECDSA/RSA_CHACHA20
///
/// rustls ring 默认把 ChaCha20 放最前面，这会导致 JA3 指纹明显不同于浏览器，
/// 可能被 Cloudflare Bot Management 标记为非浏览器客户端。
fn reorder_cipher_suites_chrome_style(
    suites: Vec<rustls::SupportedCipherSuite>,
) -> Vec<rustls::SupportedCipherSuite> {
    let priority = |suite: &rustls::SupportedCipherSuite| -> u32 {
        match suite.suite() {
            // TLS 1.3 — Chrome 顺序
            CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
            CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
            // TLS 1.2 — Chrome 顺序
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 10,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 11,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 12,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 13,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 14,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 15,
            _ => 100,
        }
    };

    let mut sorted = suites;
    sorted.sort_by_key(|s| priority(s));
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "pqc")]
    fn hybrid_pq_group_is_preferred_with_classical_fallback() {
        use rustls::NamedGroup;
        let provider = build_provider();
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups.first(), Some(&NamedGroup::X25519MLKEM768));
        assert!(groups.contains(&NamedGroup::X25519));
        assert!(groups.contains(&NamedGroup::secp256r1));
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn pq_provider_builds_tls13_client_config() {
        use std::sync::Arc;
        let provider = Arc::new(build_provider());
        assert!(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .is_ok()
        );
    }

    #[test]
    #[cfg(not(feature = "pqc"))]
    fn legacy_provider_preserves_classical_tls() {
        let provider = build_provider();
        assert!(provider
            .kx_groups
            .iter()
            .any(|group| group.name() == rustls::NamedGroup::X25519));
    }
}
