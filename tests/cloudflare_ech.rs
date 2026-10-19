#![cfg(feature = "ech")]

use doh_proxy::{dns::DnsResolver, ech::DohTlsConnector};
use rustls::client::EchStatus;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 显式运行的公网冒烟，验证国内 DoH 返回的公共入口确实接受论坛 ECH。
/// FLUXDO_ECH_DOH_URL 可覆盖待测服务器；默认验证阿里 DoH。
#[tokio::test]
#[ignore = "需要公网，显式运行验证国内 DoH 与 Cloudflare ECH 入口"]
async fn domestic_doh_accepts_forum_ech() {
    let url = std::env::var("FLUXDO_ECH_DOH_URL")
        .unwrap_or_else(|_| "https://dns.alidns.com/dns-query".to_string());
    let resolver = Arc::new(DnsResolver::new(&url, None, false, None).await.unwrap());
    let result = resolver.lookup_host("linux.do", false).await.unwrap();
    println!(
        "DoH={url}, IPs={:?}, ECH bytes={}",
        result.addrs,
        result
            .ech_config
            .as_ref()
            .map(|bytes| bytes.as_ref().len())
            .unwrap_or(0)
    );
    assert!(!result.addrs.is_empty());
    assert!(result.ech_config.is_some());
    let connector = DohTlsConnector::new(Some(resolver), true, Duration::from_secs(10), None, None);
    let mut stream = connector.connect("linux.do", 443).await.unwrap();
    let status = stream.get_ref().1.ech_status();
    println!("linux.do ECH status: {status:?}");
    assert_eq!(status, EchStatus::Accepted);
    stream
        .write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: linux.do\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "{}",
        text.lines().next().unwrap_or_default()
    );
    assert!(text.contains("sni=encrypted"), "Cloudflare 未确认加密 SNI");
    println!("Cloudflare /cdn-cgi/trace: HTTP 200, sni=encrypted");
}
