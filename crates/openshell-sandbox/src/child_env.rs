// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

const LOCAL_NO_PROXY: &str = "127.0.0.1,localhost,::1";

/// Build the NO_PROXY value by combining localhost entries with any hosts
/// listed in `OPENSHELL_DIRECT_TCP_HOSTS` / `OPENSHELL_DIRECT_TCP_ENDPOINTS`.
/// Those hosts have iptables ACCEPT rules for direct TCP (set up by netns),
/// so HTTP clients must also skip the proxy to avoid TLS termination issues
/// with non-Node binaries (e.g. Rust/rustls programs that cannot trust the
/// egress proxy CA).
fn build_no_proxy() -> String {
    let mut no_proxy = LOCAL_NO_PROXY.to_owned();
    let mut push_host = |raw: &str| {
        let host = raw.trim();
        if host.is_empty() {
            return;
        }
        no_proxy.push(',');
        no_proxy.push_str(host);
    };
    if let Ok(hosts) = std::env::var("OPENSHELL_DIRECT_TCP_HOSTS") {
        for host in hosts.split(',') {
            push_host(host);
        }
    }
    if let Ok(endpoints) = std::env::var("OPENSHELL_DIRECT_TCP_ENDPOINTS") {
        for entry in endpoints.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let host = entry.rsplit_once(':').map(|(h, _)| h).unwrap_or(entry);
            let host = host.trim().trim_start_matches('[').trim_end_matches(']');
            push_host(host);
        }
    }
    no_proxy
}

pub(crate) fn proxy_env_vars(proxy_url: &str) -> [(&'static str, String); 9] {
    let no_proxy = build_no_proxy();
    [
        ("ALL_PROXY", proxy_url.to_owned()),
        ("HTTP_PROXY", proxy_url.to_owned()),
        ("HTTPS_PROXY", proxy_url.to_owned()),
        ("NO_PROXY", no_proxy.clone()),
        ("http_proxy", proxy_url.to_owned()),
        ("https_proxy", proxy_url.to_owned()),
        ("no_proxy", no_proxy),
        ("grpc_proxy", proxy_url.to_owned()),
        // Node.js only honors HTTP(S)_PROXY for built-in fetch/http clients when
        // proxy support is explicitly enabled at process startup.
        ("NODE_USE_ENV_PROXY", "1".to_owned()),
    ]
}

pub(crate) fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 4] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path),
    ]
}

/// Serializes tests that read or write `OPENSHELL_DIRECT_TCP_*`.
///
/// `std::env::set_var` / `remove_var` are unsafe because a concurrent read or
/// write of the environment is undefined behavior. Tests run in parallel by
/// default, and the tests in this module and in `sandbox::linux::netns` touch
/// the same variables, so every such test holds this lock for its whole body.
#[cfg(test)]
pub(crate) fn lock_direct_tcp_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

    #[test]
    fn apply_proxy_env_includes_node_proxy_opt_in_and_local_bypass() {
        let _env = lock_direct_tcp_env();
        // Ensure no leftover env from other tests affects NO_PROXY
        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::remove_var("OPENSHELL_DIRECT_TCP_HOSTS") };

        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        for (key, value) in proxy_env_vars("http://10.200.0.1:3128") {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("HTTP_PROXY=http://10.200.0.1:3128"));
        assert!(stdout.contains("NO_PROXY=127.0.0.1,localhost,::1"));
        assert!(stdout.contains("NODE_USE_ENV_PROXY=1"));
        assert!(stdout.contains("no_proxy=127.0.0.1,localhost,::1"));
    }

    #[test]
    fn no_proxy_includes_direct_tcp_hosts() {
        let _env = lock_direct_tcp_env();
        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::remove_var("OPENSHELL_DIRECT_TCP_ENDPOINTS") };
        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::set_var(
            "OPENSHELL_DIRECT_TCP_HOSTS",
            "oauth2.googleapis.com,gmail.googleapis.com",
        ) };

        let no_proxy = build_no_proxy();
        assert_eq!(
            no_proxy,
            "127.0.0.1,localhost,::1,oauth2.googleapis.com,gmail.googleapis.com"
        );

        // Clean up
        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::remove_var("OPENSHELL_DIRECT_TCP_HOSTS") };
    }

    #[test]
    fn no_proxy_includes_direct_tcp_endpoints() {
        let _env = lock_direct_tcp_env();
        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::remove_var("OPENSHELL_DIRECT_TCP_HOSTS") };
        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::set_var(
            "OPENSHELL_DIRECT_TCP_ENDPOINTS",
            "10.0.1.215:5432, 10.0.1.215:6379 , db.internal:1025,",
        ) };

        let no_proxy = build_no_proxy();
        assert_eq!(
            no_proxy,
            "127.0.0.1,localhost,::1,10.0.1.215,10.0.1.215,db.internal"
        );

        // SAFETY: test-only; all tests touching these env vars hold lock_direct_tcp_env().
        unsafe { std::env::remove_var("OPENSHELL_DIRECT_TCP_ENDPOINTS") };
    }

    #[test]
    fn apply_tls_env_sets_node_and_bundle_paths() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        for (key, value) in tls_env_vars(ca_cert_path, combined_bundle_path) {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("NODE_EXTRA_CA_CERTS=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
    }
}
