use std::net::Ipv4Addr;

use rust_vpn_splitter::domain::{SplitterConfig, VpnKind, validate_config_with_resolver};

fn enabled_config(entries: &[(VpnKind, &str)]) -> SplitterConfig {
    let mut config = SplitterConfig::default();
    for (vpn, targets) in entries {
        let profile = config.profile_mut(*vpn).expect("profile exists");
        profile.enabled = true;
        profile.networks = (*targets).to_owned();
    }
    config
}

#[test]
fn enabled_profile_accepts_mixed_cidr_domain_and_url_targets() {
    let config = enabled_config(&[(
        VpnKind::FortiClient,
        "192.0.2.0/24\nhttp://gitlab.example.test:1500/\npackages.example.test",
    )]);

    let validated = validate_config_with_resolver(&config, |vpn, hostname| match hostname {
        "gitlab.example.test" => Ok(vec![
            Ipv4Addr::new(198, 51, 100, 11),
            Ipv4Addr::new(198, 51, 100, 10),
        ]),
        "packages.example.test" => Ok(vec![Ipv4Addr::new(203, 0, 113, 25)]),
        other => Err(format!("unexpected {vpn} hostname: {other}")),
    })
    .expect("mixed targets should be valid");

    assert_eq!(
        validated[0].networks,
        vec![
            "192.0.2.0/24".parse().unwrap(),
            "198.51.100.10/32".parse().unwrap(),
            "198.51.100.11/32".parse().unwrap(),
            "203.0.113.25/32".parse().unwrap(),
        ]
    );
    assert_eq!(
        validated[0].hostnames,
        vec!["gitlab.example.test", "packages.example.test"]
    );
}

#[test]
fn resolved_url_address_cannot_overlap_another_enabled_vpn() {
    let config = enabled_config(&[
        (VpnKind::FortiClient, "http://gitlab.example.test:1500/"),
        (VpnKind::F5, "198.51.100.0/24"),
    ]);

    let errors = validate_config_with_resolver(&config, |vpn, hostname| match hostname {
        "gitlab.example.test" => Ok(vec![Ipv4Addr::new(198, 51, 100, 40)]),
        other => Err(format!("unexpected {vpn} hostname: {other}")),
    })
    .expect_err("a resolved URL address must participate in overlap validation");

    assert!(errors.iter().any(|error| {
        error.message.contains("FortiClient")
            && error.message.contains("gitlab.example.test")
            && error.message.contains("198.51.100.40/32")
            && error.message.contains("F5")
            && error.message.contains("198.51.100.0/24")
    }));
}

#[test]
fn one_hostname_cannot_select_two_vpn_dns_views() {
    let config = enabled_config(&[
        (VpnKind::FortiClient, "shared.example.test"),
        (VpnKind::Ivanti, "https://shared.example.test/path"),
    ]);

    let errors = validate_config_with_resolver(&config, |vpn, _| {
        let address = match vpn {
            VpnKind::FortiClient => Ipv4Addr::new(198, 51, 100, 10),
            VpnKind::Ivanti => Ipv4Addr::new(203, 0, 113, 10),
            VpnKind::F5 => unreachable!(),
        };
        Ok(vec![address])
    })
    .expect_err("one hostname cannot use two VPN DNS servers");

    assert!(errors.iter().any(|error| {
        error.message.contains("shared.example.test")
            && error.message.contains("FortiClient")
            && error.message.contains("Ivanti")
    }));
}

#[test]
fn bare_ipv4_target_is_not_sent_to_dns() {
    let config = enabled_config(&[(VpnKind::F5, "163.21.158.7")]);
    let mut resolution_calls = 0;

    let validated = validate_config_with_resolver(&config, |_, hostname| {
        resolution_calls += 1;
        Err(format!("bare IPv4 was incorrectly sent to DNS: {hostname}"))
    })
    .expect("a bare IPv4 target should be accepted without DNS resolution");

    assert_eq!(resolution_calls, 0);
    assert_eq!(
        validated[0].networks,
        vec!["163.21.158.7/32".parse().unwrap()]
    );
    assert!(validated[0].hostnames.is_empty());
}
