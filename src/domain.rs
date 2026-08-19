use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VpnKind {
    FortiClient,
    F5,
    Ivanti,
}

impl VpnKind {
    pub const ALL: [Self; 3] = [Self::FortiClient, Self::F5, Self::Ivanti];

    pub const fn key(self) -> &'static str {
        match self {
            Self::FortiClient => "forticlient",
            Self::F5 => "f5",
            Self::Ivanti => "ivanti",
        }
    }
}

impl fmt::Display for VpnKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FortiClient => "FortiClient",
            Self::F5 => "F5",
            Self::Ivanti => "Ivanti",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProfile {
    pub vpn: VpnKind,
    pub enabled: bool,
    pub networks: String,
    pub adapter_description: Option<String>,
}

impl VpnProfile {
    fn new(vpn: VpnKind) -> Self {
        Self {
            vpn,
            enabled: false,
            networks: String::new(),
            adapter_description: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitterConfig {
    pub profiles: Vec<VpnProfile>,
}

impl Default for SplitterConfig {
    fn default() -> Self {
        Self {
            profiles: VpnKind::ALL.into_iter().map(VpnProfile::new).collect(),
        }
    }
}

impl SplitterConfig {
    pub fn profile(&self, vpn: VpnKind) -> Option<&VpnProfile> {
        self.profiles.iter().find(|profile| profile.vpn == vpn)
    }

    pub fn profile_mut(&mut self, vpn: VpnKind) -> Option<&mut VpnProfile> {
        self.profiles.iter_mut().find(|profile| profile.vpn == vpn)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProfile {
    pub vpn: VpnKind,
    pub networks: Vec<Ipv4Net>,
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub vpns: Vec<VpnKind>,
    pub message: String,
}

/// Validates the whole desired configuration through one interface.
///
/// Disabled profiles are intentionally ignored. Enabled profiles must contain
/// at least one IPv4 CIDR, IPv4 address, domain, or URL. Domains and URL hosts
/// are resolved into IPv4 /32 routes. A default route is rejected, and concrete
/// routes cannot overlap routes assigned to another enabled VPN.
pub fn validate_config(
    config: &SplitterConfig,
) -> Result<Vec<ValidatedProfile>, Vec<ValidationError>> {
    validate_config_with_resolver(config, |_, hostname| resolve_system_ipv4(hostname))
}

pub fn validate_config_with_resolver(
    config: &SplitterConfig,
    mut resolve_hostname: impl FnMut(VpnKind, &str) -> Result<Vec<Ipv4Addr>, String>,
) -> Result<Vec<ValidatedProfile>, Vec<ValidationError>> {
    let mut errors = Vec::new();
    let mut validated = Vec::new();
    let mut network_sources = BTreeMap::new();
    let mut resolved_hosts = BTreeMap::new();
    let mut hostname_owners = BTreeMap::new();

    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let tokens = target_tokens(&profile.networks).collect::<Vec<_>>();

        if tokens.is_empty() {
            errors.push(ValidationError {
                vpns: vec![profile.vpn],
                message: format!("{} 已啟用，但尚未填入任何 CIDR、網域或網址。", profile.vpn),
            });
            continue;
        }

        let mut networks = Vec::new();
        let mut hostnames = BTreeSet::new();

        for token in tokens {
            match token.parse::<Ipv4Net>() {
                Ok(network) => {
                    let network = network.trunc();
                    if network.prefix_len() == 0 {
                        errors.push(ValidationError {
                            vpns: vec![profile.vpn],
                            message: format!(
                                "{} 不接受 0.0.0.0/0；這個工具只管理分流路由。",
                                profile.vpn
                            ),
                        });
                    } else {
                        add_network(
                            profile.vpn,
                            token,
                            network,
                            &mut networks,
                            &mut network_sources,
                        );
                    }
                }
                Err(_) => match target_host(token) {
                    Ok(Host::Ipv4(address)) => {
                        add_network(
                            profile.vpn,
                            token,
                            Ipv4Net::new(address, 32).expect("/32 is valid"),
                            &mut networks,
                            &mut network_sources,
                        );
                    }
                    Ok(Host::Domain(hostname)) => {
                        if let Some(existing_vpn) = hostname_owners.get(&hostname)
                            && *existing_vpn != profile.vpn
                        {
                            errors.push(ValidationError {
                                vpns: vec![*existing_vpn, profile.vpn],
                                message: format!(
                                    "網域 {hostname} 同時指定給 {existing_vpn} 與 {}；同一名稱只能使用一組 VPN DNS。",
                                    profile.vpn
                                ),
                            });
                            continue;
                        }
                        hostname_owners.insert(hostname.clone(), profile.vpn);
                        hostnames.insert(hostname.clone());

                        match resolved_hosts
                            .entry((profile.vpn, hostname.clone()))
                            .or_insert_with(|| resolve_hostname(profile.vpn, &hostname))
                            .clone()
                        {
                            Ok(addresses) if !addresses.is_empty() => {
                                for address in addresses {
                                    add_network(
                                        profile.vpn,
                                        token,
                                        Ipv4Net::new(address, 32).expect("/32 is valid"),
                                        &mut networks,
                                        &mut network_sources,
                                    );
                                }
                            }
                            Ok(_) => errors.push(ValidationError {
                                vpns: vec![profile.vpn],
                                message: format!(
                                    "{} 的「{token}」沒有解析到任何 IPv4 位址。",
                                    profile.vpn
                                ),
                            }),
                            Err(error) => errors.push(ValidationError {
                                vpns: vec![profile.vpn],
                                message: format!(
                                    "{} 無法解析「{token}」的網域 {hostname}：{error}",
                                    profile.vpn
                                ),
                            }),
                        }
                    }
                    Ok(Host::Ipv6(_)) => errors.push(ValidationError {
                        vpns: vec![profile.vpn],
                        message: format!("{} 的「{token}」是 IPv6；目前只支援 IPv4。", profile.vpn),
                    }),
                    Err(error) => errors.push(ValidationError {
                        vpns: vec![profile.vpn],
                        message: format!(
                            "{} 的「{token}」不是有效的 CIDR、網域或網址：{error}",
                            profile.vpn
                        ),
                    }),
                },
            }
        }

        // Broader networks come first, allowing redundant child networks for
        // the same VPN to collapse into one route.
        networks.sort_by_key(|network| {
            (
                network.prefix_len(),
                u32::from(network.network()),
                u32::from(network.broadcast()),
            )
        });

        let mut minimal_networks: Vec<Ipv4Net> = Vec::new();
        for network in networks {
            let covered = minimal_networks
                .iter()
                .any(|existing| existing.contains(&network.network()));
            if !covered {
                minimal_networks.push(network);
            }
        }

        validated.push(ValidatedProfile {
            vpn: profile.vpn,
            networks: minimal_networks,
            hostnames: hostnames.into_iter().collect(),
        });
    }

    for left_index in 0..validated.len() {
        for right_index in (left_index + 1)..validated.len() {
            let left = &validated[left_index];
            let right = &validated[right_index];

            for left_network in &left.networks {
                for right_network in &right.networks {
                    let overlaps = left_network.contains(&right_network.network())
                        || right_network.contains(&left_network.network());

                    if overlaps {
                        let left_source = network_sources
                            .get(&(left.vpn, *left_network))
                            .map_or_else(|| left_network.to_string(), Clone::clone);
                        let right_source = network_sources
                            .get(&(right.vpn, *right_network))
                            .map_or_else(|| right_network.to_string(), Clone::clone);
                        errors.push(ValidationError {
                            vpns: vec![left.vpn, right.vpn],
                            message: format!(
                                "{} 的「{}」所產生的 {} 與 {} 的「{}」所產生的 {} 重疊，已阻擋套用。",
                                left.vpn,
                                left_source,
                                left_network,
                                right.vpn,
                                right_source,
                                right_network
                            ),
                        });
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(validated)
    } else {
        Err(errors)
    }
}

pub(crate) fn has_enabled_dns_targets(config: &SplitterConfig) -> bool {
    config
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
        .flat_map(|profile| target_tokens(&profile.networks))
        .any(|token| {
            token.parse::<Ipv4Net>().is_err() && matches!(target_host(token), Ok(Host::Domain(_)))
        })
}

pub(crate) fn configured_dns_hostnames(profile: &VpnProfile) -> Result<Vec<String>, String> {
    let mut hostnames = BTreeSet::new();
    for token in target_tokens(&profile.networks) {
        if token.parse::<Ipv4Net>().is_ok() {
            continue;
        }
        match target_host(token)? {
            Host::Domain(hostname) => {
                hostnames.insert(hostname);
            }
            Host::Ipv4(_) => {}
            Host::Ipv6(_) => return Err(format!("「{token}」是 IPv6；目前只支援 IPv4。")),
        }
    }
    Ok(hostnames.into_iter().collect())
}

pub(crate) fn configured_static_networks(profile: &VpnProfile) -> Result<Vec<Ipv4Net>, String> {
    let mut networks = Vec::new();
    for token in target_tokens(&profile.networks) {
        match token.parse::<Ipv4Net>() {
            Ok(network) => {
                let network = network.trunc();
                if network.prefix_len() == 0 {
                    return Err("0.0.0.0/0 不可作為分流目標".to_owned());
                }
                networks.push(network);
            }
            Err(_) => match target_host(token)? {
                Host::Ipv4(address) => {
                    networks.push(Ipv4Net::new(address, 32).expect("/32 is valid"));
                }
                Host::Domain(_) => {}
                Host::Ipv6(_) => {
                    return Err(format!("「{token}」是 IPv6；目前只支援 IPv4。"));
                }
            },
        }
    }
    Ok(networks)
}

fn target_tokens(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(|character: char| character.is_whitespace() || character == ',' || character == ';')
        .filter(|token| !token.is_empty())
}

fn add_network(
    vpn: VpnKind,
    source: &str,
    network: Ipv4Net,
    networks: &mut Vec<Ipv4Net>,
    network_sources: &mut BTreeMap<(VpnKind, Ipv4Net), String>,
) {
    network_sources
        .entry((vpn, network))
        .or_insert_with(|| source.to_owned());
    networks.push(network);
}

fn target_host(token: &str) -> Result<Host<String>, String> {
    if let Ok(address) = token.parse::<Ipv4Addr>() {
        return Ok(Host::Ipv4(address));
    }

    let url = if token.contains("://") {
        Url::parse(token)
    } else if token.contains('/') {
        return Err("網域不可包含路徑；若要輸入完整網址，請包含 http:// 或 https://".to_owned());
    } else {
        Url::parse(&format!("route://{token}"))
    }
    .map_err(|error| error.to_string())?;

    url.host()
        .map(|host| host.to_owned())
        .ok_or_else(|| "缺少目的網域或 IP".to_owned())
}

fn resolve_system_ipv4(hostname: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut addresses = (hostname, 0)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .filter_map(|address| match address {
            SocketAddr::V4(address) => Some(*address.ip()),
            SocketAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();

    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(entries: &[(VpnKind, bool, &str)]) -> SplitterConfig {
        let mut config = SplitterConfig::default();
        for (vpn, enabled, networks) in entries {
            let profile = config.profile_mut(*vpn).expect("profile exists");
            profile.enabled = *enabled;
            profile.networks = (*networks).to_owned();
        }
        config
    }

    #[test]
    fn normalizes_and_collapses_networks_for_the_same_vpn() {
        let result = validate_config(&config(&[(
            VpnKind::FortiClient,
            true,
            "10.1.2.3/8, 10.20.0.0/16\n192.168.50.0/24",
        )]))
        .expect("configuration should be valid");

        assert_eq!(
            result[0].networks,
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "192.168.50.0/24".parse().unwrap()
            ]
        );
    }

    #[test]
    fn blocks_overlap_between_enabled_vpns() {
        let errors = validate_config(&config(&[
            (VpnKind::FortiClient, true, "10.0.0.0/8"),
            (VpnKind::F5, true, "10.20.0.0/16"),
        ]))
        .expect_err("overlap must be rejected");

        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("10.0.0.0/8")
                    && error.message.contains("10.20.0.0/16"))
        );
    }

    #[test]
    fn allows_adjacent_networks() {
        let result = validate_config(&config(&[
            (VpnKind::FortiClient, true, "10.0.0.0/24"),
            (VpnKind::F5, true, "10.0.1.0/24"),
        ]));

        assert!(result.is_ok());
    }

    #[test]
    fn ignores_disabled_profiles_when_checking_overlap() {
        let result = validate_config(&config(&[
            (VpnKind::FortiClient, true, "10.0.0.0/8"),
            (VpnKind::F5, false, "10.20.0.0/16"),
        ]));

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_a_default_route() {
        let errors = validate_config(&config(&[(VpnKind::Ivanti, true, "0.0.0.0/0")]))
            .expect_err("a split-tunnel tool must reject a default route");

        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("0.0.0.0/0"))
        );
    }
}
