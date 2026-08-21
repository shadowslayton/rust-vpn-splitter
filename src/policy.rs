use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use ipnet::Ipv4Net;

use crate::{
    domain::{
        SplitterConfig, ValidatedProfile, VpnKind, configured_dns_hostnames,
        configured_static_networks, has_enabled_dns_targets, validate_config_with_resolver,
    },
    windows::{
        InternetGateway, ManagedDnsRule, ManagedRoute, ManagedRoutePurpose, NativeRoute,
        NetworkAdapter, RoutePriority, RouteTableFingerprint, apply_routes,
        existing_managed_routes,
    },
};

#[cfg(test)]
use crate::windows::resolve_ipv4_with_dns_servers;

pub(crate) const ROUTE_METRIC: u16 = 5;

const INTERNET_BYPASS_PREFIX_LENGTH: u8 = 4;

pub(crate) fn internet_bypass_networks() -> [Ipv4Net; 16] {
    std::array::from_fn(|index| {
        Ipv4Net::new(
            Ipv4Addr::from((index as u32) << (32 - INTERNET_BYPASS_PREFIX_LENGTH)),
            INTERNET_BYPASS_PREFIX_LENGTH,
        )
        .expect("generated IPv4 coverage prefix is valid")
    })
}

#[derive(Debug, Default)]
pub(crate) struct PreparedRoutes {
    pub(crate) routes: Vec<ManagedRoute>,
    pub(crate) dns_rules: Vec<ManagedDnsRule>,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProfileDnsPlan {
    vpn: VpnKind,
    adapter_index: u32,
    next_hop: String,
    hostnames: Vec<String>,
    servers: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, Default)]
struct DnsPlan {
    fallback_servers: Vec<Ipv4Addr>,
    profiles: BTreeMap<VpnKind, ProfileDnsPlan>,
}

impl DnsPlan {
    fn build(
        config: &SplitterConfig,
        adapters: &[NetworkAdapter],
        fallback: Option<InternetFallback<'_>>,
        manage_dns: bool,
    ) -> Result<Self, Vec<String>> {
        if !manage_dns {
            return Ok(Self::default());
        }
        let Some(fallback) = fallback else {
            return Err(vec![
                "找不到可接手未指定名稱的原生 VPN 或一般網路，已停止套用。".to_owned(),
            ]);
        };
        let mut fallback_servers = fallback_dns_servers(fallback, adapters)?;
        let fallback_set = fallback_servers.iter().copied().collect::<BTreeSet<_>>();
        let mut hostname_owners = BTreeMap::new();
        let mut raw_profiles = Vec::new();

        for profile in config.profiles.iter().filter(|profile| profile.enabled) {
            let adapter = selected_adapter_for_profile(config, profile.vpn, adapters)?;
            let hostnames = configured_dns_hostnames(profile)
                .map_err(|error| vec![format!("{} 的 DNS 目標無效：{error}", profile.vpn)])?;
            for hostname in &hostnames {
                if let Some(existing_vpn) = hostname_owners.insert(hostname.clone(), profile.vpn)
                    && existing_vpn != profile.vpn
                {
                    return Err(vec![format!(
                        "網域 {hostname} 同時指定給 {existing_vpn} 與 {}；同一名稱只能使用一組 VPN DNS。",
                        profile.vpn
                    )]);
                }
            }

            raw_profiles.push((
                profile.vpn,
                adapter,
                hostnames,
                normalized_ipv4_addresses(&adapter.dns_servers)
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            ));
        }

        let mut profiles = BTreeMap::new();
        let mut server_owners = BTreeMap::new();
        let mut fallback_removals = BTreeSet::new();
        for (vpn, adapter, hostnames, reported_servers) in raw_profiles {
            if matches!(fallback, InternetFallback::Vpn { .. })
                && !reported_servers.is_empty()
                && reported_servers == fallback_set
            {
                return Err(vec![format!(
                    "{} 與 {} 回報相同、無法分辨歸屬的 IPv4 DNS server；為避免未指定名稱誤用已啟用分流 VPN 的 DNS，已停止套用。",
                    vpn,
                    fallback.label()
                )]);
            }
            let servers = if matches!(fallback, InternetFallback::Vpn { .. })
                && reported_servers.is_subset(&fallback_set)
                && reported_servers != fallback_set
            {
                fallback_removals.extend(reported_servers.iter().copied());
                reported_servers.iter().copied().collect::<Vec<_>>()
            } else {
                reported_servers
                    .difference(&fallback_set)
                    .copied()
                    .collect::<Vec<_>>()
            };
            if !hostnames.is_empty() && servers.is_empty() {
                return Err(vec![format!(
                    "{} 的介面「{}」沒有可與未指定流量路徑分離的 IPv4 DNS server；為避免 DNS 串線，已停止套用。",
                    vpn, adapter.description
                )]);
            }
            for server in &servers {
                if let Some(existing_vpn) = server_owners.insert(*server, vpn)
                    && existing_vpn != vpn
                {
                    return Err(vec![format!(
                        "{existing_vpn} 與 {} 的網路介面都宣告 DNS server {server}；Windows 無法把同一目的 IP 同時固定到兩條 VPN，已停止套用以避免 DNS 串線。",
                        vpn
                    )]);
                }
            }
            if !hostnames.is_empty() {
                profiles.insert(
                    vpn,
                    ProfileDnsPlan {
                        vpn,
                        adapter_index: adapter.index,
                        next_hop: adapter.next_hop.clone(),
                        hostnames,
                        servers,
                    },
                );
            }
        }

        fallback_servers.retain(|server| !fallback_removals.contains(server));
        if fallback_servers.is_empty() {
            return Err(vec![
                "接手未指定流量的網路介面只回報了啟用中 VPN 的 DNS server；無法安全分辨 DNS 歸屬，已停止套用。"
                    .to_owned(),
            ]);
        }

        Ok(Self {
            fallback_servers,
            profiles,
        })
    }

    fn server_strings(&self, vpn: VpnKind) -> Result<Vec<String>, String> {
        self.profiles
            .get(&vpn)
            .map(|profile| profile.servers.iter().map(ToString::to_string).collect())
            .ok_or_else(|| format!("找不到 {vpn} 的 DNS 規劃。"))
    }

    fn bootstrap_routes(&self) -> Vec<ManagedRoute> {
        self.profiles
            .values()
            .flat_map(|profile| {
                profile.servers.iter().map(|server| ManagedRoute {
                    vpn: profile.vpn,
                    purpose: ManagedRoutePurpose::VpnDnsServer,
                    prefix: Ipv4Net::new(*server, 32).expect("/32 is valid").to_string(),
                    interface_index: profile.adapter_index,
                    next_hop: profile.next_hop.clone(),
                    route_metric: ROUTE_METRIC,
                })
            })
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct AppliedPolicy {
    pub(crate) prepared: PreparedRoutes,
    pub(crate) changed: bool,
}

#[derive(Debug)]
struct RouteHealthPlan {
    config: SplitterConfig,
    routes: Vec<ManagedRoute>,
    dns_rules: Vec<ManagedDnsRule>,
    disabled_vpns: Vec<VpnKind>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ReconciledRoutes {
    pub(crate) routes: Vec<ManagedRoute>,
    pub(crate) removed: usize,
}

pub(crate) struct NetworkSnapshot {
    pub(crate) adapters: Vec<NetworkAdapter>,
    pub(crate) internet_gateway: Option<InternetGateway>,
    pub(crate) native_routes: Vec<NativeRoute>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum InternetFallback<'a> {
    Physical(&'a InternetGateway),
    Vpn {
        vpn: VpnKind,
        adapter: &'a NetworkAdapter,
    },
}

impl<'a> InternetFallback<'a> {
    pub(crate) fn interface_index(self) -> u32 {
        match self {
            Self::Physical(gateway) => gateway.interface_index,
            Self::Vpn { adapter, .. } => adapter.index,
        }
    }

    pub(crate) fn next_hop(self) -> &'a str {
        match self {
            Self::Physical(gateway) => &gateway.next_hop,
            Self::Vpn { adapter, .. } => &adapter.next_hop,
        }
    }

    pub(crate) fn priority(self) -> Option<RoutePriority> {
        match self {
            Self::Physical(gateway) => gateway.route_priority,
            Self::Vpn { adapter, .. } => adapter.full_tunnel_priority,
        }
    }

    pub(crate) fn label(self) -> String {
        match self {
            Self::Physical(gateway) => gateway.interface_alias.clone(),
            Self::Vpn { vpn, adapter } => format!("未啟用分流的 {vpn}（{}）", adapter.name),
        }
    }

    pub(crate) fn inferred_from_escape_route(self) -> bool {
        matches!(self, Self::Physical(gateway) if gateway.inferred_from_escape_route)
    }
}

pub(crate) struct PolicyTransactionInput<'a> {
    pub(crate) managed_routes: &'a [ManagedRoute],
    pub(crate) active_routes: &'a [ManagedRoute],
    pub(crate) config: &'a SplitterConfig,
    pub(crate) adapters: &'a [NetworkAdapter],
    pub(crate) internet_gateway: Option<&'a InternetGateway>,
}

pub(crate) struct RouteHealthInput {
    pub(crate) current_routes: Vec<ManagedRoute>,
    pub(crate) config: SplitterConfig,
    pub(crate) existing_routes: Vec<ManagedRoute>,
    pub(crate) adapters: Vec<NetworkAdapter>,
    pub(crate) internet_gateway: Option<InternetGateway>,
    pub(crate) native_routes: Vec<NativeRoute>,
}

#[derive(Debug, Clone)]
pub(crate) enum RouteHealthOutcome {
    Healthy,
    Updated {
        config: SplitterConfig,
        routes: Vec<ManagedRoute>,
        adapters: Vec<NetworkAdapter>,
        internet_gateway: Option<Box<InternetGateway>>,
        repaired: bool,
        disabled_vpns: Vec<VpnKind>,
        warnings: Vec<String>,
    },
    Failed(String),
}

#[cfg(test)]
pub(crate) fn replace_vpn_routes(
    current: &[ManagedRoute],
    vpn: VpnKind,
    replacement: Vec<ManagedRoute>,
) -> Vec<ManagedRoute> {
    current
        .iter()
        .filter(|route| route.vpn != vpn)
        .cloned()
        .chain(replacement)
        .collect()
}

pub(crate) fn routes_match(left: &[ManagedRoute], right: &[ManagedRoute]) -> bool {
    left.len() == right.len() && left.iter().all(|route| right.contains(route))
}

pub(crate) fn needs_periodic_route_refresh(config: &SplitterConfig) -> bool {
    config.profiles.iter().any(|profile| profile.enabled)
}

pub(crate) fn should_schedule_dns_refresh(config: &SplitterConfig) -> bool {
    has_enabled_dns_targets(config)
}

pub(crate) fn discard_incomplete_vpn_route_sets(
    previous: &[ManagedRoute],
    existing: &[ManagedRoute],
) -> Vec<ManagedRoute> {
    existing
        .iter()
        .filter(|route| {
            let previous_count = previous
                .iter()
                .filter(|candidate| candidate.vpn == route.vpn)
                .count();
            let existing_count = existing
                .iter()
                .filter(|candidate| candidate.vpn == route.vpn)
                .count();
            previous_count == existing_count
        })
        .cloned()
        .collect()
}

pub(crate) fn reconciled_routes_for_config(
    previous: &[ManagedRoute],
    existing: &[ManagedRoute],
    config: &SplitterConfig,
) -> Vec<ManagedRoute> {
    discard_incomplete_vpn_route_sets(previous, existing)
        .into_iter()
        .filter(|route| {
            config
                .profile(route.vpn)
                .is_some_and(|profile| profile.enabled)
        })
        .collect()
}

pub(crate) fn reconcile_routes(
    previous: Vec<ManagedRoute>,
    config: SplitterConfig,
) -> Result<ReconciledRoutes, String> {
    let previous_count = previous.len();
    let existing = existing_managed_routes(&previous)?;
    let reconciled = reconciled_routes_for_config(&previous, &existing, &config);

    if !routes_match(&existing, &reconciled) {
        apply_routes(&existing, &reconciled)?;
    }

    Ok(ReconciledRoutes {
        removed: previous_count.saturating_sub(reconciled.len()),
        routes: reconciled,
    })
}

#[cfg(test)]
pub(crate) fn prepare_profile_routes_for(
    config: &SplitterConfig,
    vpn: VpnKind,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
) -> Result<PreparedRoutes, Vec<String>> {
    let mut prepared = prepare_all_enabled_routes_for(config, adapters, internet_gateway)?;
    prepared.routes.retain(|route| route.vpn == vpn);
    Ok(prepared)
}

#[cfg(test)]
pub(crate) fn prepare_all_enabled_routes_for(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
) -> Result<PreparedRoutes, Vec<String>> {
    prepare_all_enabled_routes_with_resolver(
        config,
        adapters,
        internet_gateway,
        |_, hostname, servers| resolve_ipv4_with_dns_servers(hostname, servers),
    )
}

#[cfg(test)]
pub(crate) fn prepare_all_enabled_routes_with_resolver(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
    resolve_hostname: impl FnMut(VpnKind, &str, &[String]) -> Result<Vec<Ipv4Addr>, String>,
) -> Result<PreparedRoutes, Vec<String>> {
    prepare_all_enabled_routes_with_context(
        config,
        adapters,
        internet_gateway,
        &[],
        &[],
        resolve_hostname,
    )
}

#[cfg(test)]
fn prepare_all_enabled_routes_with_context(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
    native_routes: &[NativeRoute],
    managed_routes: &[ManagedRoute],
    resolve_hostname: impl FnMut(VpnKind, &str, &[String]) -> Result<Vec<Ipv4Addr>, String>,
) -> Result<PreparedRoutes, Vec<String>> {
    if !config.profiles.iter().any(|profile| profile.enabled) {
        return Ok(PreparedRoutes::default());
    }

    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        selected_adapter_for_profile(config, profile.vpn, adapters)?;
    }

    let full_tunnel_vpns = enabled_full_tunnel_vpns(config, adapters);
    let fallback = select_internet_fallback(config, adapters, internet_gateway);
    let manage_dns = should_manage_dns_policy(config, &full_tunnel_vpns, fallback);
    let dns_plan = DnsPlan::build(config, adapters, fallback, manage_dns)?;
    prepare_enabled_routes_from_dns_plan(
        config,
        adapters,
        native_routes,
        managed_routes,
        &full_tunnel_vpns,
        fallback,
        manage_dns,
        &dns_plan,
        resolve_hostname,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_enabled_routes_from_dns_plan(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    native_routes: &[NativeRoute],
    managed_routes: &[ManagedRoute],
    full_tunnel_vpns: &[VpnKind],
    fallback: Option<InternetFallback<'_>>,
    manage_dns: bool,
    dns_plan: &DnsPlan,
    mut resolve_hostname: impl FnMut(VpnKind, &str, &[String]) -> Result<Vec<Ipv4Addr>, String>,
) -> Result<PreparedRoutes, Vec<String>> {
    let validated = validate_config_with_resolver(config, |vpn, hostname| {
        let vpn_dns = dns_plan.server_strings(vpn)?;
        resolve_hostname(vpn, hostname, &vpn_dns)
    })
    .map_err(|errors| {
        errors
            .into_iter()
            .map(|error| error.message)
            .collect::<Vec<_>>()
    })?;
    let mut prepared = PreparedRoutes::default();

    for profile in &validated {
        prepared
            .routes
            .extend(prepare_validated_profile_routes(config, profile, adapters)?);
    }

    append_internet_bypass_routes(
        &mut prepared,
        config,
        adapters,
        full_tunnel_vpns,
        fallback,
        native_routes,
        managed_routes,
    )?;
    if manage_dns {
        append_dns_policy(
            &mut prepared,
            fallback.expect("managed DNS requires a fallback path"),
            dns_plan,
        )?;
    }

    Ok(prepared)
}

fn selected_adapter_for_profile<'a>(
    config: &SplitterConfig,
    vpn: VpnKind,
    adapters: &'a [NetworkAdapter],
) -> Result<&'a NetworkAdapter, Vec<String>> {
    let profile = config
        .profile(vpn)
        .expect("selected VPN profiles originate from config");
    let Some(description) = profile.adapter_description.as_ref() else {
        return Err(vec![format!(
            "{} 已啟用，但尚未選擇 VPN 網路介面。",
            profile.vpn
        )]);
    };
    let Some(adapter) = adapters
        .iter()
        .find(|adapter| adapter.matches(profile.vpn) && &adapter.description == description)
    else {
        return Err(vec![format!(
            "{} 找不到已選擇的介面「{}」，請重新偵測。",
            profile.vpn, description
        )]);
    };

    if !adapter.is_up() {
        return Err(vec![format!(
            "{} 的介面「{}」尚未連線。",
            profile.vpn, adapter.description
        )]);
    }

    Ok(adapter)
}

fn normalized_ipv4_addresses(servers: &[String]) -> Vec<Ipv4Addr> {
    let mut seen = BTreeSet::new();
    servers
        .iter()
        .filter_map(|server| server.parse::<Ipv4Addr>().ok())
        .filter(|server| seen.insert(*server))
        .collect()
}

fn validate_dns_route_target_conflicts(
    config: &SplitterConfig,
    dns_plan: &DnsPlan,
) -> Result<(), Vec<String>> {
    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let networks = configured_static_networks(profile)
            .map_err(|error| vec![format!("{} 的目標無效：{error}", profile.vpn)])?;
        for dns_profile in dns_plan
            .profiles
            .values()
            .filter(|dns_profile| dns_profile.vpn != profile.vpn)
        {
            for address in &dns_profile.servers {
                if let Some(network) = networks.iter().find(|network| network.contains(address)) {
                    return Err(vec![format!(
                        "{} 的 DNS server {address} 被 {} 的目標「{network}」涵蓋，無法同時建立正確 DNS 路由。",
                        dns_profile.vpn, profile.vpn
                    )]);
                }
            }
        }
    }
    Ok(())
}

fn routes_with_dns_bootstrap(
    current_routes: &[ManagedRoute],
    dns_routes: Vec<ManagedRoute>,
) -> Vec<ManagedRoute> {
    let mut staged = current_routes.to_vec();
    for dns_route in dns_routes {
        if staged.contains(&dns_route) {
            continue;
        }
        staged.retain(|route| route.prefix != dns_route.prefix);
        staged.push(dns_route);
    }
    staged
}

fn routes_for_policy_transition(
    staged_routes: &[ManagedRoute],
    final_routes: &[ManagedRoute],
) -> Vec<ManagedRoute> {
    let mut transition = final_routes.to_vec();
    for route in staged_routes
        .iter()
        .filter(|route| route.purpose == ManagedRoutePurpose::VpnDnsServer)
    {
        if transition
            .iter()
            .any(|candidate| candidate.prefix == route.prefix)
        {
            continue;
        }
        transition.push(route.clone());
    }
    transition
}

fn rollback_policy_routes(
    active_routes: &[ManagedRoute],
    original_routes: &[ManagedRoute],
    replace_routes: &mut impl FnMut(&[ManagedRoute], &[ManagedRoute]) -> Result<(), String>,
    error: String,
) -> String {
    if routes_match(active_routes, original_routes) {
        return error;
    }
    match replace_routes(active_routes, original_routes) {
        Ok(()) => format!("{error}\n已將 IPv4 路由回復到套用前狀態。"),
        Err(rollback_error) => {
            format!("{error}\nIPv4 路由回復也失敗：{rollback_error}")
        }
    }
}

#[cfg(test)]
pub(crate) fn apply_policy_transaction_with(
    input: PolicyTransactionInput<'_>,
    resolve_hostname: impl FnMut(VpnKind, &str, &[String]) -> Result<Vec<Ipv4Addr>, String>,
    replace_routes: impl FnMut(&[ManagedRoute], &[ManagedRoute]) -> Result<(), String>,
    replace_dns_policy: impl FnMut(&[ManagedDnsRule]) -> Result<bool, String>,
) -> Result<AppliedPolicy, String> {
    apply_policy_transaction_with_native_routes(
        input,
        &[],
        resolve_hostname,
        replace_routes,
        replace_dns_policy,
    )
}

pub(crate) fn apply_policy_transaction_with_native_routes(
    input: PolicyTransactionInput<'_>,
    native_routes: &[NativeRoute],
    mut resolve_hostname: impl FnMut(VpnKind, &str, &[String]) -> Result<Vec<Ipv4Addr>, String>,
    mut replace_routes: impl FnMut(&[ManagedRoute], &[ManagedRoute]) -> Result<(), String>,
    mut replace_dns_policy: impl FnMut(&[ManagedDnsRule]) -> Result<bool, String>,
) -> Result<AppliedPolicy, String> {
    let PolicyTransactionInput {
        managed_routes,
        active_routes,
        config,
        adapters,
        internet_gateway,
    } = input;
    let full_tunnel_vpns = enabled_full_tunnel_vpns(config, adapters);
    let fallback = select_internet_fallback(config, adapters, internet_gateway);
    let manage_dns = should_manage_dns_policy(config, &full_tunnel_vpns, fallback);
    let dns_plan = DnsPlan::build(config, adapters, fallback, manage_dns)
        .map_err(|errors| errors.join("\n"))?;
    validate_dns_route_target_conflicts(config, &dns_plan).map_err(|errors| errors.join("\n"))?;
    let bootstrap_routes = dns_plan.bootstrap_routes();
    let staged_routes = routes_with_dns_bootstrap(managed_routes, bootstrap_routes);
    let bootstrap_changed = !routes_match(active_routes, &staged_routes);
    if bootstrap_changed {
        replace_routes(active_routes, &staged_routes)?;
    }

    let mut prepared = match prepare_enabled_routes_from_dns_plan(
        config,
        adapters,
        native_routes,
        managed_routes,
        &full_tunnel_vpns,
        fallback,
        manage_dns,
        &dns_plan,
        &mut resolve_hostname,
    ) {
        Ok(prepared) => prepared,
        Err(errors) => {
            return Err(rollback_policy_routes(
                &staged_routes,
                active_routes,
                &mut replace_routes,
                errors.join("\n"),
            ));
        }
    };

    let transition_routes = routes_for_policy_transition(&staged_routes, &prepared.routes);
    let transition_changed = !routes_match(&staged_routes, &transition_routes);
    if transition_changed && let Err(error) = replace_routes(&staged_routes, &transition_routes) {
        return Err(rollback_policy_routes(
            &staged_routes,
            active_routes,
            &mut replace_routes,
            error,
        ));
    }

    let dns_changed = match replace_dns_policy(&prepared.dns_rules) {
        Ok(changed) => changed,
        Err(error) => {
            return Err(rollback_policy_routes(
                &transition_routes,
                active_routes,
                &mut replace_routes,
                error,
            ));
        }
    };

    let cleanup_changed = !routes_match(&transition_routes, &prepared.routes);
    if cleanup_changed && let Err(error) = replace_routes(&transition_routes, &prepared.routes) {
        prepared.warnings.push(format!(
            "DNS 分流已更新，但舊路由暫時無法清除；健康檢查將自動重試：{error}"
        ));
        prepared.routes = transition_routes;
    }

    Ok(AppliedPolicy {
        prepared,
        changed: bootstrap_changed || transition_changed || cleanup_changed || dns_changed,
    })
}

fn adapter_vpn_kind(adapter: &NetworkAdapter) -> Option<VpnKind> {
    VpnKind::ALL.into_iter().find(|vpn| adapter.matches(*vpn))
}

fn fallback_is_preferred(candidate: InternetFallback<'_>, current: InternetFallback<'_>) -> bool {
    match (candidate.priority(), current.priority()) {
        (Some(candidate_priority), Some(current_priority)) => {
            candidate_priority.prefix_length > current_priority.prefix_length
                || (candidate_priority.prefix_length == current_priority.prefix_length
                    && (candidate_priority.effective_metric < current_priority.effective_metric
                        || (candidate_priority.effective_metric
                            == current_priority.effective_metric
                            && candidate.interface_index() < current.interface_index())))
        }
        (Some(_), None) => true,
        (None, Some(_)) | (None, None) => false,
    }
}

pub(crate) fn select_internet_fallback<'a>(
    config: &SplitterConfig,
    adapters: &'a [NetworkAdapter],
    internet_gateway: Option<&'a InternetGateway>,
) -> Option<InternetFallback<'a>> {
    let mut selected = internet_gateway.map(InternetFallback::Physical);

    for adapter in adapters
        .iter()
        .filter(|adapter| adapter.is_up() && adapter.full_tunnel_priority.is_some())
    {
        let Some(vpn) = adapter_vpn_kind(adapter) else {
            continue;
        };
        if config.profile(vpn).is_some_and(|profile| profile.enabled) {
            continue;
        }

        let candidate = InternetFallback::Vpn { vpn, adapter };
        if selected.is_none_or(|current| fallback_is_preferred(candidate, current)) {
            selected = Some(candidate);
        }
    }

    selected
}

pub(crate) fn fallback_dns_servers(
    fallback: InternetFallback<'_>,
    adapters: &[NetworkAdapter],
) -> Result<Vec<Ipv4Addr>, Vec<String>> {
    match fallback {
        InternetFallback::Physical(gateway) => current_network_dns_servers(adapters, gateway),
        InternetFallback::Vpn { vpn, adapter } => {
            let servers = normalized_ipv4_addresses(&adapter.dns_servers);
            if servers.is_empty() {
                return Err(vec![format!(
                    "{vpn} 已連線且其原生通道應處理未指定流量，但介面「{}」沒有可辨識的 IPv4 DNS server；為避免改變未啟用分流時的 DNS 行為，已停止套用。",
                    adapter.description
                )]);
            }
            Ok(servers)
        }
    }
}

fn current_network_dns_servers(
    adapters: &[NetworkAdapter],
    gateway: &InternetGateway,
) -> Result<Vec<Ipv4Addr>, Vec<String>> {
    let vpn_dns = adapters
        .iter()
        .filter(|adapter| adapter.is_up())
        .flat_map(|adapter| normalized_ipv4_addresses(&adapter.dns_servers))
        .collect::<BTreeSet<_>>();
    let active_physical_dns = normalized_ipv4_addresses(&gateway.dns_servers)
        .into_iter()
        .filter(|server| !vpn_dns.contains(server))
        .collect::<Vec<_>>();
    let physical_dns = if active_physical_dns.is_empty() {
        normalized_ipv4_addresses(&gateway.fallback_dns_servers)
            .into_iter()
            .filter(|server| !vpn_dns.contains(server))
            .collect::<Vec<_>>()
    } else {
        active_physical_dns
    };

    if physical_dns.is_empty() {
        return Err(vec![format!(
            "{} 沒有可辨識的一般網路 IPv4 DNS server；為避免讓未指定服務繼續使用 VPN DNS，已停止啟用分流。",
            gateway.interface_alias
        )]);
    }

    Ok(physical_dns)
}

fn append_dns_policy(
    prepared: &mut PreparedRoutes,
    fallback: InternetFallback<'_>,
    dns_plan: &DnsPlan,
) -> Result<(), Vec<String>> {
    prepared.dns_rules.push(ManagedDnsRule {
        vpn: None,
        namespaces: vec![".".to_owned()],
        name_servers: dns_plan
            .fallback_servers
            .iter()
            .map(ToString::to_string)
            .collect(),
    });

    for address in &dns_plan.fallback_servers {
        if let Some(route) = prepared.routes.iter().find(|route| {
            route.purpose == ManagedRoutePurpose::Target
                && route
                    .prefix
                    .parse::<ipnet::Ipv4Net>()
                    .is_ok_and(|network| network.contains(address))
        }) {
            return Err(vec![format!(
                "未指定名稱所使用的 {} DNS {address} 被 {} 的目標「{}」涵蓋；這會改變未啟用分流時的 DNS 行為，已停止套用。",
                fallback.label(),
                route.vpn,
                route.prefix
            )]);
        }
    }

    for profile in dns_plan.profiles.values() {
        prepared.dns_rules.push(ManagedDnsRule {
            vpn: Some(profile.vpn),
            namespaces: profile.hostnames.clone(),
            name_servers: profile.servers.iter().map(ToString::to_string).collect(),
        });

        for address in &profile.servers {
            if let Some(route) = prepared.routes.iter().find(|route| {
                route.vpn != profile.vpn
                    && route.purpose == ManagedRoutePurpose::Target
                    && route
                        .prefix
                        .parse::<ipnet::Ipv4Net>()
                        .is_ok_and(|network| network.contains(address))
            }) {
                return Err(vec![format!(
                    "{} 的 DNS server {address} 被 {} 的目標「{}」涵蓋，無法同時建立正確 DNS 路由。",
                    profile.vpn, route.vpn, route.prefix
                )]);
            }

            let covered_by_own_target = prepared.routes.iter().any(|route| {
                route.vpn == profile.vpn
                    && route.purpose == ManagedRoutePurpose::Target
                    && route
                        .prefix
                        .parse::<ipnet::Ipv4Net>()
                        .is_ok_and(|network| network.contains(address))
            });
            if covered_by_own_target {
                continue;
            }

            let prefix = Ipv4Net::new(*address, 32)
                .expect("/32 is valid")
                .to_string();
            if let Some(existing) = prepared.routes.iter().find(|route| {
                route.purpose == ManagedRoutePurpose::VpnDnsServer && route.prefix == prefix
            }) {
                return Err(vec![format!(
                    "{} 與 {} 使用同一個 VPN DNS server {address}，但 Windows 只能選擇一條介面路由。",
                    existing.vpn, profile.vpn
                )]);
            }
            prepared.routes.push(ManagedRoute {
                vpn: profile.vpn,
                purpose: ManagedRoutePurpose::VpnDnsServer,
                prefix,
                interface_index: profile.adapter_index,
                next_hop: profile.next_hop.clone(),
                route_metric: ROUTE_METRIC,
            });
        }
    }

    Ok(())
}

pub(crate) fn enabled_full_tunnel_vpns(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
) -> Vec<VpnKind> {
    config
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
        .filter_map(|profile| {
            let description = profile.adapter_description.as_ref()?;
            adapters
                .iter()
                .find(|adapter| {
                    adapter.matches(profile.vpn)
                        && &adapter.description == description
                        && adapter.is_up()
                        && adapter.full_tunnel_priority.is_some()
                })
                .map(|_| profile.vpn)
        })
        .collect()
}

fn should_manage_dns_policy(
    config: &SplitterConfig,
    full_tunnel_vpns: &[VpnKind],
    fallback: Option<InternetFallback<'_>>,
) -> bool {
    !full_tunnel_vpns.is_empty()
        || has_enabled_dns_targets(config)
        || matches!(fallback, Some(InternetFallback::Vpn { .. }))
}

pub(crate) fn internet_bypass_routes_are_required(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    full_tunnel_vpns: &[VpnKind],
    fallback: InternetFallback<'_>,
) -> bool {
    full_tunnel_vpns.iter().any(|vpn| {
        let Some(adapter) = config
            .profile(*vpn)
            .and_then(|profile| profile.adapter_description.as_ref())
            .and_then(|description| {
                adapters.iter().find(|adapter| {
                    adapter.matches(*vpn)
                        && &adapter.description == description
                        && adapter.is_up()
                        && adapter.full_tunnel_priority.is_some()
                })
            })
        else {
            return true;
        };
        let enabled_tunnel = InternetFallback::Vpn { vpn: *vpn, adapter };
        !fallback_is_preferred(fallback, enabled_tunnel)
    })
}

fn append_internet_bypass_routes(
    prepared: &mut PreparedRoutes,
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    full_tunnel_vpns: &[VpnKind],
    fallback: Option<InternetFallback<'_>>,
    native_routes: &[NativeRoute],
    managed_routes: &[ManagedRoute],
) -> Result<(), Vec<String>> {
    let Some(&owner) = full_tunnel_vpns.first() else {
        return Ok(());
    };
    let names = full_tunnel_vpns
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、");
    let tunnel_state = if full_tunnel_vpns.len() == 1 {
        format!("{names} 是")
    } else {
        format!("{names} 同時是")
    };
    let Some(fallback) = fallback else {
        return Err(vec![format!(
            "{tunnel_state} Full Tunnel，但找不到可接手未指定流量的原生 VPN 或一般網路；為避免套用後仍無法連線，已停止。請按「重新偵測 VPN」後再試。"
        )]);
    };

    let source = if fallback.inferred_from_escape_route() {
        "（由 VPN 保留的伺服器繞行路由推定）"
    } else {
        ""
    };
    if internet_bypass_routes_are_required(config, adapters, full_tunnel_vpns, fallback) {
        let enabled_interface_indexes = config
            .profiles
            .iter()
            .filter(|profile| profile.enabled)
            .filter_map(|profile| {
                let description = profile.adapter_description.as_ref()?;
                adapters
                    .iter()
                    .find(|adapter| {
                        adapter.matches(profile.vpn)
                            && &adapter.description == description
                            && adapter.is_up()
                    })
                    .map(|adapter| adapter.index)
            })
            .collect::<BTreeSet<_>>();
        let native_routes = native_routes
            .iter()
            .filter(|route| !enabled_interface_indexes.contains(&route.interface_index))
            .filter(|route| {
                !managed_routes.iter().any(|managed| {
                    managed.prefix.parse::<Ipv4Net>().ok() == Some(route.prefix)
                        && managed.interface_index == route.interface_index
                        && managed.next_hop == route.next_hop
                        && u32::from(managed.route_metric) == route.route_metric
                })
            })
            .collect::<Vec<_>>();

        prepared
            .routes
            .extend(internet_bypass_networks().into_iter().map(|network| {
                let native = native_routes
                    .iter()
                    .copied()
                    .filter(|route| route.prefix.contains(&network.network()))
                    .min_by_key(|route| {
                        (
                            Reverse(route.prefix.prefix_len()),
                            route.effective_metric(),
                            route.interface_index,
                            route.next_hop.as_str(),
                        )
                    });
                let (interface_index, next_hop) = native
                    .map(|route| (route.interface_index, route.next_hop.clone()))
                    .unwrap_or_else(|| {
                        (fallback.interface_index(), fallback.next_hop().to_owned())
                    });
                ManagedRoute {
                    vpn: owner,
                    purpose: ManagedRoutePurpose::InternetBypass,
                    prefix: network.to_string(),
                    interface_index,
                    next_hop,
                    route_metric: ROUTE_METRIC,
                }
            }));
        prepared.warnings.push(format!(
            "{tunnel_state} Full Tunnel；非指定 IPv4 流量會逐段保留其他已連線 VPN 或一般網路的 Windows 原生選路{}。若 VPN 公司策略強制封鎖繞行，連線仍可能受限。",
            source
        ));
    } else {
        prepared.warnings.push(format!(
            "{tunnel_state} Full Tunnel；{} 的原生路由已優先處理非指定 IPv4 流量，本程式不會建立重複的全網路 fallback 路由。",
            fallback.label()
        ));
    }

    Ok(())
}

fn prepare_validated_profile_routes(
    config: &SplitterConfig,
    validated_profile: &ValidatedProfile,
    adapters: &[NetworkAdapter],
) -> Result<Vec<ManagedRoute>, Vec<String>> {
    let profile = config
        .profile(validated_profile.vpn)
        .expect("validated profiles originate from config");
    let adapter = selected_adapter_for_profile(config, profile.vpn, adapters)?;

    Ok(validated_profile
        .networks
        .iter()
        .map(|network| ManagedRoute {
            vpn: profile.vpn,
            purpose: ManagedRoutePurpose::Target,
            prefix: network.to_string(),
            interface_index: adapter.index,
            next_hop: adapter.next_hop.clone(),
            route_metric: ROUTE_METRIC,
        })
        .collect())
}

fn desired_routes_for_health_check_with_native_routes(
    current_routes: &[ManagedRoute],
    mut config: SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
    native_routes: &[NativeRoute],
) -> Result<RouteHealthPlan, String> {
    let mut desired_routes = Vec::new();
    let mut disabled_vpns = Vec::new();
    let mut warnings = Vec::new();
    let mut full_tunnel_vpns = Vec::new();

    for vpn in VpnKind::ALL {
        let Some(profile) = config.profile(vpn) else {
            continue;
        };
        if !profile.enabled {
            continue;
        }

        let selected_description = profile.adapter_description.clone();
        let adapter = selected_description.as_ref().and_then(|description| {
            adapters.iter().find(|adapter| {
                adapter.matches(vpn) && &adapter.description == description && adapter.is_up()
            })
        });
        let target_routes = current_routes
            .iter()
            .filter(|route| route.vpn == vpn && route.purpose == ManagedRoutePurpose::Target)
            .cloned()
            .collect::<Vec<_>>();

        let Some(adapter) = adapter else {
            if let Some(profile) = config.profile_mut(vpn) {
                profile.enabled = false;
            }
            disabled_vpns.push(vpn);
            warnings.push(format!(
                "{vpn} 已斷線或原介面已不存在；已移除其殘留路由並關閉分流。"
            ));
            continue;
        };

        if target_routes.is_empty() {
            if let Some(profile) = config.profile_mut(vpn) {
                profile.enabled = false;
            }
            disabled_vpns.push(vpn);
            warnings.push(format!(
                "{vpn} 的管理路由清單不完整；已清除殘留路由並關閉分流，請重新啟用。"
            ));
            continue;
        }

        desired_routes.extend(target_routes.into_iter().map(|mut route| {
            route.interface_index = adapter.index;
            route.next_hop = adapter.next_hop.clone();
            route
        }));

        if adapter.full_tunnel_priority.is_some() {
            full_tunnel_vpns.push(vpn);
        }
    }

    let mut prepared = PreparedRoutes {
        routes: desired_routes,
        dns_rules: Vec::new(),
        warnings,
    };
    let fallback = select_internet_fallback(&config, adapters, internet_gateway);
    let manage_dns = should_manage_dns_policy(&config, &full_tunnel_vpns, fallback);
    let dns_plan = DnsPlan::build(&config, adapters, fallback, manage_dns)
        .map_err(|errors| errors.join("\n"))?;
    append_internet_bypass_routes(
        &mut prepared,
        &config,
        adapters,
        &full_tunnel_vpns,
        fallback,
        native_routes,
        current_routes,
    )
    .map_err(|errors| errors.join("\n"))?;
    if manage_dns {
        append_dns_policy(
            &mut prepared,
            fallback.expect("managed DNS requires a fallback path"),
            &dns_plan,
        )
        .map_err(|errors| errors.join("\n"))?;
    }

    Ok(RouteHealthPlan {
        config,
        routes: prepared.routes,
        dns_rules: prepared.dns_rules,
        disabled_vpns,
        warnings: prepared.warnings,
    })
}

#[cfg(test)]
pub(crate) fn evaluate_route_health_with(
    current_routes: Vec<ManagedRoute>,
    config: SplitterConfig,
    existing_routes: Vec<ManagedRoute>,
    adapters: Vec<NetworkAdapter>,
    internet_gateway: Option<InternetGateway>,
    apply: impl FnMut(&[ManagedRoute], &[ManagedRoute]) -> Result<(), String>,
    apply_dns: impl FnMut(&[ManagedDnsRule]) -> Result<bool, String>,
) -> RouteHealthOutcome {
    evaluate_route_health_with_native_routes(
        RouteHealthInput {
            current_routes,
            config,
            existing_routes,
            adapters,
            internet_gateway,
            native_routes: Vec::new(),
        },
        apply,
        apply_dns,
    )
}

pub(crate) fn evaluate_route_health_with_native_routes(
    input: RouteHealthInput,
    mut apply: impl FnMut(&[ManagedRoute], &[ManagedRoute]) -> Result<(), String>,
    mut apply_dns: impl FnMut(&[ManagedDnsRule]) -> Result<bool, String>,
) -> RouteHealthOutcome {
    let RouteHealthInput {
        current_routes,
        config,
        existing_routes,
        adapters,
        internet_gateway,
        native_routes,
    } = input;
    let plan = match desired_routes_for_health_check_with_native_routes(
        &current_routes,
        config,
        &adapters,
        internet_gateway.as_ref(),
        &native_routes,
    ) {
        Ok(result) => result,
        Err(error) => return RouteHealthOutcome::Failed(error),
    };
    let routes_repaired = !routes_match(&existing_routes, &plan.routes);

    if routes_repaired && let Err(error) = apply(&existing_routes, &plan.routes) {
        return RouteHealthOutcome::Failed(format!(
            "自動修復分流路由失敗；將於下次健康檢查重試：{error}"
        ));
    }
    let dns_repaired = match apply_dns(&plan.dns_rules) {
        Ok(changed) => changed,
        Err(error) => {
            return RouteHealthOutcome::Failed(format!(
                "自動修復 DNS 分流失敗；將於下次健康檢查重試：{error}"
            ));
        }
    };

    RouteHealthOutcome::Updated {
        config: plan.config,
        routes: plan.routes,
        adapters,
        internet_gateway: internet_gateway.map(Box::new),
        repaired: routes_repaired || dns_repaired,
        disabled_vpns: plan.disabled_vpns,
        warnings: plan.warnings,
    }
}

pub(crate) fn endpoint_refresh_required(
    scheduled_refresh: bool,
    previous_fingerprint: Option<RouteTableFingerprint>,
    current_fingerprint: RouteTableFingerprint,
) -> bool {
    scheduled_refresh || previous_fingerprint != Some(current_fingerprint)
}
