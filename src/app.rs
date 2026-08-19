use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use eframe::egui::{
    self, Color32, ComboBox, FontData, FontDefinitions, FontFamily, RichText, Stroke,
};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        SplitterConfig, ValidatedProfile, VpnKind, configured_dns_hostnames,
        configured_static_networks, has_enabled_dns_targets, validate_config_with_resolver,
    },
    windows::{
        InternetGateway, ManagedDnsRule, ManagedRoute, ManagedRoutePurpose, NetworkAdapter,
        RoutePriority, apply_dns_policy, apply_dns_policy_unless_cancelled_before_start,
        apply_routes, discover_internet_gateway, discover_vpn_adapters, existing_managed_routes,
        resolve_ipv4_with_dns_servers,
    },
};

const APP_ID: &str = "tw.layton.rust-vpn-splitter";
const ROUTE_METRIC: u16 = 5;
const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const ROUTE_HEALTH_INTERVAL: Duration = Duration::from_secs(5);
const ENDPOINT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const SHUTDOWN_CLEANUP_ATTEMPTS: usize = 3;
// FortiClient can preinstall all four /2 route keys on both the VPN and
// physical interfaces. Eight /3 routes avoid those keys and win by prefix.
const INTERNET_BYPASS_PREFIXES: [&str; 8] = [
    "0.0.0.0/3",
    "32.0.0.0/3",
    "64.0.0.0/3",
    "96.0.0.0/3",
    "128.0.0.0/3",
    "160.0.0.0/3",
    "192.0.0.0/3",
    "224.0.0.0/3",
];
const MIN_PROFILE_CARD_WIDTH: f32 = 340.0;
const MIN_PROFILE_CARD_CONTENT_HEIGHT: f32 = 300.0;
const MIN_PROFILE_CARD_HEIGHT: f32 = MIN_PROFILE_CARD_CONTENT_HEIGHT + 35.0;
const COMPACT_HEADER_BREAKPOINT: f32 = 720.0;
const MAIN_CONTENT_HORIZONTAL_MARGIN: i8 = 8;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    config: SplitterConfig,
    managed_routes: Vec<ManagedRoute>,
}

#[derive(Debug, Clone)]
enum Banner {
    Info(String),
    Success(String),
    Error(String),
}

#[derive(Debug, Default)]
struct PreparedRoutes {
    routes: Vec<ManagedRoute>,
    dns_rules: Vec<ManagedDnsRule>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct AppliedPolicy {
    prepared: PreparedRoutes,
    changed: bool,
}

#[derive(Debug)]
struct RouteHealthPlan {
    config: SplitterConfig,
    routes: Vec<ManagedRoute>,
    dns_rules: Vec<ManagedDnsRule>,
    disabled_vpns: Vec<VpnKind>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    RefreshAdapters,
    ToggleProfile { vpn: VpnKind, enabled: bool },
    RefreshDns,
    RouteHealth,
}

impl OperationKind {
    fn blocks_user_interface(self) -> bool {
        matches!(self, Self::RefreshAdapters | Self::ToggleProfile { .. })
    }

    fn progress_message(self) -> String {
        match self {
            Self::RefreshAdapters => "正在重新偵測 VPN，視窗仍可操作…".to_owned(),
            Self::ToggleProfile { vpn, enabled: true } => {
                format!("正在啟用 {vpn} 分流，請稍候…")
            }
            Self::ToggleProfile {
                vpn,
                enabled: false,
            } => format!("正在停用 {vpn} 分流，請稍候…"),
            Self::RefreshDns => "正在背景更新網域路由…".to_owned(),
            Self::RouteHealth => "正在背景核對分流路由…".to_owned(),
        }
    }

    fn cancel_during_shutdown(self) -> bool {
        matches!(self, Self::RefreshAdapters | Self::RouteHealth)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedForegroundAction {
    RefreshAdapters,
    ToggleProfile { vpn: VpnKind, enabled: bool },
}

#[derive(Debug, Clone)]
struct ReconciledRoutes {
    routes: Vec<ManagedRoute>,
    removed: usize,
}

struct NetworkSnapshot {
    adapters: Vec<NetworkAdapter>,
    internet_gateway: Option<InternetGateway>,
}

#[derive(Debug, Clone, Copy)]
enum InternetFallback<'a> {
    Physical(&'a InternetGateway),
    Vpn {
        vpn: VpnKind,
        adapter: &'a NetworkAdapter,
    },
}

impl<'a> InternetFallback<'a> {
    fn interface_index(self) -> u32 {
        match self {
            Self::Physical(gateway) => gateway.interface_index,
            Self::Vpn { adapter, .. } => adapter.index,
        }
    }

    fn next_hop(self) -> &'a str {
        match self {
            Self::Physical(gateway) => &gateway.next_hop,
            Self::Vpn { adapter, .. } => &adapter.next_hop,
        }
    }

    fn priority(self) -> Option<RoutePriority> {
        match self {
            Self::Physical(gateway) => gateway.route_priority,
            Self::Vpn { adapter, .. } => adapter.full_tunnel_priority,
        }
    }

    fn label(self) -> String {
        match self {
            Self::Physical(gateway) => gateway.interface_alias.clone(),
            Self::Vpn { vpn, adapter } => format!("未啟用分流的 {vpn}（{}）", adapter.name),
        }
    }

    fn inferred_from_escape_route(self) -> bool {
        matches!(self, Self::Physical(gateway) if gateway.inferred_from_escape_route)
    }
}

struct PolicyTransactionInput<'a> {
    managed_routes: &'a [ManagedRoute],
    active_routes: &'a [ManagedRoute],
    config: &'a SplitterConfig,
    adapters: &'a [NetworkAdapter],
    internet_gateway: Option<&'a InternetGateway>,
}

#[derive(Debug, Clone)]
struct RefreshOutcome {
    route_notice: Result<ReconciledRoutes, String>,
    dns_notice: Result<bool, String>,
    gateway_notice: Result<Option<InternetGateway>, String>,
    adapter_notice: Result<Vec<NetworkAdapter>, String>,
}

#[derive(Debug, Clone)]
enum ToggleOutcome {
    Applied {
        vpn: VpnKind,
        enabled: bool,
        config: SplitterConfig,
        routes: Vec<ManagedRoute>,
        warnings: Vec<String>,
    },
    Failed {
        attempted_enabled: bool,
        error: String,
    },
}

#[derive(Debug, Clone)]
enum DnsRefreshOutcome {
    Unchanged,
    Updated {
        routes: Vec<ManagedRoute>,
        warnings: Vec<String>,
    },
    Failed(String),
}

#[derive(Debug, Clone)]
enum RouteHealthOutcome {
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

#[derive(Debug, Clone)]
enum OperationResult {
    Refresh(RefreshOutcome),
    Toggle(ToggleOutcome),
    RefreshDns(DnsRefreshOutcome),
    RouteHealth(RouteHealthOutcome),
}

struct PendingOperation {
    kind: OperationKind,
    receiver: Receiver<OperationResult>,
    handle: Option<JoinHandle<OperationResult>>,
    cancellation: Arc<AtomicBool>,
}

impl PendingOperation {
    fn spawn(
        kind: OperationKind,
        repaint_context: egui::Context,
        work: impl FnOnce(Arc<AtomicBool>) -> OperationResult + Send + 'static,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let handle = thread::spawn(move || {
            let result = work(worker_cancellation);
            let _ = sender.send(result.clone());
            repaint_context.request_repaint();
            result
        });
        Self {
            kind,
            receiver,
            handle: Some(handle),
            cancellation,
        }
    }

    fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
    }

    fn join(mut self) -> Result<OperationResult, String> {
        self.handle
            .take()
            .expect("pending operation owns a worker")
            .join()
            .map_err(|_| "背景網路工作異常終止。".to_owned())
    }
}

#[cfg(test)]
fn replace_vpn_routes(
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

fn routes_match(left: &[ManagedRoute], right: &[ManagedRoute]) -> bool {
    left.len() == right.len() && left.iter().all(|route| right.contains(route))
}

fn needs_periodic_route_refresh(config: &SplitterConfig) -> bool {
    config.profiles.iter().any(|profile| profile.enabled)
}

fn should_schedule_dns_refresh(config: &SplitterConfig) -> bool {
    has_enabled_dns_targets(config)
}

fn discard_incomplete_vpn_route_sets(
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

fn reconciled_routes_for_config(
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

fn reconcile_routes(
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

fn run_refresh(
    previous: Vec<ManagedRoute>,
    config: SplitterConfig,
    cancellation: Arc<AtomicBool>,
) -> OperationResult {
    let remove_stale_dns_rules = !config.profiles.iter().any(|profile| profile.enabled);
    let (route_notice, gateway_notice, adapter_notice) = thread::scope(|scope| {
        let route_task = scope.spawn(move || reconcile_routes(previous, config));
        let gateway_cancellation = Arc::clone(&cancellation);
        let gateway_task = scope.spawn(move || discover_internet_gateway(&gateway_cancellation));
        let adapter_cancellation = Arc::clone(&cancellation);
        let adapter_task = scope.spawn(move || discover_vpn_adapters(&adapter_cancellation));

        let route_notice = route_task
            .join()
            .unwrap_or_else(|_| Err("背景核對路由時異常終止。".to_owned()));
        let gateway_notice = gateway_task
            .join()
            .unwrap_or_else(|_| Err("背景偵測一般網路閘道時異常終止。".to_owned()));
        let adapter_notice = adapter_task
            .join()
            .unwrap_or_else(|_| Err("背景偵測 VPN 介面時異常終止。".to_owned()));
        (route_notice, gateway_notice, adapter_notice)
    });
    let dns_notice =
        cleanup_stale_dns_rules_if_needed(remove_stale_dns_rules, &cancellation, || {
            apply_dns_policy_unless_cancelled_before_start(&[], &cancellation)
                .map(|result| result.changed)
        });

    OperationResult::Refresh(RefreshOutcome {
        route_notice,
        dns_notice,
        gateway_notice,
        adapter_notice,
    })
}

fn cleanup_stale_dns_rules_if_needed(
    remove_stale_dns_rules: bool,
    cancellation: &AtomicBool,
    cleanup: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    if !remove_stale_dns_rules || cancellation.load(Ordering::Acquire) {
        Ok(false)
    } else {
        cleanup()
    }
}

fn discover_network_snapshot(cancellation: &AtomicBool) -> Result<NetworkSnapshot, String> {
    let (adapters, internet_gateway) = thread::scope(|scope| {
        let adapter_task = scope.spawn(|| discover_vpn_adapters(cancellation));
        let gateway_task = scope.spawn(|| discover_internet_gateway(cancellation));
        let adapters = adapter_task
            .join()
            .unwrap_or_else(|_| Err("背景偵測 VPN 介面時異常終止。".to_owned()));
        let internet_gateway = gateway_task
            .join()
            .unwrap_or_else(|_| Err("背景偵測一般網路閘道時異常終止。".to_owned()));
        (adapters, internet_gateway)
    });

    Ok(NetworkSnapshot {
        adapters: adapters.map_err(|error| format!("無法重新偵測 VPN 介面：{error}"))?,
        internet_gateway: internet_gateway
            .map_err(|error| format!("無法重新偵測一般網路閘道：{error}"))?,
    })
}

#[cfg(test)]
fn prepare_profile_routes_for(
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
fn prepare_all_enabled_routes_for(
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

fn prepare_all_enabled_routes_with_resolver(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
    mut resolve_hostname: impl FnMut(VpnKind, &str, &[String]) -> Result<Vec<Ipv4Addr>, String>,
) -> Result<PreparedRoutes, Vec<String>> {
    if !config.profiles.iter().any(|profile| profile.enabled) {
        return Ok(PreparedRoutes::default());
    }

    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        selected_adapter_for_profile(config, profile.vpn, adapters)?;
    }

    let full_tunnel_vpns = enabled_full_tunnel_vpns(config, adapters);
    let fallback = select_internet_fallback(config, adapters, internet_gateway);
    let manage_dns = should_manage_dns_policy(config, &full_tunnel_vpns);
    let fallback_dns = manage_dns
        .then(|| fallback_dns_servers(fallback, adapters))
        .transpose()?;
    let validated = validate_config_with_resolver(config, |vpn, hostname| {
        let adapter = selected_adapter_for_profile(config, vpn, adapters)
            .map_err(|errors| errors.join("\n"))?;
        let vpn_dns = normalized_ipv4_servers(&adapter.dns_servers);
        if vpn_dns.is_empty() {
            return Err(format!(
                "{} 的介面「{}」尚未提供 IPv4 DNS server；不會改用其他 VPN 或一般網路 DNS。",
                vpn, adapter.description
            ));
        }
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

    append_internet_bypass_routes(&mut prepared, &full_tunnel_vpns, fallback)?;
    if let Some(fallback_dns) = fallback_dns.as_deref() {
        append_dns_policy(
            &mut prepared,
            &validated,
            config,
            adapters,
            fallback.expect("managed DNS requires a fallback path"),
            fallback_dns,
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

fn normalized_ipv4_servers(servers: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    servers
        .iter()
        .filter_map(|server| server.parse::<Ipv4Addr>().ok())
        .map(|server| server.to_string())
        .filter(|server| seen.insert(server.clone()))
        .collect()
}

fn configured_vpn_dns_routes(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
) -> Result<Vec<ManagedRoute>, Vec<String>> {
    let mut routes: Vec<ManagedRoute> = Vec::new();

    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let hostnames = configured_dns_hostnames(profile)
            .map_err(|error| vec![format!("{} 的 DNS 目標無效：{error}", profile.vpn)])?;
        if hostnames.is_empty() {
            continue;
        }

        let adapter = selected_adapter_for_profile(config, profile.vpn, adapters)?;
        let vpn_dns = normalized_ipv4_servers(&adapter.dns_servers);
        if vpn_dns.is_empty() {
            return Err(vec![format!(
                "{} 的介面「{}」尚未提供 IPv4 DNS server；為避免把其網域交給其他 VPN 或一般網路 DNS，已停止套用。請按「重新偵測 VPN」後再試。",
                profile.vpn, adapter.description
            )]);
        }
        for server in vpn_dns {
            let prefix = format!("{server}/32");
            if let Some(existing) = routes.iter().find(|route| route.prefix == prefix) {
                return Err(vec![format!(
                    "{} 與 {} 使用同一個 VPN DNS server {server}，但 Windows 只能選擇一條介面路由。",
                    existing.vpn, profile.vpn
                )]);
            }
            routes.push(ManagedRoute {
                vpn: profile.vpn,
                purpose: ManagedRoutePurpose::VpnDnsServer,
                prefix,
                interface_index: adapter.index,
                next_hop: adapter.next_hop.clone(),
                route_metric: ROUTE_METRIC,
            });
        }
    }

    Ok(routes)
}

fn validate_dns_hostname_ownership(config: &SplitterConfig) -> Result<(), Vec<String>> {
    let mut owners = BTreeMap::new();
    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let hostnames = configured_dns_hostnames(profile)
            .map_err(|error| vec![format!("{} 的 DNS 目標無效：{error}", profile.vpn)])?;
        for hostname in hostnames {
            if let Some(existing_vpn) = owners.insert(hostname.clone(), profile.vpn)
                && existing_vpn != profile.vpn
            {
                return Err(vec![format!(
                    "網域 {hostname} 同時指定給 {existing_vpn} 與 {}；同一名稱只能使用一組 VPN DNS。",
                    profile.vpn
                )]);
            }
        }
    }
    Ok(())
}

fn validate_vpn_dns_server_ownership(
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
) -> Result<(), Vec<String>> {
    let mut owners = BTreeMap::new();
    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let adapter = selected_adapter_for_profile(config, profile.vpn, adapters)?;
        for server in normalized_ipv4_servers(&adapter.dns_servers) {
            if let Some(existing_vpn) = owners.insert(server.clone(), profile.vpn)
                && existing_vpn != profile.vpn
            {
                return Err(vec![format!(
                    "{existing_vpn} 與 {} 的網路介面都宣告 DNS server {server}；Windows 無法把同一目的 IP 同時固定到兩條 VPN，已停止套用以避免 DNS 串線。",
                    profile.vpn
                )]);
            }
        }
    }
    Ok(())
}

fn validate_dns_route_target_conflicts(
    config: &SplitterConfig,
    dns_routes: &[ManagedRoute],
) -> Result<(), Vec<String>> {
    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let networks = configured_static_networks(profile)
            .map_err(|error| vec![format!("{} 的目標無效：{error}", profile.vpn)])?;
        for dns_route in dns_routes
            .iter()
            .filter(|dns_route| dns_route.vpn != profile.vpn)
        {
            let address = dns_route
                .prefix
                .strip_suffix("/32")
                .expect("DNS bootstrap routes are IPv4 host routes")
                .parse::<Ipv4Addr>()
                .expect("DNS bootstrap routes contain normalized IPv4 addresses");
            if let Some(network) = networks.iter().find(|network| network.contains(&address)) {
                return Err(vec![format!(
                    "{} 的 DNS server {address} 被 {} 的目標「{network}」涵蓋，無法同時建立正確 DNS 路由。",
                    dns_route.vpn, profile.vpn
                )]);
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

fn apply_policy_transaction_with(
    input: PolicyTransactionInput<'_>,
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
    validate_dns_hostname_ownership(config).map_err(|errors| errors.join("\n"))?;
    validate_vpn_dns_server_ownership(config, adapters).map_err(|errors| errors.join("\n"))?;
    let bootstrap_routes =
        configured_vpn_dns_routes(config, adapters).map_err(|errors| errors.join("\n"))?;
    validate_dns_route_target_conflicts(config, &bootstrap_routes)
        .map_err(|errors| errors.join("\n"))?;
    let staged_routes = routes_with_dns_bootstrap(managed_routes, bootstrap_routes);
    let bootstrap_changed = !routes_match(active_routes, &staged_routes);
    if bootstrap_changed {
        replace_routes(active_routes, &staged_routes)?;
    }

    let mut prepared = match prepare_all_enabled_routes_with_resolver(
        config,
        adapters,
        internet_gateway,
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

fn apply_policy_transaction(
    current_routes: &[ManagedRoute],
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
) -> Result<AppliedPolicy, String> {
    let active_routes = existing_managed_routes(current_routes)
        .map_err(|error| format!("無法核對套用前的 ActiveStore 分流路由：{error}"))?;
    apply_policy_transaction_with(
        PolicyTransactionInput {
            managed_routes: current_routes,
            active_routes: &active_routes,
            config,
            adapters,
            internet_gateway,
        },
        |_, hostname, servers| resolve_ipv4_with_dns_servers(hostname, servers),
        |previous, desired| apply_routes(previous, desired).map(|_| ()),
        |rules| apply_dns_policy(rules).map(|result| result.changed),
    )
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

fn select_internet_fallback<'a>(
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

fn fallback_dns_servers(
    fallback: Option<InternetFallback<'_>>,
    adapters: &[NetworkAdapter],
) -> Result<Vec<String>, Vec<String>> {
    match fallback {
        Some(InternetFallback::Physical(gateway)) => {
            current_network_dns_servers(adapters, Some(gateway))
        }
        Some(InternetFallback::Vpn { vpn, adapter }) => {
            let servers = normalized_ipv4_servers(&adapter.dns_servers);
            if servers.is_empty() {
                Err(vec![format!(
                    "{vpn} 已連線且其原生通道應處理未指定流量，但介面「{}」沒有可辨識的 IPv4 DNS server；為避免改變未啟用分流時的 DNS 行為，已停止套用。",
                    adapter.description
                )])
            } else {
                Ok(servers)
            }
        }
        None => Err(vec![
            "找不到可接手未指定流量的原生 VPN 或一般網路，已停止套用。".to_owned(),
        ]),
    }
}

fn current_network_dns_servers(
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
) -> Result<Vec<String>, Vec<String>> {
    let Some(gateway) = internet_gateway else {
        return Err(vec![
            "找不到目前 Wi-Fi／有線網路的閘道，無法建立一般 DNS 分流。".to_owned(),
        ]);
    };
    let vpn_dns = adapters
        .iter()
        .filter(|adapter| adapter.is_up())
        .flat_map(|adapter| normalized_ipv4_servers(&adapter.dns_servers))
        .collect::<BTreeSet<_>>();
    let active_physical_dns = normalized_ipv4_servers(&gateway.dns_servers)
        .into_iter()
        .filter(|server| !vpn_dns.contains(server))
        .collect::<Vec<_>>();
    let physical_dns = if active_physical_dns.is_empty() {
        normalized_ipv4_servers(&gateway.fallback_dns_servers)
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
    validated: &[ValidatedProfile],
    config: &SplitterConfig,
    adapters: &[NetworkAdapter],
    fallback: InternetFallback<'_>,
    fallback_dns: &[String],
) -> Result<(), Vec<String>> {
    prepared.dns_rules.push(ManagedDnsRule {
        vpn: None,
        namespaces: vec![".".to_owned()],
        name_servers: fallback_dns.to_vec(),
    });

    for server in fallback_dns {
        let address = server
            .parse::<Ipv4Addr>()
            .expect("fallback DNS servers are normalized IPv4 addresses");
        if let Some(route) = prepared.routes.iter().find(|route| {
            route.purpose == ManagedRoutePurpose::Target
                && route
                    .prefix
                    .parse::<ipnet::Ipv4Net>()
                    .is_ok_and(|network| network.contains(&address))
        }) {
            return Err(vec![format!(
                "未指定名稱所使用的 {} DNS {address} 被 {} 的目標「{}」涵蓋；這會改變未啟用分流時的 DNS 行為，已停止套用。",
                fallback.label(),
                route.vpn,
                route.prefix
            )]);
        }
    }

    for profile in validated
        .iter()
        .filter(|profile| !profile.hostnames.is_empty())
    {
        let adapter = selected_adapter_for_profile(config, profile.vpn, adapters)?;
        let vpn_dns = normalized_ipv4_servers(&adapter.dns_servers);
        if vpn_dns.is_empty() {
            return Err(vec![format!(
                "{} 的介面「{}」尚未提供 IPv4 DNS server；不會建立可能串線的 DNS 規則。",
                profile.vpn, adapter.description
            )]);
        }

        prepared.dns_rules.push(ManagedDnsRule {
            vpn: Some(profile.vpn),
            namespaces: profile.hostnames.clone(),
            name_servers: vpn_dns.clone(),
        });

        for server in vpn_dns {
            let address = server
                .parse::<Ipv4Addr>()
                .expect("VPN DNS servers are normalized IPv4 addresses");
            if let Some(route) = prepared.routes.iter().find(|route| {
                route.vpn != profile.vpn
                    && route.purpose == ManagedRoutePurpose::Target
                    && route
                        .prefix
                        .parse::<ipnet::Ipv4Net>()
                        .is_ok_and(|network| network.contains(&address))
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
                        .is_ok_and(|network| network.contains(&address))
            });
            if covered_by_own_target {
                continue;
            }

            let prefix = format!("{address}/32");
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
                interface_index: adapter.index,
                next_hop: adapter.next_hop.clone(),
                route_metric: ROUTE_METRIC,
            });
        }
    }

    Ok(())
}

fn enabled_full_tunnel_vpns(config: &SplitterConfig, adapters: &[NetworkAdapter]) -> Vec<VpnKind> {
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

fn should_manage_dns_policy(config: &SplitterConfig, full_tunnel_vpns: &[VpnKind]) -> bool {
    !full_tunnel_vpns.is_empty() || has_enabled_dns_targets(config)
}

fn append_internet_bypass_routes(
    prepared: &mut PreparedRoutes,
    full_tunnel_vpns: &[VpnKind],
    fallback: Option<InternetFallback<'_>>,
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

    prepared
        .routes
        .extend(INTERNET_BYPASS_PREFIXES.map(|prefix| ManagedRoute {
            vpn: owner,
            purpose: ManagedRoutePurpose::InternetBypass,
            prefix: prefix.to_owned(),
            interface_index: fallback.interface_index(),
            next_hop: fallback.next_hop().to_owned(),
            route_metric: ROUTE_METRIC,
        }));

    let source = if fallback.inferred_from_escape_route() {
        "（由 VPN 保留的伺服器繞行路由推定）"
    } else {
        ""
    };
    prepared.warnings.push(format!(
        "{tunnel_state} Full Tunnel；非指定 IPv4 流量會透過 {} 保留原生選路{}。若 VPN 公司策略強制封鎖繞行，連線仍可能受限。",
        fallback.label(), source
    ));

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

fn run_toggle(
    current_routes: Vec<ManagedRoute>,
    mut next_config: SplitterConfig,
    vpn: VpnKind,
    enabled: bool,
    cancellation: Arc<AtomicBool>,
) -> OperationResult {
    let Some(profile) = next_config.profile_mut(vpn) else {
        return OperationResult::Toggle(ToggleOutcome::Failed {
            attempted_enabled: enabled,
            error: format!("找不到 {vpn} 設定；開關未變更。"),
        });
    };
    profile.enabled = enabled;

    let snapshot = match discover_network_snapshot(&cancellation) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return OperationResult::Toggle(ToggleOutcome::Failed {
                attempted_enabled: enabled,
                error: format!("套用前重新偵測網路狀態失敗：{error}\n開關已恢復原狀。"),
            });
        }
    };

    match apply_policy_transaction(
        &current_routes,
        &next_config,
        &snapshot.adapters,
        snapshot.internet_gateway.as_ref(),
    ) {
        Ok(applied) => OperationResult::Toggle(ToggleOutcome::Applied {
            vpn,
            enabled,
            config: next_config,
            routes: applied.prepared.routes,
            warnings: applied.prepared.warnings,
        }),
        Err(error) => OperationResult::Toggle(ToggleOutcome::Failed {
            attempted_enabled: enabled,
            error: format!("{error}\n開關已恢復原狀。"),
        }),
    }
}

fn run_dns_refresh(
    current_routes: Vec<ManagedRoute>,
    config: SplitterConfig,
    cancellation: Arc<AtomicBool>,
) -> OperationResult {
    let snapshot = match discover_network_snapshot(&cancellation) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return OperationResult::RefreshDns(DnsRefreshOutcome::Failed(format!(
                "自動更新 DNS 前無法重新偵測網路狀態，目前路由保持不變：{error}"
            )));
        }
    };
    match apply_policy_transaction(
        &current_routes,
        &config,
        &snapshot.adapters,
        snapshot.internet_gateway.as_ref(),
    ) {
        Ok(AppliedPolicy { changed: false, .. }) => {
            OperationResult::RefreshDns(DnsRefreshOutcome::Unchanged)
        }
        Ok(applied) => OperationResult::RefreshDns(DnsRefreshOutcome::Updated {
            routes: applied.prepared.routes,
            warnings: applied.prepared.warnings,
        }),
        Err(error) => OperationResult::RefreshDns(DnsRefreshOutcome::Failed(format!(
            "自動更新 DNS 路由失敗，目前路由保持不變：{error}"
        ))),
    }
}

fn desired_routes_for_health_check(
    current_routes: &[ManagedRoute],
    mut config: SplitterConfig,
    adapters: &[NetworkAdapter],
    internet_gateway: Option<&InternetGateway>,
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

    let dns_profiles = config
        .profiles
        .iter()
        .filter(|profile| profile.enabled)
        .map(|profile| {
            configured_dns_hostnames(profile)
                .map(|hostnames| ValidatedProfile {
                    vpn: profile.vpn,
                    networks: Vec::new(),
                    hostnames,
                })
                .map_err(|error| format!("{} 的 DNS 目標無效：{error}", profile.vpn))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared = PreparedRoutes {
        routes: desired_routes,
        dns_rules: Vec::new(),
        warnings,
    };
    let fallback = select_internet_fallback(&config, adapters, internet_gateway);
    append_internet_bypass_routes(&mut prepared, &full_tunnel_vpns, fallback)
        .map_err(|errors| errors.join("\n"))?;
    if should_manage_dns_policy(&config, &full_tunnel_vpns) {
        let fallback_dns =
            fallback_dns_servers(fallback, adapters).map_err(|errors| errors.join("\n"))?;
        append_dns_policy(
            &mut prepared,
            &dns_profiles,
            &config,
            adapters,
            fallback.expect("managed DNS requires a fallback path"),
            &fallback_dns,
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

fn evaluate_route_health_with(
    current_routes: Vec<ManagedRoute>,
    config: SplitterConfig,
    existing_routes: Vec<ManagedRoute>,
    adapters: Vec<NetworkAdapter>,
    internet_gateway: Option<InternetGateway>,
    mut apply: impl FnMut(&[ManagedRoute], &[ManagedRoute]) -> Result<(), String>,
    mut apply_dns: impl FnMut(&[ManagedDnsRule]) -> Result<bool, String>,
) -> RouteHealthOutcome {
    let plan = match desired_routes_for_health_check(
        &current_routes,
        config,
        &adapters,
        internet_gateway.as_ref(),
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

fn run_route_health(
    current_routes: Vec<ManagedRoute>,
    config: SplitterConfig,
    refresh_endpoints: bool,
    cancellation: Arc<AtomicBool>,
) -> OperationResult {
    let existing_routes = match existing_managed_routes(&current_routes) {
        Ok(routes) => routes,
        Err(error) => {
            return OperationResult::RouteHealth(RouteHealthOutcome::Failed(format!(
                "無法核對 ActiveStore 分流路由；將稍後重試：{error}"
            )));
        }
    };

    if !refresh_endpoints && routes_match(&existing_routes, &current_routes) {
        return OperationResult::RouteHealth(RouteHealthOutcome::Healthy);
    }

    let (adapters, internet_gateway) = thread::scope(|scope| {
        let adapter_cancellation = Arc::clone(&cancellation);
        let adapter_task = scope.spawn(move || discover_vpn_adapters(&adapter_cancellation));
        let gateway_cancellation = Arc::clone(&cancellation);
        let gateway_task = scope.spawn(move || discover_internet_gateway(&gateway_cancellation));
        let adapters = adapter_task
            .join()
            .unwrap_or_else(|_| Err("背景偵測 VPN 介面時異常終止。".to_owned()));
        let internet_gateway = gateway_task
            .join()
            .unwrap_or_else(|_| Err("背景偵測一般網路閘道時異常終止。".to_owned()));
        (adapters, internet_gateway)
    });
    let adapters = match adapters {
        Ok(adapters) => adapters,
        Err(error) => {
            return OperationResult::RouteHealth(RouteHealthOutcome::Failed(format!(
                "自動修復前無法重新偵測 VPN 介面：{error}"
            )));
        }
    };
    let internet_gateway = match internet_gateway {
        Ok(gateway) => gateway,
        Err(error) => {
            return OperationResult::RouteHealth(RouteHealthOutcome::Failed(format!(
                "自動修復前無法重新偵測一般網路閘道：{error}"
            )));
        }
    };

    OperationResult::RouteHealth(evaluate_route_health_with(
        current_routes,
        config,
        existing_routes,
        adapters,
        internet_gateway,
        |previous, desired| apply_routes(previous, desired).map(|_| ()),
        |rules| apply_dns_policy(rules).map(|result| result.changed),
    ))
}

fn disable_all_profiles(state: &mut PersistedState) {
    for profile in &mut state.config.profiles {
        profile.enabled = false;
    }
}

fn cleanup_managed_routes_with(
    state: &mut PersistedState,
    mut remove_routes: impl FnMut(&[ManagedRoute]) -> Result<(), String>,
) -> Result<(), String> {
    disable_all_profiles(state);
    if state.managed_routes.is_empty() {
        return Ok(());
    }

    let inventory = state.managed_routes.clone();
    let mut last_error = None;
    for _ in 0..SHUTDOWN_CLEANUP_ATTEMPTS {
        match remove_routes(&inventory) {
            Ok(()) => {
                state.managed_routes.clear();
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(format!(
        "關閉時重試 {SHUTDOWN_CLEANUP_ATTEMPTS} 次仍無法移除全部管理路由；已保留路由清單供下次啟動復原：{}",
        last_error.unwrap_or_else(|| "未知錯誤".to_owned())
    ))
}

fn cleanup_managed_routes(state: &mut PersistedState) -> Result<(), String> {
    cleanup_managed_routes_with(state, |routes| apply_routes(routes, &[]).map(|_| ()))
}

fn cleanup_dns_policy_on_shutdown_with(
    had_active_policy: bool,
    stale_dns_cleanup_pending: bool,
    cancelled_pending_operation: bool,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if had_active_policy || stale_dns_cleanup_pending || cancelled_pending_operation {
        cleanup()
    } else {
        Ok(())
    }
}

pub struct SplitterApp {
    state: PersistedState,
    state_path: PathBuf,
    adapters: Vec<NetworkAdapter>,
    internet_gateway: Option<InternetGateway>,
    banner: Banner,
    enable_error_dialog: Option<String>,
    next_dns_refresh_at: Instant,
    next_route_health_at: Instant,
    next_endpoint_refresh_at: Instant,
    repaint_context: egui::Context,
    pending_operation: Option<PendingOperation>,
    queued_foreground_action: Option<QueuedForegroundAction>,
    stale_dns_cleanup_pending: bool,
}

impl SplitterApp {
    pub fn new(creation_context: &eframe::CreationContext<'_>) -> Self {
        install_chinese_font(&creation_context.egui_ctx);
        configure_style(&creation_context.egui_ctx);

        let state_path = state_path();
        let mut state = load_state(&state_path).unwrap_or_default();
        // ActiveStore routes can survive an abnormal process termination until
        // reboot.  Always start disabled so the initial reconciliation removes
        // any inventory left by a prior process before the user opts in again.
        disable_all_profiles(&mut state);

        let mut app = Self {
            state,
            state_path,
            adapters: Vec::new(),
            internet_gateway: None,
            banner: Banner::Info(
                "請填入 CIDR、網域或網址；切換開關時會立即驗證並套用。".to_owned(),
            ),
            enable_error_dialog: None,
            next_dns_refresh_at: Instant::now(),
            next_route_health_at: Instant::now(),
            next_endpoint_refresh_at: Instant::now(),
            repaint_context: creation_context.egui_ctx.clone(),
            pending_operation: None,
            queued_foreground_action: None,
            stale_dns_cleanup_pending: true,
        };
        app.refresh_adapters();
        app
    }

    fn refresh_adapters(&mut self) {
        if let Some(pending) = &self.pending_operation {
            if !pending.kind.blocks_user_interface() {
                self.queued_foreground_action = Some(QueuedForegroundAction::RefreshAdapters);
                self.banner = Banner::Info(OperationKind::RefreshAdapters.progress_message());
            }
            return;
        }
        self.next_dns_refresh_at = Instant::now();
        self.next_endpoint_refresh_at = Instant::now();
        let previous = self.state.managed_routes.clone();
        let config = self.state.config.clone();
        self.start_operation(OperationKind::RefreshAdapters, move |cancellation| {
            run_refresh(previous, config, cancellation)
        });
    }

    fn start_operation(
        &mut self,
        kind: OperationKind,
        work: impl FnOnce(Arc<AtomicBool>) -> OperationResult + Send + 'static,
    ) {
        if self.pending_operation.is_some() {
            return;
        }
        if kind.blocks_user_interface() {
            self.banner = Banner::Info(kind.progress_message());
        }
        self.pending_operation = Some(PendingOperation::spawn(
            kind,
            self.repaint_context.clone(),
            work,
        ));
    }

    fn poll_background_operation(&mut self) {
        let Some(pending) = self.pending_operation.as_ref() else {
            return;
        };
        let received = match pending.receiver.try_recv() {
            Ok(result) => Some(Ok(result)),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(format!(
                "{}失敗：背景工作未回傳結果。",
                pending.kind.progress_message()
            ))),
        };
        let Some(received) = received else {
            return;
        };

        let pending = self
            .pending_operation
            .take()
            .expect("received result belongs to a pending operation");
        let operation_kind = pending.kind;
        let joined = pending.join();
        match received.or(joined) {
            Ok(result) => self.apply_operation_result(result),
            Err(error) => self.finish_unexpected_operation_failure(operation_kind, error),
        }
        self.start_queued_foreground_action();
    }

    fn start_queued_foreground_action(&mut self) {
        if self.pending_operation.is_some() {
            return;
        }
        let Some(action) = self.queued_foreground_action.take() else {
            return;
        };
        match action {
            QueuedForegroundAction::RefreshAdapters => self.refresh_adapters(),
            QueuedForegroundAction::ToggleProfile { vpn, enabled } => {
                self.set_profile_enabled(vpn, enabled);
            }
        }
    }

    fn user_interface_busy(&self) -> bool {
        self.queued_foreground_action.is_some()
            || self
                .pending_operation
                .as_ref()
                .is_some_and(|pending| pending.kind.blocks_user_interface())
    }

    fn apply_operation_result(&mut self, result: OperationResult) {
        match result {
            OperationResult::Refresh(outcome) => self.finish_refresh(outcome),
            OperationResult::Toggle(outcome) => self.finish_toggle(outcome),
            OperationResult::RefreshDns(outcome) => self.finish_dns_refresh(outcome),
            OperationResult::RouteHealth(outcome) => self.finish_route_health(outcome),
        }
    }

    fn finish_refresh(&mut self, outcome: RefreshOutcome) {
        let stale_dns_cleanup_completed = outcome.dns_notice.is_ok();
        let route_notice = match outcome.route_notice {
            Ok(reconciled) => {
                self.state.managed_routes = reconciled.routes;
                self.sync_enabled_profiles_to_routes();
                if reconciled.removed > 0 {
                    let _ = save_state(&self.state_path, &self.state);
                }
                Ok(reconciled.removed)
            }
            Err(error) => Err(error),
        };

        let gateway_notice = outcome.gateway_notice;
        let dns_notice = outcome.dns_notice;
        if let Ok(gateway) = &gateway_notice {
            self.internet_gateway = gateway.clone();
        }

        match outcome.adapter_notice {
            Ok(adapters) => {
                self.adapters = adapters;
                self.auto_select_adapters();
                self.banner = match (route_notice, gateway_notice, dns_notice) {
                    (_, Err(error), _) => Banner::Error(format!(
                        "VPN 介面已重新偵測，但無法偵測一般網路閘道：{error}"
                    )),
                    (_, _, Err(error)) => Banner::Error(format!(
                        "VPN 介面已重新偵測，但無法清除先前殘留的 DNS 分流：{error}"
                    )),
                    (Ok(removed), _, _) if removed > 0 => Banner::Info(format!(
                        "已重新偵測介面；另清除 {removed} 條 VPN 已斷線後殘留的 ActiveStore 路由，開關狀態已同步。"
                    )),
                    (Ok(_), _, _) => Banner::Info(format!(
                        "已重新偵測到 {} 個可能的 VPN 網路介面。",
                        self.adapters.len()
                    )),
                    (Err(error), _, _) => Banner::Error(error),
                };
            }
            Err(error) => self.banner = Banner::Error(error),
        }
        if stale_dns_cleanup_completed {
            self.stale_dns_cleanup_pending = false;
        }
    }

    fn finish_toggle(&mut self, outcome: ToggleOutcome) {
        match outcome {
            ToggleOutcome::Applied {
                vpn,
                enabled,
                config,
                routes,
                warnings,
            } => {
                self.state.config = config;
                self.state.managed_routes = routes;
                self.next_dns_refresh_at = Instant::now() + DNS_REFRESH_INTERVAL;
                self.next_route_health_at = Instant::now() + ROUTE_HEALTH_INTERVAL;
                self.next_endpoint_refresh_at = Instant::now() + ENDPOINT_REFRESH_INTERVAL;
                let warning_text = if warnings.is_empty() {
                    String::new()
                } else {
                    format!("\n{}", warnings.join("\n"))
                };
                let message = if enabled {
                    let count = self
                        .state
                        .managed_routes
                        .iter()
                        .filter(|route| route.vpn == vpn)
                        .count();
                    format!("{vpn} 分流已開啟，目前管理 {count} 條路由。")
                } else {
                    format!("{vpn} 分流已關閉，本程式建立的相關路由已移除。")
                };
                self.banner = Banner::Success(format!("{message}{warning_text}"));
                if let Err(error) = save_state(&self.state_path, &self.state) {
                    self.banner = Banner::Error(format!("路由已套用，但設定保存失敗：{error}"));
                }
            }
            ToggleOutcome::Failed {
                attempted_enabled,
                error,
            } => {
                self.banner = Banner::Error(error.clone());
                if attempted_enabled {
                    self.enable_error_dialog = Some(error);
                }
            }
        }
    }

    fn finish_unexpected_operation_failure(&mut self, operation: OperationKind, error: String) {
        self.banner = Banner::Error(error.clone());
        if matches!(
            operation,
            OperationKind::ToggleProfile { enabled: true, .. }
        ) {
            self.enable_error_dialog = Some(error);
        }
    }

    fn show_enable_error_dialog(&mut self, context: &egui::Context) {
        let Some(error) = self.enable_error_dialog.clone() else {
            return;
        };

        let modal = egui::Modal::new(egui::Id::new("enable-error-dialog")).show(context, |ui| {
            ui.set_min_width(360.0);
            ui.set_max_width(520.0);
            ui.heading("啟用分流失敗");
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .max_height(240.0)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(error).wrap());
                });
            ui.add_space(10.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.button("確定").clicked()
            })
            .inner
        });

        if modal.inner || modal.should_close() {
            self.enable_error_dialog = None;
        }
    }

    fn finish_dns_refresh(&mut self, outcome: DnsRefreshOutcome) {
        match outcome {
            DnsRefreshOutcome::Unchanged => {}
            DnsRefreshOutcome::Updated { routes, warnings } => {
                self.state.managed_routes = routes;
                let warning_text = if warnings.is_empty() {
                    String::new()
                } else {
                    format!("\n{}", warnings.join("\n"))
                };
                self.banner = Banner::Success(format!(
                    "網域已重新解析並更新，目前管理 {} 條路由。{}",
                    self.state.managed_routes.len(),
                    warning_text
                ));
                if let Err(error) = save_state(&self.state_path, &self.state) {
                    self.banner = Banner::Error(format!("DNS 路由已更新，但設定保存失敗：{error}"));
                }
            }
            DnsRefreshOutcome::Failed(error) => self.banner = Banner::Error(error),
        }
    }

    fn finish_route_health(&mut self, outcome: RouteHealthOutcome) {
        match outcome {
            RouteHealthOutcome::Healthy => {}
            RouteHealthOutcome::Updated {
                config,
                routes,
                adapters,
                internet_gateway,
                repaired,
                disabled_vpns,
                warnings,
            } => {
                debug_assert!(
                    disabled_vpns.iter().all(|vpn| {
                        config.profile(*vpn).is_some_and(|profile| !profile.enabled)
                    })
                );
                let mut state_changed = self.state.managed_routes != routes;
                for vpn in &disabled_vpns {
                    if let Some(profile) = self.state.config.profile_mut(*vpn)
                        && profile.enabled
                    {
                        profile.enabled = false;
                        state_changed = true;
                    }
                }
                self.state.managed_routes = routes;
                self.adapters = adapters;
                self.internet_gateway = internet_gateway.map(|gateway| *gateway);

                if state_changed {
                    let _ = save_state(&self.state_path, &self.state);
                }
                if !disabled_vpns.is_empty() {
                    self.banner = Banner::Info(warnings.join("\n"));
                } else if repaired {
                    self.banner = Banner::Success(format!(
                        "偵測到 VPN 或網路介面改寫路由，已自動修復 {} 條管理路由。",
                        self.state.managed_routes.len()
                    ));
                }
            }
            RouteHealthOutcome::Failed(error) => {
                self.next_endpoint_refresh_at = Instant::now() + ROUTE_HEALTH_INTERVAL;
                self.banner = Banner::Error(error);
            }
        }
    }

    fn sync_enabled_profiles_to_routes(&mut self) {
        for vpn in VpnKind::ALL {
            let active = self
                .state
                .managed_routes
                .iter()
                .any(|route| route.vpn == vpn);
            if let Some(profile) = self.state.config.profile_mut(vpn) {
                profile.enabled = active;
            }
        }
    }

    fn auto_select_adapters(&mut self) {
        for vpn in VpnKind::ALL {
            let candidates = self
                .adapters
                .iter()
                .filter(|adapter| adapter.matches(vpn))
                .collect::<Vec<_>>();

            let Some(profile) = self.state.config.profile_mut(vpn) else {
                continue;
            };

            if profile.enabled {
                continue;
            }

            let connected = candidates
                .iter()
                .copied()
                .filter(|adapter| adapter.is_up())
                .collect::<Vec<_>>();

            let selected = if connected.len() == 1 {
                connected.first().copied()
            } else if profile
                .adapter_description
                .as_ref()
                .is_some_and(|description| {
                    candidates
                        .iter()
                        .any(|adapter| &adapter.description == description)
                })
            {
                continue;
            } else if !candidates.is_empty() {
                candidates.first().copied()
            } else {
                None
            };

            profile.adapter_description = selected.map(|adapter| adapter.description.clone());
        }
    }

    fn profile_card(&mut self, ui: &mut egui::Ui, vpn: VpnKind, minimum_height: f32) {
        let accent = accent_color(vpn);
        let busy = self.user_interface_busy();
        let candidates = self
            .adapters
            .iter()
            .filter(|adapter| adapter.matches(vpn))
            .cloned()
            .collect::<Vec<_>>();
        let Some(profile) = self.state.config.profile_mut(vpn) else {
            return;
        };
        let enabled = profile.enabled;
        let mut requested_enabled = enabled;
        let mut toggle_request = None;

        let frame = egui::Frame::group(ui.style())
            .stroke(Stroke::new(1.5, accent))
            .inner_margin(16);
        let minimum_content_height =
            (minimum_height - frame.total_margin().sum().y).max(MIN_PROFILE_CARD_CONTENT_HEIGHT);

        frame.show(ui, |ui| {
            let content_top = ui.cursor().top();
            ui.set_min_width(ui.available_width());
            ui.set_min_height(minimum_content_height);

            ui.horizontal(|ui| {
                ui.heading(RichText::new(vpn.to_string()).color(accent));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if enabled {
                        "停用分流"
                    } else {
                        "啟用分流"
                    };
                    ui.add_enabled_ui(!busy, |ui| {
                        let response = ui.toggle_value(&mut requested_enabled, label);
                        if response.changed() {
                            toggle_request = Some(requested_enabled);
                        }
                    });
                });
            });

            ui.add_space(8.0);
            ui.label(RichText::new("VPN 虛擬網卡（自動偵測）").strong());

            let selected_text = profile
                .adapter_description
                .as_ref()
                .and_then(|description| {
                    candidates
                        .iter()
                        .find(|adapter| &adapter.description == description)
                })
                .map(NetworkAdapter::display_label)
                .or_else(|| profile.adapter_description.clone())
                .unwrap_or_else(|| "尚未選擇".to_owned());

            let connected_count = candidates.iter().filter(|adapter| adapter.is_up()).count();
            let requires_choice = connected_count > 1;

            if requires_choice {
                ui.small("同時偵測到多張已連線網卡，請選擇這次使用的那一張。");
                ui.add_enabled_ui(!enabled && !busy, |ui| {
                    ComboBox::from_id_salt(("adapter", vpn.key()))
                        .selected_text(selected_text)
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            for adapter in &candidates {
                                ui.selectable_value(
                                    &mut profile.adapter_description,
                                    Some(adapter.description.clone()),
                                    adapter.display_label(),
                                );
                            }
                        });
                });
            } else {
                let selected_adapter =
                    profile
                        .adapter_description
                        .as_ref()
                        .and_then(|description| {
                            candidates
                                .iter()
                                .find(|adapter| &adapter.description == description)
                        });

                egui::Frame::new()
                    .fill(Color32::from_rgb(31, 39, 52))
                    .corner_radius(6)
                    .inner_margin(10)
                    .show(ui, |ui| {
                        if let Some(adapter) = selected_adapter {
                            let (status, color) = if adapter.is_up() {
                                ("已連線", Color32::from_rgb(92, 200, 132))
                            } else {
                                ("未連線", Color32::from_rgb(244, 133, 133))
                            };
                            ui.colored_label(color, status);
                            ui.add(
                                egui::Label::new(&adapter.description)
                                    .wrap()
                                    .selectable(false),
                            );
                        } else {
                            ui.colored_label(
                                Color32::from_rgb(244, 133, 133),
                                format!("尚未偵測到 {vpn} 虛擬網卡"),
                            );
                            ui.small("請先連線 VPN，再按上方的「重新偵測 VPN」。");
                        }
                    });

                if candidates.len() > 1 && connected_count == 1 {
                    ui.small("已自動選擇目前正在連線的網卡。");
                }
            }

            if let Some(adapter) = profile
                .adapter_description
                .as_ref()
                .and_then(|description| {
                    candidates
                        .iter()
                        .find(|adapter| &adapter.description == description)
                })
                && adapter.full_tunnel_priority.is_some()
            {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Full Tunnel：啟用分流後，非指定流量仍由未啟用分流的 VPN 或原本網路處理。",
                        )
                        .color(Color32::from_rgb(216, 142, 42)),
                    )
                    .wrap(),
                );
            }

            ui.add_space(10.0);
            ui.label("目的 IPv4 CIDR、網域或網址");
            let line_height = ui.text_style_height(&egui::TextStyle::Monospace);
            let minimum_editor_height = line_height * 4.0 + 4.0;
            let used_content_height = ui.cursor().top() - content_top;
            let editor_height =
                (minimum_content_height - used_content_height).max(minimum_editor_height);
            let desired_rows = ((editor_height - 4.0) / line_height).floor().max(4.0) as usize;
            let response = egui::ScrollArea::vertical()
                .id_salt(("target-editor", vpn.key()))
                .max_height(editor_height)
                .min_scrolled_height(editor_height)
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                .show(ui, |ui| {
                    ui.add_enabled(
                        !enabled && !busy,
                        egui::TextEdit::multiline(&mut profile.networks)
                            .desired_rows(desired_rows)
                            .desired_width(f32::INFINITY)
                            .hint_text("例如：\n192.0.2.0/24\nhttp://gitlab.example.test:1500/")
                            .font(egui::TextStyle::Monospace),
                    )
                })
                .inner;
            if enabled {
                response.on_hover_text("分流已啟用；請先關閉，成功移除路由與 DNS 規則後才能修改。");
            }
        });

        if let Some(requested_enabled) = toggle_request {
            self.set_profile_enabled(vpn, requested_enabled);
        }
    }

    fn profile_grid(&mut self, ui: &mut egui::Ui, available_height: f32) {
        let available_width = ui.available_width();
        let spacing = ui.spacing().item_spacing;
        let layout = profile_grid_layout(available_width, available_height, spacing.x, spacing.y);

        ui.allocate_ui_with_layout(
            egui::vec2(available_width, layout.total_height),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                for vpns in VpnKind::ALL.chunks(layout.column_count) {
                    ui.columns(vpns.len(), |columns| {
                        for (column, vpn) in columns.iter_mut().zip(vpns.iter().copied()) {
                            self.profile_card(column, vpn, layout.row_height);
                        }
                    });
                }
            },
        );
    }

    fn header(&mut self, ui: &mut egui::Ui, busy: bool) {
        if ui.available_width() < COMPACT_HEADER_BREAKPOINT {
            ui.heading("VPN 分流管理器");
            ui.label("指定哪些 IPv4 目的網段或網域要走 FortiClient、F5 或 Ivanti。");
            ui.add_space(4.0);
            ui.horizontal(|ui| self.refresh_controls(ui, busy));
        } else {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.heading("VPN 分流管理器");
                    ui.label("指定哪些 IPv4 目的網段或網域要走 FortiClient、F5 或 Ivanti。");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.refresh_controls(ui, busy);
                });
            });
        }
    }

    fn refresh_controls(&mut self, ui: &mut egui::Ui, busy: bool) {
        if ui
            .add_enabled(!busy, egui::Button::new("重新偵測 VPN"))
            .clicked()
        {
            self.refresh_adapters();
        }
        if busy {
            ui.label("處理中…");
        }
    }

    fn content(&mut self, ui: &mut egui::Ui, busy: bool, viewport_height: f32) {
        let content_top = ui.cursor().top();
        self.header(ui, busy);

        ui.add_space(6.0);
        egui::Frame::new()
            .fill(Color32::from_rgb(31, 39, 52))
            .corner_radius(8)
            .inner_margin(10)
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        "可填 CIDR、網域或網址；只有已開啟區塊的目標會改走其 VPN。未列入的名稱與流量仍由未開分流的 VPN 或原本網路處理。開關開啟期間會鎖定輸入。",
                    )
                    .wrap(),
                );
            });

        ui.add_space(10.0);
        let occupied_height = ui.cursor().top() - content_top;
        let bottom_spacing = ui.spacing().item_spacing.y;
        let available_grid_height =
            profile_grid_available_height(viewport_height, occupied_height, bottom_spacing);
        self.profile_grid(ui, available_grid_height);

        // Commit egui's automatic trailing item spacing to the content bounds so
        // the last card row keeps the same gap above the fixed status bar.
        ui.add_space(0.0);
    }

    fn footer(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "目前管理 {} 條路由",
                self.state.managed_routes.len()
            ));
            ui.separator();
            match &self.banner {
                Banner::Info(message) => {
                    ui.label(message);
                }
                Banner::Success(message) => {
                    ui.colored_label(Color32::from_rgb(92, 200, 132), message);
                }
                Banner::Error(message) => {
                    ui.colored_label(Color32::from_rgb(244, 133, 133), message);
                }
            }
        });
    }

    #[cfg(test)]
    fn prepare_profile_routes(
        &self,
        config: &SplitterConfig,
        vpn: VpnKind,
    ) -> Result<PreparedRoutes, Vec<String>> {
        prepare_profile_routes_for(config, vpn, &self.adapters, self.internet_gateway.as_ref())
    }

    #[cfg(test)]
    fn prepare_all_enabled_routes(
        &self,
        config: &SplitterConfig,
    ) -> Result<PreparedRoutes, Vec<String>> {
        prepare_all_enabled_routes_for(config, &self.adapters, self.internet_gateway.as_ref())
    }

    fn refresh_routes_if_due(&mut self) {
        let now = Instant::now();
        if self.pending_operation.is_some()
            || now < self.next_route_health_at
            || (!needs_periodic_route_refresh(&self.state.config)
                && self.state.managed_routes.is_empty())
        {
            return;
        }

        self.next_route_health_at = now + ROUTE_HEALTH_INTERVAL;
        let refresh_endpoints = now >= self.next_endpoint_refresh_at;
        if refresh_endpoints {
            self.next_endpoint_refresh_at = now + ENDPOINT_REFRESH_INTERVAL;
        }
        let current_routes = self.state.managed_routes.clone();
        let config = self.state.config.clone();
        self.start_operation(OperationKind::RouteHealth, move |cancellation| {
            run_route_health(current_routes, config, refresh_endpoints, cancellation)
        });
    }

    fn refresh_dns_routes_if_due(&mut self) {
        let now = Instant::now();
        if self.pending_operation.is_some()
            || now < self.next_dns_refresh_at
            || !should_schedule_dns_refresh(&self.state.config)
        {
            return;
        }
        self.next_dns_refresh_at = now + DNS_REFRESH_INTERVAL;
        let current_routes = self.state.managed_routes.clone();
        let config = self.state.config.clone();
        self.start_operation(OperationKind::RefreshDns, move |cancellation| {
            run_dns_refresh(current_routes, config, cancellation)
        });
    }

    fn set_profile_enabled(&mut self, vpn: VpnKind, enabled: bool) {
        if let Some(pending) = &self.pending_operation {
            if !pending.kind.blocks_user_interface() {
                self.queued_foreground_action =
                    Some(QueuedForegroundAction::ToggleProfile { vpn, enabled });
                self.banner =
                    Banner::Info(OperationKind::ToggleProfile { vpn, enabled }.progress_message());
            }
            return;
        }
        let currently_enabled = self
            .state
            .config
            .profile(vpn)
            .is_some_and(|profile| profile.enabled);
        if currently_enabled == enabled {
            return;
        }
        let current_routes = self.state.managed_routes.clone();
        let config = self.state.config.clone();
        self.start_operation(
            OperationKind::ToggleProfile { vpn, enabled },
            move |cancellation| run_toggle(current_routes, config, vpn, enabled, cancellation),
        );
    }

    fn save_to_disk(&self) {
        let _ = save_state(&self.state_path, &self.state);
    }
}

impl Drop for SplitterApp {
    fn drop(&mut self) {
        let mut cancelled_pending_operation = false;
        if let Some(pending) = self.pending_operation.take() {
            if pending.kind.cancel_during_shutdown() {
                pending.cancel();
                cancelled_pending_operation = true;
            }
            if let Ok(result) = pending.join() {
                self.apply_operation_result(result);
            }
        }
        let had_active_policy = !self.state.managed_routes.is_empty()
            || self
                .state
                .config
                .profiles
                .iter()
                .any(|profile| profile.enabled);
        let _ = cleanup_managed_routes(&mut self.state);
        let _ = cleanup_dns_policy_on_shutdown_with(
            had_active_policy,
            self.stale_dns_cleanup_pending,
            cancelled_pending_operation,
            || apply_dns_policy(&[]).map(|_| ()),
        );
        self.save_to_disk();
    }
}

impl eframe::App for SplitterApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_background_operation();
        self.refresh_routes_if_due();
        self.refresh_dns_routes_if_due();
        let busy = self.user_interface_busy();

        egui::Panel::bottom("status-bar").show(ui, |ui| self.footer(ui));

        egui::ScrollArea::vertical()
            .id_salt("main-content")
            .auto_shrink([false, false])
            .content_margin(egui::Margin::symmetric(MAIN_CONTENT_HORIZONTAL_MARGIN, 0))
            .show_viewport(ui, |ui, viewport| {
                ui.set_min_width(ui.available_width());
                self.content(ui, busy, viewport.height());
            });

        let context = ui.ctx().clone();
        self.show_enable_error_dialog(&context);

        if needs_periodic_route_refresh(&self.state.config) || !self.state.managed_routes.is_empty()
        {
            let now = Instant::now();
            let mut repaint_after = self.next_route_health_at.saturating_duration_since(now);
            if should_schedule_dns_refresh(&self.state.config) {
                repaint_after =
                    repaint_after.min(self.next_dns_refresh_at.saturating_duration_since(now));
            }
            ui.ctx().request_repaint_after(repaint_after);
        }
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        self.save_to_disk();
    }
}

fn profile_column_count(available_width: f32, column_spacing: f32) -> usize {
    let available_width = available_width.max(0.0);
    let column_spacing = column_spacing.max(0.0);
    let fitting_columns = ((available_width + column_spacing)
        / (MIN_PROFILE_CARD_WIDTH + column_spacing))
        .floor() as usize;

    fitting_columns.clamp(1, VpnKind::ALL.len())
}

#[derive(Debug, Clone, Copy)]
struct ProfileGridLayout {
    column_count: usize,
    row_height: f32,
    total_height: f32,
}

fn profile_grid_available_height(
    viewport_height: f32,
    occupied_height: f32,
    bottom_spacing: f32,
) -> f32 {
    (viewport_height.max(0.0) - occupied_height.max(0.0) - bottom_spacing.max(0.0)).max(0.0)
}

fn profile_grid_layout(
    available_width: f32,
    available_height: f32,
    column_spacing: f32,
    row_spacing: f32,
) -> ProfileGridLayout {
    let column_count = profile_column_count(available_width, column_spacing);
    let row_count = VpnKind::ALL.len().div_ceil(column_count);
    let row_spacing = row_spacing.max(0.0);
    let total_row_spacing = row_spacing * row_count.saturating_sub(1) as f32;
    let minimum_total_height = MIN_PROFILE_CARD_HEIGHT * row_count as f32 + total_row_spacing;
    let total_height = available_height.max(0.0).max(minimum_total_height);
    let row_height = (total_height - total_row_spacing) / row_count as f32;

    ProfileGridLayout {
        column_count,
        row_height,
        total_height,
    }
}

fn accent_color(vpn: VpnKind) -> Color32 {
    match vpn {
        VpnKind::FortiClient => Color32::from_rgb(92, 166, 255),
        VpnKind::F5 => Color32::from_rgb(245, 166, 77),
        VpnKind::Ivanti => Color32::from_rgb(174, 126, 239),
    }
}

fn configure_style(context: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(20, 25, 34);
    visuals.window_fill = visuals.panel_fill;
    visuals.extreme_bg_color = Color32::from_rgb(13, 17, 24);
    context.set_visuals(visuals);

    context.style_mut_of(egui::Theme::Dark, |style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
    });
}

fn install_chinese_font(context: &egui::Context) {
    let candidates = [
        (r"C:\Windows\Fonts\msjh.ttc", 0_u32),
        (r"C:\Windows\Fonts\msjhbd.ttc", 0_u32),
        (r"C:\Windows\Fonts\mingliu.ttc", 0_u32),
    ];

    for (path, face_index) in candidates {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };

        let mut fonts = FontDefinitions::default();
        let mut font = FontData::from_owned(bytes);
        font.index = face_index;
        fonts.font_data.insert("zh-tw".to_owned(), Arc::new(font));

        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, "zh-tw".to_owned());
        }
        if let Some(family) = fonts.families.get_mut(&FontFamily::Monospace) {
            family.push("zh-tw".to_owned());
        }

        context.set_fonts(fonts);
        break;
    }
}

fn state_path() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_ID)
        .join("data")
        .join("state.json")
}

fn migrate_legacy_route_purposes(state: &mut PersistedState) {
    for vpn in VpnKind::ALL {
        let Some(lower_half) = state
            .managed_routes
            .iter()
            .find(|route| route.vpn == vpn && route.prefix == "0.0.0.0/1")
            .cloned()
        else {
            continue;
        };
        let Some(upper_half) = state
            .managed_routes
            .iter()
            .find(|route| route.vpn == vpn && route.prefix == "128.0.0.0/1")
        else {
            continue;
        };
        let same_endpoint = lower_half.interface_index == upper_half.interface_index
            && lower_half.next_hop == upper_half.next_hop
            && lower_half.route_metric == upper_half.route_metric;
        let has_target_on_another_endpoint = state.managed_routes.iter().any(|route| {
            route.vpn == vpn
                && route.prefix != "0.0.0.0/1"
                && route.prefix != "128.0.0.0/1"
                && (route.interface_index != lower_half.interface_index
                    || route.next_hop != lower_half.next_hop)
        });

        if same_endpoint && has_target_on_another_endpoint {
            for route in &mut state.managed_routes {
                if route.vpn == vpn
                    && (route.prefix == "0.0.0.0/1" || route.prefix == "128.0.0.0/1")
                {
                    route.purpose = ManagedRoutePurpose::InternetBypass;
                }
            }
        }
    }
}

fn load_state(path: &Path) -> Result<PersistedState, String> {
    if !path.exists() {
        return Ok(PersistedState::default());
    }

    let bytes = fs::read(path).map_err(|error| format!("讀取 {} 失敗：{error}", path.display()))?;
    let mut state: PersistedState = serde_json::from_slice(&bytes)
        .map_err(|error| format!("解析 {} 失敗：{error}", path.display()))?;
    migrate_legacy_route_purposes(&mut state);
    Ok(state)
}

fn save_state(path: &Path, state: &PersistedState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("建立 {} 失敗：{error}", parent.display()))?;
    }

    let json =
        serde_json::to_vec_pretty(state).map_err(|error| format!("序列化設定失敗：{error}"))?;
    fs::write(path, json).map_err(|error| format!("寫入 {} 失敗：{error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(vpn: VpnKind, prefix: &str) -> ManagedRoute {
        ManagedRoute {
            vpn,
            purpose: ManagedRoutePurpose::Target,
            prefix: prefix.to_owned(),
            interface_index: 10,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        }
    }

    fn full_tunnel_app(vpn: VpnKind) -> SplitterApp {
        let (name, description) = match vpn {
            VpnKind::FortiClient => (
                "FortiClient VPN",
                "Fortinet SSL VPN Virtual Ethernet Adapter",
            ),
            VpnKind::F5 => (
                "_Common_SSLVPN-NA_V - sslvpn.example.test",
                "F5 Networks VPN Adapter",
            ),
            VpnKind::Ivanti => ("Ivanti VPN", "Pulse Secure Virtual Adapter"),
        };
        SplitterApp {
            state: PersistedState::default(),
            state_path: PathBuf::new(),
            adapters: vec![NetworkAdapter {
                index: 43,
                name: name.to_owned(),
                description: description.to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 2,
                    effective_metric: 5,
                }),
                dns_servers: Vec::new(),
            }],
            internet_gateway: Some(InternetGateway {
                interface_index: 7,
                interface_alias: "Wi-Fi".to_owned(),
                interface_description: "Physical Wi-Fi Adapter".to_owned(),
                next_hop: "192.0.2.1".to_owned(),
                inferred_from_escape_route: true,
                route_priority: None,
                dns_servers: vec!["192.0.2.53".to_owned()],
                fallback_dns_servers: vec!["192.0.2.53".to_owned()],
            }),
            banner: Banner::Info(String::new()),
            enable_error_dialog: None,
            next_dns_refresh_at: Instant::now(),
            next_route_health_at: Instant::now(),
            next_endpoint_refresh_at: Instant::now(),
            repaint_context: egui::Context::default(),
            pending_operation: None,
            queued_foreground_action: None,
            stale_dns_cleanup_pending: false,
        }
    }

    fn enabled_full_tunnel_config(app: &SplitterApp, vpn: VpnKind) -> SplitterConfig {
        let mut config = SplitterConfig::default();
        let profile = config.profile_mut(vpn).expect("profile exists");
        profile.enabled = true;
        profile.networks = "203.0.113.10/32".to_owned();
        profile.adapter_description = Some(app.adapters[0].description.clone());
        config
    }

    #[derive(Default)]
    struct FakeRouteTable {
        routes: Vec<ManagedRoute>,
    }

    impl FakeRouteTable {
        fn same_windows_route_key(left: &ManagedRoute, right: &ManagedRoute) -> bool {
            left.prefix == right.prefix
                && left.interface_index == right.interface_index
                && left.next_hop == right.next_hop
        }

        fn same_os_route(left: &ManagedRoute, right: &ManagedRoute) -> bool {
            Self::same_windows_route_key(left, right) && left.route_metric == right.route_metric
        }

        fn existing(&self, inventory: &[ManagedRoute]) -> Vec<ManagedRoute> {
            inventory
                .iter()
                .filter(|candidate| {
                    self.routes
                        .iter()
                        .any(|route| Self::same_os_route(route, candidate))
                })
                .cloned()
                .collect()
        }

        fn apply(
            &mut self,
            previous: &[ManagedRoute],
            desired: &[ManagedRoute],
        ) -> Result<(), String> {
            let to_remove = previous
                .iter()
                .filter(|candidate| {
                    !desired
                        .iter()
                        .any(|route| Self::same_os_route(route, candidate))
                })
                .cloned()
                .collect::<Vec<_>>();
            let to_add = desired
                .iter()
                .filter(|candidate| {
                    !previous
                        .iter()
                        .any(|route| Self::same_os_route(route, candidate))
                })
                .cloned()
                .collect::<Vec<_>>();

            if let Some(conflict) = to_add.iter().find(|candidate| {
                self.routes
                    .iter()
                    .any(|route| Self::same_windows_route_key(route, candidate))
            }) {
                return Err(format!(
                    "Instance MSFT_NetRoute already exists: {}",
                    conflict.prefix
                ));
            }

            for removed in &to_remove {
                if let Some(index) = self
                    .routes
                    .iter()
                    .position(|route| Self::same_os_route(route, removed))
                {
                    self.routes.remove(index);
                }
            }
            self.routes.extend(to_add);
            Ok(())
        }

        fn matches(&self, expected: &[ManagedRoute]) -> bool {
            self.routes.len() == expected.len()
                && expected.iter().all(|candidate| {
                    self.routes
                        .iter()
                        .any(|route| Self::same_os_route(route, candidate))
                })
        }
    }

    fn dns_isolation_adapters() -> Vec<NetworkAdapter> {
        vec![
            NetworkAdapter {
                index: 18,
                name: "FortiClient VPN".to_owned(),
                description: "Fortinet SSL VPN Virtual Ethernet Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "10.88.201.4".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 2,
                    effective_metric: 5,
                }),
                dns_servers: vec!["10.1.101.31".to_owned()],
            },
            NetworkAdapter {
                index: 44,
                name: "F5 VPN".to_owned(),
                description: "F5 Networks VPN Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: None,
                dns_servers: vec!["163.21.249.166".to_owned()],
            },
            NetworkAdapter {
                index: 55,
                name: "Ivanti VPN".to_owned(),
                description: "Pulse Secure Virtual Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: None,
                dns_servers: vec!["10.80.0.53".to_owned()],
            },
        ]
    }

    fn physical_gateway() -> InternetGateway {
        InternetGateway {
            interface_index: 7,
            interface_alias: "Wi-Fi".to_owned(),
            interface_description: "Physical Wi-Fi Adapter".to_owned(),
            next_hop: "192.168.0.1".to_owned(),
            inferred_from_escape_route: false,
            route_priority: Some(RoutePriority {
                prefix_length: 0,
                effective_metric: 30,
            }),
            dns_servers: vec!["192.168.0.1".to_owned()],
            fallback_dns_servers: vec!["192.168.0.1".to_owned()],
        }
    }

    #[test]
    fn forticlient_native_quarter_routes_do_not_block_full_tunnel_enable() {
        use std::cell::RefCell;

        let app = full_tunnel_app(VpnKind::FortiClient);
        let config = enabled_full_tunnel_config(&app, VpnKind::FortiClient);
        let native_quarter_routes =
            ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"].map(|prefix| ManagedRoute {
                vpn: VpnKind::FortiClient,
                purpose: ManagedRoutePurpose::InternetBypass,
                prefix: prefix.to_owned(),
                interface_index: 7,
                next_hop: "192.0.2.1".to_owned(),
                route_metric: 0,
            });
        let route_table = RefCell::new(FakeRouteTable {
            routes: native_quarter_routes.to_vec(),
        });

        let applied = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &[],
                active_routes: &[],
                config: &config,
                adapters: &app.adapters,
                internet_gateway: app.internet_gateway.as_ref(),
            },
            |_, hostname, _| panic!("CIDR-only fixture must not resolve {hostname}"),
            |previous, desired| route_table.borrow_mut().apply(previous, desired),
            |_| Ok(false),
        )
        .expect("FortiClient's native /2 routes must not collide with physical bypass routes");

        let bypass_prefixes = applied
            .prepared
            .routes
            .iter()
            .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
            .map(|route| route.prefix.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            bypass_prefixes,
            BTreeSet::from([
                "0.0.0.0/3",
                "32.0.0.0/3",
                "64.0.0.0/3",
                "96.0.0.0/3",
                "128.0.0.0/3",
                "160.0.0.0/3",
                "192.0.0.0/3",
                "224.0.0.0/3",
            ])
        );
        assert!(native_quarter_routes.iter().all(|native| {
            route_table
                .borrow()
                .routes
                .iter()
                .any(|route| FakeRouteTable::same_os_route(route, native))
        }));
    }

    #[test]
    fn enabling_forticlient_pins_its_dns_before_resolving_when_f5_owns_the_10_network() {
        use std::cell::RefCell;

        let adapters = dns_isolation_adapters();
        let gateway = physical_gateway();
        let mut config = SplitterConfig::default();
        {
            let profile = config
                .profile_mut(VpnKind::FortiClient)
                .expect("FortiClient profile exists");
            profile.enabled = true;
            profile.adapter_description = Some(adapters[0].description.clone());
            profile.networks = "sonarqube.twjoin.com".to_owned();
        }
        {
            let profile = config.profile_mut(VpnKind::F5).expect("F5 profile exists");
            profile.enabled = true;
            profile.adapter_description = Some(adapters[1].description.clone());
            profile.networks = "203.0.113.10/32".to_owned();
        }
        let current_routes = vec![ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "203.0.113.10/32".to_owned(),
            interface_index: 44,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        }];
        let route_table = RefCell::new(FakeRouteTable {
            routes: current_routes.clone(),
        });

        let applied = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &current_routes,
                active_routes: &current_routes,
                config: &config,
                adapters: &adapters,
                internet_gateway: Some(&gateway),
            },
            |vpn, hostname, servers| {
                assert_eq!(vpn, VpnKind::FortiClient);
                assert_eq!(hostname, "sonarqube.twjoin.com");
                assert_eq!(servers, ["10.1.101.31"]);
                let dns_is_pinned_to_forticlient =
                    route_table.borrow().routes.iter().any(|route| {
                        route.vpn == VpnKind::FortiClient
                            && route.purpose == ManagedRoutePurpose::VpnDnsServer
                            && route.prefix == "10.1.101.31/32"
                            && route.interface_index == 18
                    });
                if dns_is_pinned_to_forticlient {
                    Ok(vec![Ipv4Addr::new(10, 1, 101, 103)])
                } else {
                    Err("F5 的 10.0.0.0/8 攔截了 FortiClient DNS".to_owned())
                }
            },
            |previous, desired| route_table.borrow_mut().apply(previous, desired),
            |_| Ok(false),
        )
        .expect("the DNS host route must exist before FortiClient resolves its hostname");

        assert!(applied.prepared.routes.contains(&ManagedRoute {
            vpn: VpnKind::FortiClient,
            purpose: ManagedRoutePurpose::Target,
            prefix: "10.1.101.103/32".to_owned(),
            interface_index: 18,
            next_hop: "10.88.201.4".to_owned(),
            route_metric: ROUTE_METRIC,
        }));
        assert!(route_table.borrow().matches(&applied.prepared.routes));
    }

    #[test]
    fn switching_dns_policy_keeps_old_and_new_dns_routes_until_nrpt_commit() {
        use std::cell::RefCell;

        let adapters = dns_isolation_adapters();
        let gateway = physical_gateway();
        let mut config = SplitterConfig::default();
        let forti = config
            .profile_mut(VpnKind::FortiClient)
            .expect("FortiClient profile exists");
        forti.enabled = true;
        forti.adapter_description = Some(adapters[0].description.clone());
        forti.networks = "sonarqube.twjoin.com".to_owned();
        let f5 = config.profile_mut(VpnKind::F5).expect("F5 profile exists");
        f5.enabled = false;
        f5.adapter_description = Some(adapters[1].description.clone());
        f5.networks = "legacy.example.test".to_owned();

        let current_routes = vec![
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::Target,
                prefix: "203.0.113.40/32".to_owned(),
                interface_index: 44,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            },
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::VpnDnsServer,
                prefix: "163.21.249.166/32".to_owned(),
                interface_index: 44,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            },
        ];
        let route_table = RefCell::new(FakeRouteTable {
            routes: current_routes.clone(),
        });

        let applied = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &current_routes,
                active_routes: &current_routes,
                config: &config,
                adapters: &adapters,
                internet_gateway: Some(&gateway),
            },
            |_, _, _| Ok(vec![Ipv4Addr::new(10, 1, 101, 103)]),
            |previous, desired| route_table.borrow_mut().apply(previous, desired),
            |_| {
                let table = route_table.borrow();
                let old_dns_still_works = table.routes.iter().any(|route| {
                    route.vpn == VpnKind::F5
                        && route.purpose == ManagedRoutePurpose::VpnDnsServer
                        && route.prefix == "163.21.249.166/32"
                });
                let new_dns_is_ready = table.routes.iter().any(|route| {
                    route.vpn == VpnKind::FortiClient
                        && route.purpose == ManagedRoutePurpose::VpnDnsServer
                        && route.prefix == "10.1.101.31/32"
                });
                let old_target_is_gone = !table.routes.iter().any(|route| {
                    route.vpn == VpnKind::F5 && route.purpose == ManagedRoutePurpose::Target
                });
                if old_dns_still_works && new_dns_is_ready && old_target_is_gone {
                    Ok(true)
                } else {
                    Err("NRPT 切換前的 DNS 路由或一般目標路由狀態不正確".to_owned())
                }
            },
        )
        .expect("NRPT must switch while both old and new DNS routes remain usable");

        assert!(route_table.borrow().matches(&applied.prepared.routes));
        assert!(
            !applied
                .prepared
                .routes
                .iter()
                .any(|route| route.vpn == VpnKind::F5)
        );
    }

    #[test]
    fn dns_route_conflicts_are_rejected_before_any_network_change() {
        use std::cell::Cell;

        let adapters = dns_isolation_adapters();
        let gateway = physical_gateway();
        let mut config = SplitterConfig::default();
        let forti = config
            .profile_mut(VpnKind::FortiClient)
            .expect("FortiClient profile exists");
        forti.enabled = true;
        forti.adapter_description = Some(adapters[0].description.clone());
        forti.networks = "sonarqube.twjoin.com".to_owned();
        let f5 = config.profile_mut(VpnKind::F5).expect("F5 profile exists");
        f5.enabled = true;
        f5.adapter_description = Some(adapters[1].description.clone());
        f5.networks = "10.1.0.0/16".to_owned();
        let current_routes = vec![ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "10.1.0.0/16".to_owned(),
            interface_index: 44,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        }];
        let route_changes = Cell::new(0);

        let error = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &current_routes,
                active_routes: &current_routes,
                config: &config,
                adapters: &adapters,
                internet_gateway: Some(&gateway),
            },
            |_, _, _| Ok(vec![Ipv4Addr::new(10, 1, 101, 103)]),
            |_, _| {
                route_changes.set(route_changes.get() + 1);
                Ok(())
            },
            |_| Ok(false),
        )
        .expect_err("a VPN DNS server cannot be routed through another VPN target");

        assert!(error.contains("10.1.101.31"), "unexpected error: {error}");
        assert!(error.contains("F5"), "unexpected error: {error}");
        assert_eq!(
            route_changes.get(),
            0,
            "preflight conflicts must not cause a temporary route takeover"
        );
    }

    #[test]
    fn duplicate_hostname_ownership_is_rejected_before_any_network_change() {
        use std::cell::Cell;

        let adapters = dns_isolation_adapters();
        let gateway = physical_gateway();
        let mut config = SplitterConfig::default();
        for (vpn, description) in [
            (VpnKind::FortiClient, adapters[0].description.clone()),
            (VpnKind::F5, adapters[1].description.clone()),
        ] {
            let profile = config.profile_mut(vpn).expect("profile exists");
            profile.enabled = true;
            profile.adapter_description = Some(description);
            profile.networks = "shared.twjoin.internal".to_owned();
        }
        let route_changes = Cell::new(0);

        let error = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &[],
                active_routes: &[],
                config: &config,
                adapters: &adapters,
                internet_gateway: Some(&gateway),
            },
            |vpn, _, _| match vpn {
                VpnKind::FortiClient => Ok(vec![Ipv4Addr::new(10, 1, 101, 103)]),
                VpnKind::F5 => Ok(vec![Ipv4Addr::new(203, 0, 113, 40)]),
                VpnKind::Ivanti => unreachable!(),
            },
            |_, _| {
                route_changes.set(route_changes.get() + 1);
                Ok(())
            },
            |_| Ok(false),
        )
        .expect_err("one hostname cannot be owned by two VPN DNS policies");

        assert!(
            error.contains("shared.twjoin.internal"),
            "unexpected error: {error}"
        );
        assert_eq!(
            route_changes.get(),
            0,
            "ambiguous DNS ownership must fail before bootstrap routes are applied"
        );
    }

    #[test]
    fn dns_refresh_repairs_a_missing_dns_host_route_before_resolving() {
        use std::cell::RefCell;

        let mut app = full_tunnel_app(VpnKind::FortiClient);
        app.adapters[0].dns_servers = vec!["10.1.101.31".to_owned()];
        let mut config = enabled_full_tunnel_config(&app, VpnKind::FortiClient);
        config
            .profile_mut(VpnKind::FortiClient)
            .expect("FortiClient profile exists")
            .networks = "sonarqube.twjoin.com".to_owned();
        let target_route = ManagedRoute {
            vpn: VpnKind::FortiClient,
            purpose: ManagedRoutePurpose::Target,
            prefix: "10.1.101.103/32".to_owned(),
            interface_index: 43,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        };
        let dns_route = ManagedRoute {
            vpn: VpnKind::FortiClient,
            purpose: ManagedRoutePurpose::VpnDnsServer,
            prefix: "10.1.101.31/32".to_owned(),
            interface_index: 43,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        };
        let current_routes = vec![target_route.clone(), dns_route];
        let route_table = RefCell::new(FakeRouteTable {
            routes: vec![target_route],
        });

        let active_routes = route_table.borrow().routes.clone();
        let applied = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &current_routes,
                active_routes: &active_routes,
                config: &config,
                adapters: &app.adapters,
                internet_gateway: app.internet_gateway.as_ref(),
            },
            |_, _, _| {
                if route_table
                    .borrow()
                    .routes
                    .iter()
                    .any(|route| route.prefix == "10.1.101.31/32")
                {
                    Ok(vec![Ipv4Addr::new(10, 1, 101, 103)])
                } else {
                    Err("FortiClient DNS host route is missing".to_owned())
                }
            },
            |previous, desired| route_table.borrow_mut().apply(previous, desired),
            |_| Ok(false),
        )
        .expect("a missing managed DNS route must be repaired before resolution");

        assert!(route_table.borrow().matches(&applied.prepared.routes));
    }

    #[test]
    fn vpn_hostname_never_falls_back_to_another_vpn_or_physical_dns() {
        use std::cell::Cell;

        let mut adapters = dns_isolation_adapters();
        adapters.truncate(2);
        adapters[0].dns_servers.clear();
        let mut gateway = physical_gateway();
        gateway.dns_servers = vec![
            "10.1.101.31".to_owned(),
            "163.21.249.166".to_owned(),
            "192.168.0.1".to_owned(),
        ];
        let mut config = SplitterConfig::default();
        let profile = config
            .profile_mut(VpnKind::FortiClient)
            .expect("FortiClient profile exists");
        profile.enabled = true;
        profile.adapter_description = Some(adapters[0].description.clone());
        profile.networks = "sonarqube.twjoin.com".to_owned();
        let resolution_calls = Cell::new(0);
        let route_changes = Cell::new(0);

        let error = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &[],
                active_routes: &[],
                config: &config,
                adapters: &adapters,
                internet_gateway: Some(&gateway),
            },
            |_, _, _| {
                resolution_calls.set(resolution_calls.get() + 1);
                Ok(vec![Ipv4Addr::new(10, 1, 101, 103)])
            },
            |_, _| {
                route_changes.set(route_changes.get() + 1);
                Ok(())
            },
            |_| Ok(false),
        )
        .expect_err("VPN-owned hostnames require DNS servers from that VPN adapter");

        assert!(error.contains("FortiClient"), "unexpected error: {error}");
        assert!(error.contains("DNS server"), "unexpected error: {error}");
        assert_eq!(resolution_calls.get(), 0);
        assert_eq!(route_changes.get(), 0);
    }

    #[test]
    fn shared_dns_ip_across_enabled_vpns_is_rejected_before_routes_change() {
        use std::cell::Cell;

        let mut adapters = dns_isolation_adapters();
        adapters.truncate(2);
        adapters[0]
            .dns_servers
            .insert(0, "163.21.249.166".to_owned());
        let gateway = physical_gateway();
        let mut config = SplitterConfig::default();
        let forti = config
            .profile_mut(VpnKind::FortiClient)
            .expect("FortiClient profile exists");
        forti.enabled = true;
        forti.adapter_description = Some(adapters[0].description.clone());
        forti.networks = "sonarqube.twjoin.com".to_owned();
        let f5 = config.profile_mut(VpnKind::F5).expect("F5 profile exists");
        f5.enabled = true;
        f5.adapter_description = Some(adapters[1].description.clone());
        f5.networks = "203.0.113.10/32".to_owned();
        let route_changes = Cell::new(0);

        let error = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &[],
                active_routes: &[],
                config: &config,
                adapters: &adapters,
                internet_gateway: Some(&gateway),
            },
            |_, _, _| Ok(vec![Ipv4Addr::new(10, 1, 101, 103)]),
            |_, _| {
                route_changes.set(route_changes.get() + 1);
                Ok(())
            },
            |_| Ok(false),
        )
        .expect_err("one DNS destination cannot be routed through two VPN interfaces");

        assert!(
            error.contains("163.21.249.166"),
            "unexpected error: {error}"
        );
        assert!(error.contains("FortiClient"), "unexpected error: {error}");
        assert!(error.contains("F5"), "unexpected error: {error}");
        assert_eq!(route_changes.get(), 0);
    }

    #[test]
    fn all_three_vpn_dns_policies_are_isolated_in_every_enable_order() {
        use std::cell::RefCell;

        let mut adapters = dns_isolation_adapters();
        adapters[0].full_tunnel_priority = None;
        let gateway = physical_gateway();
        let permutations = [
            [VpnKind::FortiClient, VpnKind::F5, VpnKind::Ivanti],
            [VpnKind::FortiClient, VpnKind::Ivanti, VpnKind::F5],
            [VpnKind::F5, VpnKind::FortiClient, VpnKind::Ivanti],
            [VpnKind::F5, VpnKind::Ivanti, VpnKind::FortiClient],
            [VpnKind::Ivanti, VpnKind::FortiClient, VpnKind::F5],
            [VpnKind::Ivanti, VpnKind::F5, VpnKind::FortiClient],
        ];

        for order in permutations {
            let mut config = SplitterConfig::default();
            for (vpn, description, hostname) in [
                (
                    VpnKind::FortiClient,
                    adapters[0].description.clone(),
                    "forti.example.test",
                ),
                (
                    VpnKind::F5,
                    adapters[1].description.clone(),
                    "f5.example.test",
                ),
                (
                    VpnKind::Ivanti,
                    adapters[2].description.clone(),
                    "ivanti.example.test",
                ),
            ] {
                let profile = config.profile_mut(vpn).expect("profile exists");
                profile.adapter_description = Some(description);
                profile.networks = hostname.to_owned();
            }
            let route_table = RefCell::new(FakeRouteTable::default());
            let mut managed_routes = Vec::new();

            for enabled_vpn in order {
                config
                    .profile_mut(enabled_vpn)
                    .expect("profile exists")
                    .enabled = true;
                let active_routes = route_table.borrow().routes.clone();
                let applied = apply_policy_transaction_with(
                    PolicyTransactionInput {
                        managed_routes: &managed_routes,
                        active_routes: &active_routes,
                        config: &config,
                        adapters: &adapters,
                        internet_gateway: Some(&gateway),
                    },
                    |vpn, _, _| {
                        let (dns_prefix, interface_index, address) = match vpn {
                            VpnKind::FortiClient => {
                                ("10.1.101.31/32", 18, Ipv4Addr::new(198, 51, 100, 11))
                            }
                            VpnKind::F5 => {
                                ("163.21.249.166/32", 44, Ipv4Addr::new(203, 0, 113, 12))
                            }
                            VpnKind::Ivanti => ("10.80.0.53/32", 55, Ipv4Addr::new(192, 0, 2, 13)),
                        };
                        let dns_is_isolated = route_table.borrow().routes.iter().any(|route| {
                            route.vpn == vpn
                                && route.purpose == ManagedRoutePurpose::VpnDnsServer
                                && route.prefix == dns_prefix
                                && route.interface_index == interface_index
                        });
                        if dns_is_isolated {
                            Ok(vec![address])
                        } else {
                            Err(format!("{vpn} DNS was not pinned before resolution"))
                        }
                    },
                    |previous, desired| route_table.borrow_mut().apply(previous, desired),
                    |_| Ok(false),
                )
                .unwrap_or_else(|error| panic!("enable order {order:?} failed: {error}"));
                managed_routes = applied.prepared.routes;
            }

            for (vpn, prefix, interface_index) in [
                (VpnKind::FortiClient, "10.1.101.31/32", 18),
                (VpnKind::F5, "163.21.249.166/32", 44),
                (VpnKind::Ivanti, "10.80.0.53/32", 55),
            ] {
                assert!(
                    managed_routes.iter().any(|route| {
                        route.vpn == vpn
                            && route.purpose == ManagedRoutePurpose::VpnDnsServer
                            && route.prefix == prefix
                            && route.interface_index == interface_index
                    }),
                    "missing isolated DNS route for {vpn} in order {order:?}"
                );
            }
        }
    }

    #[test]
    fn failed_resolution_restores_original_routes_without_touching_nrpt() {
        use std::cell::{Cell, RefCell};

        let mut app = full_tunnel_app(VpnKind::FortiClient);
        app.adapters[0].dns_servers = vec!["10.1.101.31".to_owned()];
        let mut config = enabled_full_tunnel_config(&app, VpnKind::FortiClient);
        config
            .profile_mut(VpnKind::FortiClient)
            .expect("FortiClient profile exists")
            .networks = "missing.twjoin.internal".to_owned();
        let original_routes = vec![ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "203.0.113.10/32".to_owned(),
            interface_index: 44,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        }];
        let route_table = RefCell::new(FakeRouteTable {
            routes: original_routes.clone(),
        });
        let dns_policy_changes = Cell::new(0);

        let error = apply_policy_transaction_with(
            PolicyTransactionInput {
                managed_routes: &original_routes,
                active_routes: &original_routes,
                config: &config,
                adapters: &app.adapters,
                internet_gateway: app.internet_gateway.as_ref(),
            },
            |_, _, _| {
                assert!(
                    route_table
                        .borrow()
                        .routes
                        .iter()
                        .any(|route| route.prefix == "10.1.101.31/32")
                );
                Err("authoritative DNS returned NXDOMAIN".to_owned())
            },
            |previous, desired| route_table.borrow_mut().apply(previous, desired),
            |_| {
                dns_policy_changes.set(dns_policy_changes.get() + 1);
                Ok(true)
            },
        )
        .expect_err("failed resolution must abort the policy transaction");

        assert!(error.contains("NXDOMAIN"), "unexpected error: {error}");
        assert!(route_table.borrow().matches(&original_routes));
        assert_eq!(dns_policy_changes.get(), 0);
    }

    struct LifecycleHarness {
        app_open: bool,
        state: PersistedState,
        table: FakeRouteTable,
        adapters: Vec<NetworkAdapter>,
        gateway: InternetGateway,
    }

    impl LifecycleHarness {
        fn new(initial_full_tunnel: VpnKind) -> Self {
            let adapters = vec![
                NetworkAdapter {
                    index: 41,
                    name: "FortiClient VPN".to_owned(),
                    description: "Fortinet SSL VPN Virtual Ethernet Adapter".to_owned(),
                    status: "Up".to_owned(),
                    next_hop: "0.0.0.0".to_owned(),
                    full_tunnel_priority: (initial_full_tunnel == VpnKind::FortiClient).then_some(
                        RoutePriority {
                            prefix_length: 2,
                            effective_metric: 5,
                        },
                    ),
                    dns_servers: vec!["10.10.0.53".to_owned()],
                },
                NetworkAdapter {
                    index: 42,
                    name: "F5 VPN".to_owned(),
                    description: "F5 Networks VPN Adapter".to_owned(),
                    status: "Up".to_owned(),
                    next_hop: "0.0.0.0".to_owned(),
                    full_tunnel_priority: (initial_full_tunnel == VpnKind::F5).then_some(
                        RoutePriority {
                            prefix_length: 2,
                            effective_metric: 5,
                        },
                    ),
                    dns_servers: vec!["10.20.0.53".to_owned()],
                },
                NetworkAdapter {
                    index: 43,
                    name: "Ivanti VPN".to_owned(),
                    description: "Pulse Secure Virtual Adapter".to_owned(),
                    status: "Up".to_owned(),
                    next_hop: "0.0.0.0".to_owned(),
                    full_tunnel_priority: (initial_full_tunnel == VpnKind::Ivanti).then_some(
                        RoutePriority {
                            prefix_length: 2,
                            effective_metric: 5,
                        },
                    ),
                    dns_servers: vec!["10.30.0.53".to_owned()],
                },
            ];
            let mut state = PersistedState::default();
            for (vpn, description, network) in [
                (
                    VpnKind::FortiClient,
                    "Fortinet SSL VPN Virtual Ethernet Adapter",
                    "10.10.0.0/16",
                ),
                (VpnKind::F5, "F5 Networks VPN Adapter", "10.20.0.0/16"),
                (
                    VpnKind::Ivanti,
                    "Pulse Secure Virtual Adapter",
                    "10.30.0.0/16",
                ),
            ] {
                let profile = state.config.profile_mut(vpn).expect("profile exists");
                profile.adapter_description = Some(description.to_owned());
                profile.networks = network.to_owned();
            }

            Self {
                app_open: true,
                state,
                table: FakeRouteTable::default(),
                adapters,
                gateway: InternetGateway {
                    interface_index: 7,
                    interface_alias: "Wi-Fi".to_owned(),
                    interface_description: "Physical Wi-Fi Adapter".to_owned(),
                    next_hop: "192.0.2.1".to_owned(),
                    inferred_from_escape_route: false,
                    route_priority: Some(RoutePriority {
                        prefix_length: 0,
                        effective_metric: 30,
                    }),
                    dns_servers: vec!["192.0.2.53".to_owned()],
                    fallback_dns_servers: vec!["192.0.2.53".to_owned()],
                },
            }
        }

        fn toggle_profile(&mut self, vpn: VpnKind) {
            if !self.app_open {
                return;
            }
            let enabled = !self
                .state
                .config
                .profile(vpn)
                .expect("profile exists")
                .enabled;
            let mut next_config = self.state.config.clone();
            next_config
                .profile_mut(vpn)
                .expect("profile exists")
                .enabled = enabled;
            let Ok(prepared) =
                prepare_all_enabled_routes_for(&next_config, &self.adapters, Some(&self.gateway))
            else {
                return;
            };
            let desired = prepared.routes;
            if self
                .table
                .apply(&self.state.managed_routes, &desired)
                .is_ok()
            {
                self.state.config = next_config;
                self.state.managed_routes = desired;
            }
        }

        fn health_check(&mut self) -> Result<(), String> {
            if !self.app_open {
                return Ok(());
            }
            let current = self.state.managed_routes.clone();
            let existing = self.table.existing(&current);
            let outcome = evaluate_route_health_with(
                current,
                self.state.config.clone(),
                existing,
                self.adapters.clone(),
                Some(self.gateway.clone()),
                |previous, desired| self.table.apply(previous, desired),
                |_| Ok(false),
            );
            match outcome {
                RouteHealthOutcome::Healthy => Ok(()),
                RouteHealthOutcome::Updated { config, routes, .. } => {
                    self.state.config = config;
                    self.state.managed_routes = routes;
                    Ok(())
                }
                RouteHealthOutcome::Failed(error) => Err(error),
            }
        }

        fn set_vpn_connected(&mut self, vpn: VpnKind, connected: bool) {
            let adapter = self
                .adapters
                .iter_mut()
                .find(|adapter| adapter.matches(vpn))
                .expect("adapter exists");
            let was_connected = adapter.is_up();
            let old_index = adapter.index;
            adapter.status = if connected { "Up" } else { "Disconnected" }.to_owned();
            if connected && !was_connected {
                adapter.index += 100;
            }
            if !connected {
                self.table
                    .routes
                    .retain(|route| route.interface_index != old_index);
            }
        }

        fn flip_vpn_connection(&mut self, vpn: VpnKind) {
            let connected = !self
                .adapters
                .iter()
                .find(|adapter| adapter.matches(vpn))
                .expect("adapter exists")
                .is_up();
            self.set_vpn_connected(vpn, connected);
        }

        fn flip_full_tunnel(&mut self, vpn: VpnKind) {
            let adapter = self
                .adapters
                .iter_mut()
                .find(|adapter| adapter.matches(vpn))
                .expect("adapter exists");
            adapter.full_tunnel_priority = if adapter.full_tunnel_priority.is_some() {
                None
            } else {
                Some(RoutePriority {
                    prefix_length: 2,
                    effective_metric: 5,
                })
            };
        }

        fn change_gateway(&mut self) {
            self.gateway.interface_index = if self.gateway.interface_index == 7 {
                107
            } else {
                7
            };
            self.gateway.next_hop = if self.gateway.next_hop == "192.0.2.1" {
                "192.0.2.254".to_owned()
            } else {
                "192.0.2.1".to_owned()
            };
        }

        fn drop_managed_route(&mut self, from_end: bool) {
            if self.table.routes.is_empty() {
                return;
            }
            let index = if from_end {
                self.table.routes.len() - 1
            } else {
                0
            };
            self.table.routes.remove(index);
        }

        fn graceful_close(&mut self) -> Result<(), String> {
            if !self.app_open {
                return Ok(());
            }
            cleanup_managed_routes_with(&mut self.state, |inventory| {
                self.table.apply(inventory, &[])
            })?;
            self.app_open = false;
            if !self.table.routes.is_empty() {
                return Err("graceful close left managed routes in ActiveStore".to_owned());
            }
            Ok(())
        }

        fn crash(&mut self) {
            self.app_open = false;
        }

        fn power_cycle(&mut self) {
            self.app_open = false;
            self.table.routes.clear();
        }

        fn open(&mut self) -> Result<(), String> {
            if self.app_open {
                return Ok(());
            }
            disable_all_profiles(&mut self.state);
            let previous = self.state.managed_routes.clone();
            let existing = self.table.existing(&previous);
            let reconciled = reconciled_routes_for_config(&previous, &existing, &self.state.config);
            self.table.apply(&existing, &reconciled)?;
            self.state.managed_routes = reconciled;
            self.app_open = true;
            self.assert_stable()
        }

        fn assert_stable(&self) -> Result<(), String> {
            if !self.app_open {
                return Err("stable assertion requires an open app".to_owned());
            }
            if !self.table.matches(&self.state.managed_routes) {
                return Err(format!(
                    "state/ActiveStore mismatch: state={:?}, active={:?}",
                    self.state.managed_routes, self.table.routes
                ));
            }

            let internet_bypass_owner =
                enabled_full_tunnel_vpns(&self.state.config, &self.adapters)
                    .first()
                    .copied();
            let internet_fallback =
                select_internet_fallback(&self.state.config, &self.adapters, Some(&self.gateway));

            for vpn in VpnKind::ALL {
                let profile = self.state.config.profile(vpn).expect("profile exists");
                let vpn_routes = self
                    .state
                    .managed_routes
                    .iter()
                    .filter(|route| route.vpn == vpn)
                    .collect::<Vec<_>>();
                if !profile.enabled {
                    if !vpn_routes.is_empty() {
                        return Err(format!("disabled {vpn} still owns managed routes"));
                    }
                    continue;
                }

                let adapter = self
                    .adapters
                    .iter()
                    .find(|adapter| adapter.matches(vpn) && adapter.is_up())
                    .ok_or_else(|| format!("enabled {vpn} has no connected adapter"))?;
                let targets = vpn_routes
                    .iter()
                    .filter(|route| route.purpose == ManagedRoutePurpose::Target)
                    .collect::<Vec<_>>();
                if targets.is_empty()
                    || targets.iter().any(|route| {
                        route.interface_index != adapter.index || route.next_hop != adapter.next_hop
                    })
                {
                    return Err(format!("{vpn} target routes use a stale VPN endpoint"));
                }
                let bypasses = vpn_routes
                    .iter()
                    .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
                    .collect::<Vec<_>>();
                if Some(vpn) == internet_bypass_owner {
                    let fallback = internet_fallback
                        .ok_or_else(|| format!("{vpn} has no unmatched-traffic fallback"))?;
                    if bypasses.len() != INTERNET_BYPASS_PREFIXES.len()
                        || bypasses.iter().any(|route| {
                            route.interface_index != fallback.interface_index()
                                || route.next_hop != fallback.next_hop()
                        })
                    {
                        return Err(format!("{vpn} has incomplete or stale internet bypasses"));
                    }
                } else if !bypasses.is_empty() {
                    return Err(format!("{vpn} unexpectedly owns shared internet bypasses"));
                }
            }
            Ok(())
        }

        fn apply_event(&mut self, event: usize) -> Result<&'static str, String> {
            let name = match event {
                0 => {
                    self.toggle_profile(VpnKind::FortiClient);
                    "toggle_forticlient"
                }
                1 => {
                    self.toggle_profile(VpnKind::F5);
                    "toggle_f5"
                }
                2 => {
                    self.toggle_profile(VpnKind::Ivanti);
                    "toggle_ivanti"
                }
                3 => {
                    self.flip_vpn_connection(VpnKind::FortiClient);
                    "flip_forticlient_connection"
                }
                4 => {
                    self.flip_vpn_connection(VpnKind::F5);
                    "flip_f5_connection"
                }
                5 => {
                    self.flip_vpn_connection(VpnKind::Ivanti);
                    "flip_ivanti_connection"
                }
                6 => {
                    self.flip_full_tunnel(VpnKind::FortiClient);
                    "flip_forticlient_tunnel_mode"
                }
                7 => {
                    self.flip_full_tunnel(VpnKind::F5);
                    "flip_f5_tunnel_mode"
                }
                8 => {
                    self.flip_full_tunnel(VpnKind::Ivanti);
                    "flip_ivanti_tunnel_mode"
                }
                9 => {
                    self.drop_managed_route(false);
                    "drop_first_managed_route"
                }
                10 => {
                    self.drop_managed_route(true);
                    "drop_last_managed_route"
                }
                11 => {
                    self.change_gateway();
                    "change_physical_gateway"
                }
                12 => {
                    self.health_check()?;
                    if self.app_open {
                        self.assert_stable()?;
                    }
                    "route_health_check"
                }
                13 => {
                    self.graceful_close()?;
                    "graceful_close"
                }
                14 => {
                    self.open()?;
                    "open"
                }
                15 => {
                    self.crash();
                    "process_crash"
                }
                16 => {
                    self.power_cycle();
                    "power_cycle"
                }
                17 => {
                    self.graceful_close()?;
                    self.open()?;
                    "graceful_restart"
                }
                18 => {
                    self.crash();
                    self.open()?;
                    "crash_recovery"
                }
                _ => unreachable!("event code is bounded"),
            };
            Ok(name)
        }
    }

    #[test]
    fn lifecycle_scenarios_cover_app_vpn_and_split_tunnel_orderings() {
        for vpn in VpnKind::ALL {
            let mut harness = LifecycleHarness::new(vpn);

            // The VPN is already connected when the app enables split tunneling.
            harness.toggle_profile(vpn);
            harness.health_check().expect("initial health check");
            harness.assert_stable().expect("initial enabled state");

            // The VPN can disappear and rebuild its RAS interface while the app stays open.
            let old_index = harness
                .adapters
                .iter()
                .find(|adapter| adapter.matches(vpn))
                .expect("adapter exists")
                .index;
            harness.set_vpn_connected(vpn, false);
            harness.health_check().expect("disconnect health check");
            assert!(
                !harness
                    .state
                    .config
                    .profile(vpn)
                    .expect("profile exists")
                    .enabled,
                "{vpn} must be disabled after it disconnects"
            );
            harness.assert_stable().expect("disconnected state");

            harness.set_vpn_connected(vpn, true);
            let new_index = harness
                .adapters
                .iter()
                .find(|adapter| adapter.matches(vpn))
                .expect("adapter exists")
                .index;
            assert_ne!(old_index, new_index, "reconnect must model a new interface");
            harness.toggle_profile(vpn);
            harness.health_check().expect("reconnect health check");
            harness.assert_stable().expect("reconnected state");

            // Repeated user toggles must add and remove every owned route cleanly.
            harness.toggle_profile(vpn);
            harness.assert_stable().expect("disabled toggle state");
            harness.toggle_profile(vpn);
            harness.health_check().expect("re-enabled health check");
            harness.assert_stable().expect("re-enabled state");

            // External route, tunnel-mode, and physical-gateway changes must self-repair.
            harness.drop_managed_route(false);
            harness.health_check().expect("deleted route repair");
            harness.assert_stable().expect("repaired route state");
            harness.flip_full_tunnel(vpn);
            harness.health_check().expect("Full-to-Split transition");
            harness.assert_stable().expect("Split Tunnel state");
            harness.flip_full_tunnel(vpn);
            harness.change_gateway();
            harness.health_check().expect("Split-to-Full transition");
            harness.assert_stable().expect("new physical gateway state");

            // Closing and reopening while the VPN remains connected leaves no stale routes.
            harness.graceful_close().expect("graceful close");
            assert!(
                harness.table.routes.is_empty(),
                "close must remove all routes"
            );
            harness.open().expect("open over an already connected VPN");
            harness.assert_stable().expect("reopened state");

            // An abnormal exit can leave ActiveStore routes, but the next launch must recover.
            harness.toggle_profile(vpn);
            assert!(
                !harness.table.routes.is_empty(),
                "enabled profile has routes"
            );
            harness.crash();
            assert!(
                !harness.table.routes.is_empty(),
                "the harness must model routes surviving a process crash"
            );
            harness.open().expect("crash recovery launch");
            harness.assert_stable().expect("crash recovery state");

            // A reboot drops ActiveStore routes while persisted inventory survives.
            harness.toggle_profile(vpn);
            harness.power_cycle();
            assert!(harness.table.routes.is_empty(), "reboot clears ActiveStore");
            harness.open().expect("post-reboot launch");
            harness.assert_stable().expect("post-reboot state");
            harness.graceful_close().expect("final close");
        }
    }

    #[test]
    fn lifecycle_state_machine_converges_for_deterministic_event_sequences() {
        const SEEDS_PER_VPN: u64 = 256;
        const STEPS_PER_SEED: usize = 96;

        for (vpn_number, initial_full_tunnel) in VpnKind::ALL.into_iter().enumerate() {
            for seed in 0..SEEDS_PER_VPN {
                let mut harness = LifecycleHarness::new(initial_full_tunnel);
                let mut random = seed
                    .wrapping_add((vpn_number as u64 + 1) << 32)
                    .wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut recent_trace = Vec::new();

                for step in 0..STEPS_PER_SEED {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    let event = (random % 19) as usize;
                    match harness.apply_event(event) {
                        Ok(name) => {
                            recent_trace.push(format!("{step}:{name}"));
                            if recent_trace.len() > 32 {
                                recent_trace.remove(0);
                            }
                        }
                        Err(error) => panic!(
                            "state-machine event failed: initial_full_tunnel={initial_full_tunnel}, seed={seed}, step={step}, event={event}, error={error}, recent_trace={recent_trace:?}"
                        ),
                    }
                }

                if !harness.app_open {
                    harness.open().unwrap_or_else(|error| {
                        panic!(
                            "final recovery launch failed: initial_full_tunnel={initial_full_tunnel}, seed={seed}, error={error}, recent_trace={recent_trace:?}"
                        )
                    });
                }
                harness.health_check().unwrap_or_else(|error| {
                    panic!(
                        "final health check failed: initial_full_tunnel={initial_full_tunnel}, seed={seed}, error={error}, recent_trace={recent_trace:?}"
                    )
                });
                harness.assert_stable().unwrap_or_else(|error| {
                    panic!(
                        "final state did not converge: initial_full_tunnel={initial_full_tunnel}, seed={seed}, error={error}, recent_trace={recent_trace:?}"
                    )
                });
                harness.graceful_close().unwrap_or_else(|error| {
                    panic!(
                        "final close failed: initial_full_tunnel={initial_full_tunnel}, seed={seed}, error={error}, recent_trace={recent_trace:?}"
                    )
                });
                assert!(
                    harness.table.routes.is_empty(),
                    "final close left routes: initial_full_tunnel={initial_full_tunnel}, seed={seed}, recent_trace={recent_trace:?}"
                );
            }
        }
    }

    fn collect_shape_text(shape: &egui::epaint::Shape, output: &mut Vec<String>) {
        match shape {
            egui::epaint::Shape::Text(text) => output.push(text.galley.job.text.clone()),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect_shape_text(shape, output);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn requesting_adapter_refresh_does_not_block_the_ui_thread() {
        let mut app = full_tunnel_app(VpnKind::F5);
        let started = Instant::now();

        app.refresh_adapters();

        assert!(
            started.elapsed() < Duration::from_millis(100),
            "starting VPN detection must return immediately instead of waiting for PowerShell"
        );
    }

    #[test]
    fn periodic_background_operations_do_not_block_the_visible_interface() {
        assert!(!OperationKind::RouteHealth.blocks_user_interface());
        assert!(!OperationKind::RefreshDns.blocks_user_interface());
        assert!(OperationKind::RefreshAdapters.blocks_user_interface());
        assert!(
            OperationKind::ToggleProfile {
                vpn: VpnKind::F5,
                enabled: true,
            }
            .blocks_user_interface()
        );
    }

    #[test]
    fn unchanged_background_dns_refresh_does_not_replace_the_visible_banner() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.banner = Banner::Success("keep this result visible".to_owned());

        app.start_operation(OperationKind::RefreshDns, |_| {
            OperationResult::RefreshDns(DnsRefreshOutcome::Unchanged)
        });

        assert!(matches!(
            &app.banner,
            Banner::Success(message) if message == "keep this result visible"
        ));
    }

    #[test]
    fn cidr_only_profiles_do_not_schedule_dns_refreshes() {
        let mut config = SplitterConfig::default();
        {
            let profile = config.profile_mut(VpnKind::F5).expect("F5 profile exists");
            profile.enabled = true;
            profile.networks = "203.0.113.10/32".to_owned();
        }

        assert!(!should_schedule_dns_refresh(&config));

        config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists")
            .networks = "vpn.example.test".to_owned();
        assert!(should_schedule_dns_refresh(&config));
    }

    #[test]
    fn foreground_toggle_is_queued_while_route_health_is_finishing() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.pending_operation = Some(PendingOperation::spawn(
            OperationKind::RouteHealth,
            app.repaint_context.clone(),
            |_| OperationResult::RouteHealth(RouteHealthOutcome::Healthy),
        ));
        assert!(
            !app.user_interface_busy(),
            "periodic route health must stay visually silent"
        );

        app.set_profile_enabled(VpnKind::F5, true);

        assert_eq!(
            app.queued_foreground_action,
            Some(QueuedForegroundAction::ToggleProfile {
                vpn: VpnKind::F5,
                enabled: true,
            })
        );
        assert!(
            app.user_interface_busy(),
            "a user-requested action may show progress while it waits"
        );

        for _ in 0..100 {
            app.poll_background_operation();
            if app.pending_operation.as_ref().is_some_and(|pending| {
                pending.kind
                    == OperationKind::ToggleProfile {
                        vpn: VpnKind::F5,
                        enabled: true,
                    }
            }) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            app.pending_operation.as_ref().is_some_and(|pending| {
                pending.kind
                    == OperationKind::ToggleProfile {
                        vpn: VpnKind::F5,
                        enabled: true,
                    }
            }),
            "the queued foreground toggle must start as soon as route health finishes"
        );
        assert!(app.queued_foreground_action.is_none());
    }

    #[test]
    fn route_health_update_preserves_fields_edited_during_the_check() {
        let mut app = full_tunnel_app(VpnKind::F5);
        let profile = app
            .state
            .config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists");
        profile.enabled = true;
        profile.networks = "edited-while-health-runs.example.test".to_owned();
        let mut stale_health_config = app.state.config.clone();
        let stale_profile = stale_health_config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists");
        stale_profile.enabled = false;
        stale_profile.networks = "stale-snapshot.example.test".to_owned();

        app.finish_route_health(RouteHealthOutcome::Updated {
            config: stale_health_config,
            routes: Vec::new(),
            adapters: app.adapters.clone(),
            internet_gateway: app.internet_gateway.clone().map(Box::new),
            repaired: false,
            disabled_vpns: vec![VpnKind::F5],
            warnings: vec!["F5 disconnected".to_owned()],
        });

        let profile = app
            .state
            .config
            .profile(VpnKind::F5)
            .expect("F5 profile exists");
        assert!(
            !profile.enabled,
            "health check must still disable a lost VPN"
        );
        assert_eq!(
            profile.networks, "edited-while-health-runs.example.test",
            "a background snapshot must not overwrite live UI edits"
        );
    }

    #[test]
    fn enabled_profile_renders_disable_split_tunnel_label() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.state
            .config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists")
            .enabled = true;
        let context = egui::Context::default();

        let output = context.run_ui(egui::RawInput::default(), |ui| {
            app.profile_card(ui, VpnKind::F5, MIN_PROFILE_CARD_HEIGHT);
        });
        let mut rendered_text = Vec::new();
        for clipped in &output.shapes {
            collect_shape_text(&clipped.shape, &mut rendered_text);
        }
        assert!(
            rendered_text.iter().any(|text| text == "停用分流"),
            "enabled profile must render 停用分流; rendered text: {rendered_text:?}"
        );
    }

    #[test]
    fn long_target_list_keeps_profile_card_within_compact_height() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.state
            .config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists")
            .networks = (1..=40)
            .map(|host| format!("203.0.113.{host}"))
            .collect::<Vec<_>>()
            .join("\n");
        let context = egui::Context::default();
        let mut card_height = 0.0;

        let _ = context.run_ui(egui::RawInput::default(), |ui| {
            ui.set_width(360.0);
            let card_top = ui.cursor().top();
            app.profile_card(ui, VpnKind::F5, MIN_PROFILE_CARD_HEIGHT);
            card_height = ui.min_rect().bottom() - card_top;
        });

        assert!(
            card_height <= 520.0,
            "a long target list must scroll inside the editor instead of growing the card; rendered height was {card_height}"
        );
    }

    #[test]
    fn profile_grid_reflows_at_card_width_breakpoints() {
        let spacing = 8.0;
        let two_column_breakpoint = MIN_PROFILE_CARD_WIDTH * 2.0 + spacing;
        let three_column_breakpoint = MIN_PROFILE_CARD_WIDTH * 3.0 + spacing * 2.0;

        assert_eq!(
            profile_column_count(two_column_breakpoint - 1.0, spacing),
            1
        );
        assert_eq!(profile_column_count(two_column_breakpoint, spacing), 2);
        assert_eq!(
            profile_column_count(three_column_breakpoint - 1.0, spacing),
            2
        );
        assert_eq!(profile_column_count(three_column_breakpoint, spacing), 3);
        assert_eq!(profile_column_count(10_000.0, spacing), 3);
    }

    #[test]
    fn profile_grid_fills_height_without_shrinking_rows_below_card_minimum() {
        let spacing = 8.0;
        let available_height = 1_200.0;

        for (width, expected_columns) in [(339.0, 1), (688.0, 2), (1_036.0, 3)] {
            let layout = profile_grid_layout(width, available_height, spacing, spacing);
            let row_count = VpnKind::ALL.len().div_ceil(expected_columns);
            let filled_height =
                layout.row_height * row_count as f32 + spacing * (row_count - 1) as f32;

            assert_eq!(layout.column_count, expected_columns);
            assert!((filled_height - available_height).abs() < f32::EPSILON);
            assert_eq!(layout.total_height, available_height);
        }

        let short = profile_grid_layout(1_036.0, 200.0, spacing, spacing);
        assert_eq!(short.column_count, 3);
        assert_eq!(short.row_height, MIN_PROFILE_CARD_HEIGHT);
        assert_eq!(short.total_height, MIN_PROFILE_CARD_HEIGHT);
    }

    #[test]
    fn profile_grid_reserves_the_shared_spacing_above_the_status_bar() {
        let viewport_height = 720.0;
        let occupied_height = 120.0;
        let spacing = 8.0;
        let grid_height = profile_grid_available_height(viewport_height, occupied_height, spacing);
        let layout = profile_grid_layout(1_036.0, grid_height, spacing, spacing);

        assert_eq!(layout.column_count, 3);
        assert_eq!(
            occupied_height + layout.total_height + spacing,
            viewport_height
        );
    }

    #[test]
    fn background_busy_indicator_does_not_request_continuous_repaint() {
        let mut app = full_tunnel_app(VpnKind::F5);
        let context = egui::Context::default();
        let input = egui::RawInput {
            focused: false,
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1_000.0, 700.0),
            )),
            ..Default::default()
        };
        let mut output = None;

        for _ in 0..4 {
            output = Some(context.run_ui(input.clone(), |ui| {
                ui.set_width(1_000.0);
                app.refresh_controls(ui, true);
            }));
        }

        let repaint_delay = output
            .expect("busy controls must render")
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .expect("root viewport output exists")
            .repaint_delay;
        assert_ne!(
            repaint_delay,
            Duration::ZERO,
            "a background progress indicator must not repaint as fast as possible"
        );
    }

    #[test]
    fn enable_failure_is_rendered_as_a_modal_dialog() {
        let mut app = full_tunnel_app(VpnKind::F5);
        let expected_error = "測試用路由建立失敗";
        app.finish_toggle(ToggleOutcome::Failed {
            attempted_enabled: true,
            error: expected_error.to_owned(),
        });
        let context = egui::Context::default();
        let mut frame = eframe::Frame::_new_kittest();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1_000.0, 700.0),
            )),
            ..Default::default()
        };

        let _ = context.run_ui(input.clone(), |ui| {
            ui.set_width(1_000.0);
            ui.set_height(700.0);
            eframe::App::ui(&mut app, ui, &mut frame);
        });
        let output = context.run_ui(input, |ui| {
            ui.set_width(1_000.0);
            ui.set_height(700.0);
            eframe::App::ui(&mut app, ui, &mut frame);
        });
        let mut rendered_text = Vec::new();
        for clipped in &output.shapes {
            collect_shape_text(&clipped.shape, &mut rendered_text);
        }
        assert!(
            rendered_text.iter().any(|text| text == "啟用分流失敗"),
            "the modal must explain that enabling failed; rendered text: {rendered_text:?}"
        );
        assert!(
            rendered_text.iter().any(|text| text == expected_error),
            "the modal must include the actual failure reason; rendered text: {rendered_text:?}"
        );
        assert!(
            rendered_text.iter().any(|text| text == "確定"),
            "the modal must provide an explicit dismiss button; rendered text: {rendered_text:?}"
        );
    }

    #[test]
    fn crashed_enable_worker_is_rendered_as_a_modal_dialog() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.start_operation(
            OperationKind::ToggleProfile {
                vpn: VpnKind::F5,
                enabled: true,
            },
            |_| panic!("simulated enable worker crash"),
        );

        for _ in 0..100 {
            app.poll_background_operation();
            if app.pending_operation.is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            app.pending_operation.is_none(),
            "the crashed background worker must be collected"
        );

        let context = egui::Context::default();
        let mut frame = eframe::Frame::_new_kittest();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1_000.0, 700.0),
            )),
            ..Default::default()
        };
        let _ = context.run_ui(input.clone(), |ui| {
            ui.set_width(1_000.0);
            ui.set_height(700.0);
            eframe::App::ui(&mut app, ui, &mut frame);
        });
        let output = context.run_ui(input, |ui| {
            ui.set_width(1_000.0);
            ui.set_height(700.0);
            eframe::App::ui(&mut app, ui, &mut frame);
        });
        let mut rendered_text = Vec::new();
        for clipped in &output.shapes {
            collect_shape_text(&clipped.shape, &mut rendered_text);
        }

        assert!(
            rendered_text.iter().any(|text| text == "啟用分流失敗"),
            "an unexpected enable worker failure must use the same modal; rendered text: {rendered_text:?}"
        );
        assert!(
            rendered_text
                .iter()
                .any(|text| text.contains("背景網路工作異常終止")),
            "the modal must preserve the unexpected worker failure reason; rendered text: {rendered_text:?}"
        );
    }

    #[test]
    fn closing_during_pending_adapter_refresh_cancels_detection_before_joining() {
        let mut app = full_tunnel_app(VpnKind::F5);
        let (worker_ready_sender, worker_ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (cancellation_sender, cancellation_receiver) = mpsc::channel();
        app.pending_operation = Some(PendingOperation::spawn(
            OperationKind::RefreshAdapters,
            app.repaint_context.clone(),
            move |cancellation| {
                worker_ready_sender
                    .send(())
                    .expect("test worker announces that detection has started");
                let cancelled = loop {
                    if cancellation.load(Ordering::Acquire) {
                        break true;
                    }
                    match release_receiver.recv_timeout(Duration::from_millis(1)) {
                        Ok(()) => break false,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break false,
                    }
                };
                cancellation_sender
                    .send(cancelled)
                    .expect("test records whether shutdown cancelled detection");
                OperationResult::Refresh(RefreshOutcome {
                    route_notice: Ok(ReconciledRoutes {
                        routes: Vec::new(),
                        removed: 0,
                    }),
                    dns_notice: Ok(false),
                    gateway_notice: Ok(None),
                    adapter_notice: Ok(Vec::new()),
                })
            },
        ));
        worker_ready_receiver
            .recv()
            .expect("pending adapter detection must start");

        let (drop_finished_sender, drop_finished_receiver) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(app);
            drop_finished_sender
                .send(())
                .expect("test observes app shutdown completion");
        });
        let detection_was_cancelled =
            match cancellation_receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(cancelled) => cancelled,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    release_sender
                        .send(())
                        .expect("test releases detection if shutdown did not cancel it");
                    cancellation_receiver
                        .recv()
                        .expect("released detection must report its shutdown state")
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("detection worker ended without reporting its shutdown state")
                }
            };
        drop_finished_receiver
            .recv()
            .expect("shutdown must finish after cancelling detection and cleaning DNS policy");
        dropper.join().expect("shutdown thread must finish");

        assert!(
            detection_was_cancelled,
            "shutdown must cancel adapter detection before joining its worker"
        );
    }

    #[test]
    fn cancelled_adapter_refresh_skips_stale_dns_cleanup() {
        let cancellation = AtomicBool::new(true);
        let mut cleanup_called = false;

        let result = cleanup_stale_dns_rules_if_needed(true, &cancellation, || {
            cleanup_called = true;
            Ok(true)
        });

        assert_eq!(result, Ok(false));
        assert!(
            !cleanup_called,
            "shutdown cancellation must not start another PowerShell cleanup"
        );
    }

    #[test]
    fn shutdown_retries_dns_cleanup_after_startup_refresh_is_cancelled() {
        let mut cleanup_called = false;

        let result = cleanup_dns_policy_on_shutdown_with(false, true, true, || {
            cleanup_called = true;
            Ok(())
        });

        assert_eq!(result, Ok(()));
        assert!(
            cleanup_called,
            "closing immediately after startup must still remove app-owned NRPT rules"
        );
    }

    #[test]
    fn closing_app_clears_managed_routes_and_disables_saved_profile() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rust-vpn-splitter-shutdown-{}-{unique}",
            std::process::id()
        ));
        let state_path = directory.join("state.json");
        let mut app = full_tunnel_app(VpnKind::F5);
        app.state_path = state_path.clone();
        let profile = app
            .state
            .config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists");
        profile.enabled = true;
        app.state.managed_routes = vec![ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "203.0.113.254/32".to_owned(),
            interface_index: u32::MAX,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        }];

        drop(app);

        let saved = load_state(&state_path).expect("shutdown state should be saved");
        assert!(
            saved.managed_routes.is_empty(),
            "normal shutdown must not leave routes for the next Windows session"
        );
        assert!(
            !saved
                .config
                .profile(VpnKind::F5)
                .expect("F5 profile exists")
                .enabled
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn closing_during_pending_toggle_waits_for_result_then_cleans_it_up() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rust-vpn-splitter-pending-shutdown-{}-{unique}",
            std::process::id()
        ));
        let state_path = directory.join("state.json");
        let mut app = full_tunnel_app(VpnKind::F5);
        app.state_path = state_path.clone();

        let mut completed_config = SplitterConfig::default();
        let completed_profile = completed_config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists");
        completed_profile.enabled = true;
        completed_profile.networks = "pending-toggle.example.test".to_owned();
        let completed_routes = vec![ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "203.0.113.253/32".to_owned(),
            interface_index: u32::MAX,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        }];
        let (worker_ready_sender, worker_ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        app.pending_operation = Some(PendingOperation::spawn(
            OperationKind::ToggleProfile {
                vpn: VpnKind::F5,
                enabled: true,
            },
            app.repaint_context.clone(),
            move |_cancellation| {
                worker_ready_sender
                    .send(())
                    .expect("test worker announces that it is blocked");
                release_receiver
                    .recv()
                    .expect("test releases the pending route operation");
                OperationResult::Toggle(ToggleOutcome::Applied {
                    vpn: VpnKind::F5,
                    enabled: true,
                    config: completed_config,
                    routes: completed_routes,
                    warnings: Vec::new(),
                })
            },
        ));
        worker_ready_receiver
            .recv()
            .expect("pending operation must start");
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            release_sender
                .send(())
                .expect("shutdown still owns the pending worker");
        });

        drop(app);
        releaser.join().expect("release helper must finish");

        let saved = load_state(&state_path).expect("shutdown state should be saved");
        let saved_profile = saved
            .config
            .profile(VpnKind::F5)
            .expect("F5 profile exists");
        assert_eq!(
            saved_profile.networks, "pending-toggle.example.test",
            "shutdown must consume the completed toggle before final cleanup"
        );
        assert!(!saved_profile.enabled, "shutdown must disable the profile");
        assert!(
            saved.managed_routes.is_empty(),
            "shutdown must remove routes created by the pending toggle"
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn enabled_cidr_profile_still_receives_periodic_route_health_checks() {
        let mut config = SplitterConfig::default();
        let profile = config.profile_mut(VpnKind::F5).expect("F5 profile exists");
        profile.enabled = true;
        profile.networks = "203.0.113.10/32".to_owned();

        assert!(!has_enabled_dns_targets(&config));
        assert!(
            needs_periodic_route_refresh(&config),
            "route drift can affect CIDR-only profiles too"
        );
    }

    #[test]
    fn shutdown_cleanup_retries_a_transient_route_removal_failure() {
        let mut state = PersistedState::default();
        state
            .config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists")
            .enabled = true;
        state.managed_routes = vec![route(VpnKind::F5, "0.0.0.0/2")];
        let mut attempts = 0;

        cleanup_managed_routes_with(&mut state, |_| {
            attempts += 1;
            if attempts == 1 {
                Err("route table changed during cleanup".to_owned())
            } else {
                Ok(())
            }
        })
        .expect("a transient cleanup race should be retried");

        assert_eq!(attempts, 2);
        assert!(state.managed_routes.is_empty());
        assert!(
            !state
                .config
                .profile(VpnKind::F5)
                .expect("F5 profile exists")
                .enabled
        );
    }

    #[test]
    fn failed_shutdown_cleanup_disables_profile_but_keeps_inventory_for_recovery() {
        let mut state = PersistedState::default();
        state
            .config
            .profile_mut(VpnKind::F5)
            .expect("F5 profile exists")
            .enabled = true;
        state.managed_routes = vec![route(VpnKind::F5, "0.0.0.0/2")];
        let expected_routes = state.managed_routes.clone();

        let result = cleanup_managed_routes_with(&mut state, |_| {
            Err("permanent route removal failure".to_owned())
        });

        assert!(result.is_err());
        assert_eq!(state.managed_routes, expected_routes);
        assert!(
            !state
                .config
                .profile(VpnKind::F5)
                .expect("F5 profile exists")
                .enabled
        );
    }

    #[test]
    fn next_startup_removes_complete_route_inventory_when_profiles_were_disabled() {
        let config = SplitterConfig::default();
        let previous = vec![
            route(VpnKind::F5, "203.0.113.10/32"),
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::InternetBypass,
                prefix: "0.0.0.0/2".to_owned(),
                interface_index: 7,
                next_hop: "192.0.2.1".to_owned(),
                route_metric: ROUTE_METRIC,
            },
        ];

        assert!(
            reconciled_routes_for_config(&previous, &previous, &config).is_empty(),
            "a prior process's complete ActiveStore inventory must not be re-enabled on startup"
        );
    }

    #[test]
    fn legacy_pair_of_physical_bypass_routes_is_migrated_from_default_purpose() {
        let mut state = PersistedState {
            managed_routes: vec![
                ManagedRoute {
                    vpn: VpnKind::F5,
                    purpose: ManagedRoutePurpose::Target,
                    prefix: "203.0.113.10/32".to_owned(),
                    interface_index: 43,
                    next_hop: "0.0.0.0".to_owned(),
                    route_metric: ROUTE_METRIC,
                },
                ManagedRoute {
                    vpn: VpnKind::F5,
                    purpose: ManagedRoutePurpose::Target,
                    prefix: "0.0.0.0/1".to_owned(),
                    interface_index: 7,
                    next_hop: "192.0.2.1".to_owned(),
                    route_metric: ROUTE_METRIC,
                },
                ManagedRoute {
                    vpn: VpnKind::F5,
                    purpose: ManagedRoutePurpose::Target,
                    prefix: "128.0.0.0/1".to_owned(),
                    interface_index: 7,
                    next_hop: "192.0.2.1".to_owned(),
                    route_metric: ROUTE_METRIC,
                },
            ],
            ..PersistedState::default()
        };

        migrate_legacy_route_purposes(&mut state);

        assert_eq!(
            state
                .managed_routes
                .iter()
                .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
                .count(),
            2
        );
        assert_eq!(state.managed_routes[0].purpose, ManagedRoutePurpose::Target);
    }

    #[test]
    fn toggling_one_vpn_only_replaces_that_vpns_routes() {
        let current = vec![
            route(VpnKind::FortiClient, "10.0.0.0/8"),
            route(VpnKind::F5, "172.16.0.0/12"),
        ];
        let replacement = vec![route(VpnKind::FortiClient, "192.168.0.0/16")];

        let enabled = replace_vpn_routes(&current, VpnKind::FortiClient, replacement.clone());
        assert_eq!(
            enabled,
            vec![route(VpnKind::F5, "172.16.0.0/12"), replacement[0].clone()]
        );

        let disabled = replace_vpn_routes(&enabled, VpnKind::FortiClient, Vec::new());
        assert_eq!(disabled, vec![route(VpnKind::F5, "172.16.0.0/12")]);
    }

    #[test]
    fn disabled_full_tunnel_vpn_remains_the_unmatched_route_and_dns_fallback() {
        for (enabled_vpn, fallback_vpn) in [
            (VpnKind::FortiClient, VpnKind::F5),
            (VpnKind::FortiClient, VpnKind::Ivanti),
            (VpnKind::F5, VpnKind::FortiClient),
            (VpnKind::F5, VpnKind::Ivanti),
            (VpnKind::Ivanti, VpnKind::FortiClient),
            (VpnKind::Ivanti, VpnKind::F5),
        ] {
            let mut app = full_tunnel_app(enabled_vpn);
            let (name, description) = match fallback_vpn {
                VpnKind::FortiClient => (
                    "FortiClient fallback",
                    "Fortinet SSL VPN Virtual Ethernet Adapter",
                ),
                VpnKind::F5 => ("F5 fallback", "F5 Networks VPN Adapter"),
                VpnKind::Ivanti => ("Ivanti fallback", "Pulse Secure Virtual Adapter"),
            };
            app.adapters.push(NetworkAdapter {
                index: 44,
                name: name.to_owned(),
                description: description.to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 2,
                    effective_metric: 10,
                }),
                dns_servers: vec!["198.51.100.53".to_owned()],
            });
            let mut config = enabled_full_tunnel_config(&app, enabled_vpn);
            let disabled_profile = config.profile_mut(fallback_vpn).expect("profile exists");
            disabled_profile.networks = "disabled.example.test\n198.51.100.10/32".to_owned();
            disabled_profile.adapter_description = Some(description.to_owned());

            let prepared = app
                .prepare_profile_routes(&config, enabled_vpn)
                .expect("the unmanaged full tunnel should remain available as fallback");
            let bypass_routes = prepared
                .routes
                .iter()
                .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
                .collect::<Vec<_>>();

            assert_eq!(bypass_routes.len(), INTERNET_BYPASS_PREFIXES.len());
            assert!(bypass_routes.iter().all(|route| {
                route.vpn == enabled_vpn
                    && route.interface_index == 44
                    && route.next_hop == "0.0.0.0"
            }));
            assert!(
                !prepared
                    .routes
                    .iter()
                    .any(|route| route.vpn == fallback_vpn)
            );
            assert_eq!(prepared.dns_rules.len(), 1);
            assert_eq!(prepared.dns_rules[0].vpn, None);
            assert_eq!(prepared.dns_rules[0].namespaces, vec!["."]);
            assert_eq!(
                prepared.dns_rules[0].name_servers,
                vec!["198.51.100.53"],
                "{enabled_vpn} must leave unmatched DNS on disabled {fallback_vpn}"
            );
        }
    }

    #[test]
    fn unmanaged_fallback_uses_the_route_windows_would_prefer() {
        let mut app = full_tunnel_app(VpnKind::F5);
        let gateway = app.internet_gateway.as_mut().expect("gateway exists");
        gateway.inferred_from_escape_route = false;
        gateway.route_priority = Some(RoutePriority {
            prefix_length: 0,
            effective_metric: 10,
        });
        app.adapters.extend([
            NetworkAdapter {
                index: 44,
                name: "FortiClient fallback".to_owned(),
                description: "Fortinet SSL VPN Virtual Ethernet Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 0,
                    effective_metric: 5,
                }),
                dns_servers: vec!["198.51.100.53".to_owned()],
            },
            NetworkAdapter {
                index: 45,
                name: "Ivanti fallback".to_owned(),
                description: "Pulse Secure Virtual Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 1,
                    effective_metric: 100,
                }),
                dns_servers: vec!["203.0.113.53".to_owned()],
            },
        ]);
        let config = enabled_full_tunnel_config(&app, VpnKind::F5);

        assert!(matches!(
            select_internet_fallback(&config, &app.adapters, app.internet_gateway.as_ref()),
            Some(InternetFallback::Vpn {
                vpn: VpnKind::Ivanti,
                ..
            })
        ));

        app.adapters[2].full_tunnel_priority = Some(RoutePriority {
            prefix_length: 0,
            effective_metric: 20,
        });
        assert!(matches!(
            select_internet_fallback(&config, &app.adapters, app.internet_gateway.as_ref()),
            Some(InternetFallback::Vpn {
                vpn: VpnKind::FortiClient,
                ..
            })
        ));

        app.adapters[1].full_tunnel_priority = Some(RoutePriority {
            prefix_length: 0,
            effective_metric: 30,
        });
        assert!(matches!(
            select_internet_fallback(&config, &app.adapters, app.internet_gateway.as_ref()),
            Some(InternetFallback::Physical(_))
        ));
    }

    #[test]
    fn route_health_moves_unmatched_traffic_as_an_unmanaged_vpn_connects_and_disconnects() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.adapters.push(NetworkAdapter {
            index: 44,
            name: "FortiClient fallback".to_owned(),
            description: "Fortinet SSL VPN Virtual Ethernet Adapter".to_owned(),
            status: "Disconnected".to_owned(),
            next_hop: "0.0.0.0".to_owned(),
            full_tunnel_priority: Some(RoutePriority {
                prefix_length: 2,
                effective_metric: 5,
            }),
            dns_servers: vec!["198.51.100.53".to_owned()],
        });
        let config = enabled_full_tunnel_config(&app, VpnKind::F5);
        let physical_routes = app
            .prepare_all_enabled_routes(&config)
            .expect("physical fallback should be prepared")
            .routes;
        assert!(physical_routes.iter().all(|route| {
            route.purpose != ManagedRoutePurpose::InternetBypass || route.interface_index == 7
        }));

        app.adapters[1].status = "Up".to_owned();
        let connected_outcome = evaluate_route_health_with(
            physical_routes.clone(),
            config,
            physical_routes.clone(),
            app.adapters.clone(),
            app.internet_gateway.clone(),
            |_, desired| {
                assert!(desired.iter().all(|route| {
                    route.purpose != ManagedRoutePurpose::InternetBypass
                        || route.interface_index == 44
                }));
                Ok(())
            },
            |rules| {
                assert_eq!(rules[0].namespaces, vec!["."]);
                assert_eq!(rules[0].name_servers, vec!["198.51.100.53"]);
                Ok(true)
            },
        );
        let (connected_config, vpn_routes) = match connected_outcome {
            RouteHealthOutcome::Updated { config, routes, .. } => (config, routes),
            other => panic!("connecting the unmanaged VPN must update fallback: {other:?}"),
        };

        app.adapters[1].status = "Disconnected".to_owned();
        let disconnected_outcome = evaluate_route_health_with(
            vpn_routes.clone(),
            connected_config,
            vpn_routes,
            app.adapters.clone(),
            app.internet_gateway.clone(),
            |_, desired| {
                assert!(desired.iter().all(|route| {
                    route.purpose != ManagedRoutePurpose::InternetBypass
                        || route.interface_index == 7
                }));
                Ok(())
            },
            |rules| {
                assert_eq!(rules[0].namespaces, vec!["."]);
                assert_eq!(rules[0].name_servers, vec!["192.0.2.53"]);
                Ok(true)
            },
        );
        assert!(matches!(
            disconnected_outcome,
            RouteHealthOutcome::Updated { .. }
        ));
    }

    #[test]
    fn every_full_tunnel_vpn_adds_physical_internet_bypass_routes() {
        for vpn in VpnKind::ALL {
            let app = full_tunnel_app(vpn);
            let config = enabled_full_tunnel_config(&app, vpn);

            let prepared = app
                .prepare_profile_routes(&config, vpn)
                .expect("full-tunnel routes should be prepared");

            assert!(prepared.routes.contains(&ManagedRoute {
                vpn,
                purpose: ManagedRoutePurpose::Target,
                prefix: "203.0.113.10/32".to_owned(),
                interface_index: 43,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            }));
            // FortiClient can implement Full Tunnel with four /2 routes on
            // both interfaces. The managed bypass must be more specific so
            // it neither collides with those route keys nor loses by metric.
            for prefix in INTERNET_BYPASS_PREFIXES {
                assert!(prepared.routes.contains(&ManagedRoute {
                    vpn,
                    purpose: ManagedRoutePurpose::InternetBypass,
                    prefix: prefix.to_owned(),
                    interface_index: 7,
                    next_hop: "192.0.2.1".to_owned(),
                    route_metric: ROUTE_METRIC,
                }));
            }
            assert!(
                !prepared
                    .routes
                    .iter()
                    .any(|route| route.prefix == "0.0.0.0/1" || route.prefix == "128.0.0.0/1")
            );
        }
    }

    #[test]
    fn cidr_only_native_split_tunnels_leave_windows_dns_unchanged() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            app.adapters[0].full_tunnel_priority = None;
            let config = enabled_full_tunnel_config(&app, vpn);

            let prepared = app
                .prepare_profile_routes(&config, vpn)
                .expect("CIDR-only native split tunnel should be prepared");

            assert!(
                prepared.dns_rules.is_empty(),
                "{vpn} must not override Windows DNS when it already uses native split tunneling"
            );
        }
    }

    #[test]
    fn every_vpn_keeps_unlisted_dns_on_the_current_network() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            app.adapters[0].dns_servers = vec!["203.0.113.53".to_owned()];
            app.internet_gateway
                .as_mut()
                .expect("physical gateway exists")
                .dns_servers = vec!["203.0.113.53".to_owned(), "192.0.2.53".to_owned()];
            let config = enabled_full_tunnel_config(&app, vpn);

            let prepared = app
                .prepare_profile_routes(&config, vpn)
                .expect("split DNS policy should be prepared");

            assert_eq!(prepared.dns_rules.len(), 1, "{vpn}");
            assert_eq!(prepared.dns_rules[0].vpn, None, "{vpn}");
            assert_eq!(prepared.dns_rules[0].namespaces, vec!["."], "{vpn}");
            assert_eq!(
                prepared.dns_rules[0].name_servers,
                vec!["192.0.2.53"],
                "{vpn} must exclude its own DNS server from normal lookups"
            );
        }
    }

    #[test]
    fn every_vpn_recovers_physical_dns_when_it_replaces_the_active_dns_list() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            app.adapters[0].dns_servers = vec!["203.0.113.53".to_owned()];
            let gateway = app
                .internet_gateway
                .as_mut()
                .expect("physical gateway exists");
            gateway.dns_servers = vec!["203.0.113.53".to_owned()];
            gateway.fallback_dns_servers = vec!["192.0.2.53".to_owned()];
            let config = enabled_full_tunnel_config(&app, vpn);

            let prepared = app
                .prepare_profile_routes(&config, vpn)
                .expect("physical DNS fallback should keep split DNS usable");

            assert_eq!(prepared.dns_rules.len(), 1, "{vpn}");
            assert_eq!(prepared.dns_rules[0].namespaces, vec!["."], "{vpn}");
            assert_eq!(
                prepared.dns_rules[0].name_servers,
                vec!["192.0.2.53"],
                "{vpn} must recover the current network DNS from adapter settings"
            );
        }
    }

    #[test]
    fn every_vpn_uses_its_own_dns_only_for_listed_hostnames() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            app.adapters[0].dns_servers = vec!["203.0.113.53".to_owned()];
            app.internet_gateway
                .as_mut()
                .expect("physical gateway exists")
                .dns_servers = vec!["203.0.113.53".to_owned(), "192.0.2.53".to_owned()];
            let mut config = enabled_full_tunnel_config(&app, vpn);
            config.profile_mut(vpn).expect("profile exists").networks =
                "https://service.example.test/path".to_owned();
            let mut resolution_calls = 0;

            let prepared = prepare_all_enabled_routes_with_resolver(
                &config,
                &app.adapters,
                app.internet_gateway.as_ref(),
                |resolved_vpn, hostname, servers| {
                    resolution_calls += 1;
                    assert_eq!(resolved_vpn, vpn);
                    assert_eq!(hostname, "service.example.test");
                    assert_eq!(servers, ["203.0.113.53"]);
                    Ok(vec![Ipv4Addr::new(198, 51, 100, 20)])
                },
            )
            .expect("listed hostname policy should be prepared");

            assert_eq!(resolution_calls, 1, "{vpn}");
            assert!(prepared.dns_rules.contains(&ManagedDnsRule {
                vpn: None,
                namespaces: vec![".".to_owned()],
                name_servers: vec!["192.0.2.53".to_owned()],
            }));
            assert!(prepared.dns_rules.contains(&ManagedDnsRule {
                vpn: Some(vpn),
                namespaces: vec!["service.example.test".to_owned()],
                name_servers: vec!["203.0.113.53".to_owned()],
            }));
            assert!(prepared.routes.contains(&ManagedRoute {
                vpn,
                purpose: ManagedRoutePurpose::Target,
                prefix: "198.51.100.20/32".to_owned(),
                interface_index: 43,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            }));
            assert!(prepared.routes.contains(&ManagedRoute {
                vpn,
                purpose: ManagedRoutePurpose::VpnDnsServer,
                prefix: "203.0.113.53/32".to_owned(),
                interface_index: 43,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            }));
        }
    }

    #[test]
    fn route_health_keeps_windows_dns_unchanged_for_cidr_only_native_split_tunnels() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            app.adapters[0].full_tunnel_priority = None;
            let config = enabled_full_tunnel_config(&app, vpn);
            let current_routes = app
                .prepare_profile_routes(&config, vpn)
                .expect("initial native split policy should be prepared")
                .routes;
            let mut route_apply_calls = 0;
            let mut dns_apply_calls = 0;

            let outcome = evaluate_route_health_with(
                current_routes.clone(),
                config,
                current_routes,
                app.adapters.clone(),
                app.internet_gateway.clone(),
                |_, _| {
                    route_apply_calls += 1;
                    Ok(())
                },
                |rules| {
                    dns_apply_calls += 1;
                    assert!(
                        rules.is_empty(),
                        "{vpn} health checks must not add a Windows DNS policy"
                    );
                    Ok(false)
                },
            );

            assert_eq!(route_apply_calls, 0, "{vpn}");
            assert_eq!(dns_apply_calls, 1, "{vpn}");
            assert!(
                matches!(
                    outcome,
                    RouteHealthOutcome::Updated {
                        repaired: false,
                        ..
                    }
                ),
                "{vpn}: {outcome:?}"
            );
        }
    }

    #[test]
    fn route_health_reinstalls_the_dns_policy_for_every_vpn() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            app.adapters[0].dns_servers = vec!["203.0.113.53".to_owned()];
            app.internet_gateway
                .as_mut()
                .expect("physical gateway exists")
                .dns_servers = vec!["203.0.113.53".to_owned(), "192.0.2.53".to_owned()];
            let config = enabled_full_tunnel_config(&app, vpn);
            let current_routes = app
                .prepare_profile_routes(&config, vpn)
                .expect("initial split policy should be prepared")
                .routes;
            let mut route_apply_calls = 0;
            let mut dns_apply_calls = 0;

            let outcome = evaluate_route_health_with(
                current_routes.clone(),
                config,
                current_routes,
                app.adapters.clone(),
                app.internet_gateway.clone(),
                |_, _| {
                    route_apply_calls += 1;
                    Ok(())
                },
                |rules| {
                    dns_apply_calls += 1;
                    assert_eq!(rules.len(), 1, "{vpn}");
                    assert_eq!(rules[0].namespaces, vec!["."], "{vpn}");
                    assert_eq!(rules[0].name_servers, vec!["192.0.2.53"], "{vpn}");
                    Ok(true)
                },
            );

            assert_eq!(route_apply_calls, 0, "{vpn}");
            assert_eq!(dns_apply_calls, 1, "{vpn}");
            assert!(
                matches!(outcome, RouteHealthOutcome::Updated { repaired: true, .. }),
                "{vpn}: {outcome:?}"
            );
        }
    }

    #[test]
    fn route_health_reinstalls_a_removed_bypass_route_for_every_vpn() {
        for vpn in VpnKind::ALL {
            let app = full_tunnel_app(vpn);
            let config = enabled_full_tunnel_config(&app, vpn);
            let current_routes = app
                .prepare_profile_routes(&config, vpn)
                .expect("full-tunnel routes should be prepared")
                .routes;
            let existing_routes = current_routes
                .iter()
                .filter(|route| route.prefix != "64.0.0.0/3")
                .cloned()
                .collect::<Vec<_>>();
            let mut apply_calls = 0;

            let outcome = evaluate_route_health_with(
                current_routes.clone(),
                config,
                existing_routes,
                app.adapters.clone(),
                app.internet_gateway.clone(),
                |_, desired| {
                    apply_calls += 1;
                    assert_eq!(desired.len(), current_routes.len());
                    assert!(desired.iter().any(|route| route.prefix == "64.0.0.0/3"));
                    Ok(())
                },
                |_| Ok(false),
            );

            assert_eq!(apply_calls, 1, "{vpn} route drift must trigger repair");
            assert!(matches!(
                outcome,
                RouteHealthOutcome::Updated { repaired: true, .. }
            ));
        }
    }

    #[test]
    fn route_health_atomically_replaces_a_stale_physical_gateway() {
        let app = full_tunnel_app(VpnKind::F5);
        let config = enabled_full_tunnel_config(&app, VpnKind::F5);
        let current_routes = app
            .prepare_profile_routes(&config, VpnKind::F5)
            .expect("full-tunnel routes should be prepared")
            .routes;
        let mut new_gateway = app.internet_gateway.clone().expect("gateway exists");
        new_gateway.interface_index = 12;
        new_gateway.interface_alias = "Ethernet".to_owned();
        new_gateway.next_hop = "192.0.2.254".to_owned();
        let mut apply_calls = 0;

        let outcome = evaluate_route_health_with(
            current_routes.clone(),
            config,
            current_routes,
            app.adapters.clone(),
            Some(new_gateway.clone()),
            |previous, desired| {
                apply_calls += 1;
                assert_eq!(previous.len(), desired.len());
                assert!(
                    desired
                        .iter()
                        .filter(|route| {
                            route.purpose == ManagedRoutePurpose::InternetBypass
                                && route.interface_index == new_gateway.interface_index
                                && route.next_hop == new_gateway.next_hop
                        })
                        .count()
                        == INTERNET_BYPASS_PREFIXES.len()
                );
                Ok(())
            },
            |_| Ok(false),
        );

        assert_eq!(apply_calls, 1);
        assert!(matches!(
            outcome,
            RouteHealthOutcome::Updated { repaired: true, .. }
        ));
    }

    #[test]
    fn route_health_removes_residual_routes_when_each_vpn_disconnects() {
        for vpn in VpnKind::ALL {
            let mut app = full_tunnel_app(vpn);
            let config = enabled_full_tunnel_config(&app, vpn);
            let current_routes = app
                .prepare_profile_routes(&config, vpn)
                .expect("full-tunnel routes should be prepared")
                .routes;
            app.adapters[0].status = "Disconnected".to_owned();
            let mut apply_calls = 0;

            let outcome = evaluate_route_health_with(
                current_routes.clone(),
                config,
                current_routes,
                app.adapters.clone(),
                app.internet_gateway.clone(),
                |previous, desired| {
                    apply_calls += 1;
                    assert!(!previous.is_empty());
                    assert!(desired.is_empty());
                    Ok(())
                },
                |_| Ok(false),
            );

            assert_eq!(apply_calls, 1);
            match outcome {
                RouteHealthOutcome::Updated {
                    config,
                    routes,
                    disabled_vpns,
                    ..
                } => {
                    assert!(routes.is_empty());
                    assert_eq!(disabled_vpns, vec![vpn]);
                    assert!(!config.profile(vpn).expect("profile exists").enabled);
                }
                other => panic!("unexpected route-health outcome for {vpn}: {other:?}"),
            }
        }
    }

    #[test]
    fn route_health_keeps_both_profiles_and_one_bypass_when_two_vpns_become_full_tunnel() {
        let adapters = vec![
            NetworkAdapter {
                index: 43,
                name: "FortiClient VPN".to_owned(),
                description: "Fortinet SSL VPN Virtual Ethernet Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 2,
                    effective_metric: 5,
                }),
                dns_servers: Vec::new(),
            },
            NetworkAdapter {
                index: 44,
                name: "F5 VPN".to_owned(),
                description: "F5 Networks VPN Adapter".to_owned(),
                status: "Up".to_owned(),
                next_hop: "0.0.0.0".to_owned(),
                full_tunnel_priority: Some(RoutePriority {
                    prefix_length: 2,
                    effective_metric: 5,
                }),
                dns_servers: Vec::new(),
            },
        ];
        let mut config = SplitterConfig::default();
        for (vpn, description, network) in [
            (
                VpnKind::FortiClient,
                "Fortinet SSL VPN Virtual Ethernet Adapter",
                "198.51.100.10/32",
            ),
            (VpnKind::F5, "F5 Networks VPN Adapter", "203.0.113.10/32"),
        ] {
            let profile = config.profile_mut(vpn).expect("profile exists");
            profile.enabled = true;
            profile.adapter_description = Some(description.to_owned());
            profile.networks = network.to_owned();
        }
        let current_routes = vec![
            ManagedRoute {
                vpn: VpnKind::FortiClient,
                purpose: ManagedRoutePurpose::Target,
                prefix: "198.51.100.10/32".to_owned(),
                interface_index: 43,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            },
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::Target,
                prefix: "203.0.113.10/32".to_owned(),
                interface_index: 44,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: ROUTE_METRIC,
            },
        ];
        let gateway = InternetGateway {
            interface_index: 7,
            interface_alias: "Wi-Fi".to_owned(),
            interface_description: "Physical Wi-Fi Adapter".to_owned(),
            next_hop: "192.0.2.1".to_owned(),
            inferred_from_escape_route: false,
            route_priority: Some(RoutePriority {
                prefix_length: 0,
                effective_metric: 30,
            }),
            dns_servers: vec!["192.0.2.53".to_owned()],
            fallback_dns_servers: vec!["192.0.2.53".to_owned()],
        };
        let mut apply_calls = 0;

        let outcome = evaluate_route_health_with(
            current_routes.clone(),
            config,
            current_routes,
            adapters,
            Some(gateway),
            |_, desired| {
                apply_calls += 1;
                assert_eq!(
                    desired
                        .iter()
                        .filter(|route| route.purpose == ManagedRoutePurpose::Target)
                        .count(),
                    2
                );
                assert_eq!(
                    desired
                        .iter()
                        .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
                        .count(),
                    INTERNET_BYPASS_PREFIXES.len()
                );
                assert!(desired.iter().all(|route| {
                    route.purpose != ManagedRoutePurpose::InternetBypass
                        || route.vpn == VpnKind::FortiClient
                }));
                Ok(())
            },
            |_| Ok(false),
        );

        match outcome {
            RouteHealthOutcome::Updated {
                config,
                disabled_vpns,
                routes,
                ..
            } => {
                assert_eq!(apply_calls, 1);
                assert!(disabled_vpns.is_empty());
                assert_eq!(routes.len(), 2 + INTERNET_BYPASS_PREFIXES.len());
                assert_eq!(
                    config
                        .profiles
                        .iter()
                        .filter(|profile| profile.enabled)
                        .count(),
                    2
                );
            }
            other => panic!("full-tunnel routes must be stabilized automatically: {other:?}"),
        }
    }

    #[test]
    fn losing_dynamic_vpn_route_discards_its_remaining_bypass_routes() {
        let target = ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "203.0.113.10/32".to_owned(),
            interface_index: 43,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: ROUTE_METRIC,
        };
        let lower_half = ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::InternetBypass,
            prefix: "0.0.0.0/1".to_owned(),
            interface_index: 7,
            next_hop: "192.0.2.1".to_owned(),
            route_metric: ROUTE_METRIC,
        };
        let upper_half = ManagedRoute {
            prefix: "128.0.0.0/1".to_owned(),
            ..lower_half.clone()
        };
        let forti = route(VpnKind::FortiClient, "10.20.0.0/16");
        let previous = vec![
            target,
            lower_half.clone(),
            upper_half.clone(),
            forti.clone(),
        ];
        let existing = vec![lower_half, upper_half, forti.clone()];

        assert_eq!(
            discard_incomplete_vpn_route_sets(&previous, &existing),
            vec![forti]
        );
    }

    #[test]
    fn f5_and_ivanti_full_tunnels_share_physical_internet_bypass_routes() {
        let mut app = full_tunnel_app(VpnKind::F5);
        app.adapters.push(NetworkAdapter {
            index: 44,
            name: "Ivanti VPN".to_owned(),
            description: "Juniper Networks Virtual Adapter".to_owned(),
            status: "Up".to_owned(),
            next_hop: "0.0.0.0".to_owned(),
            full_tunnel_priority: Some(RoutePriority {
                prefix_length: 2,
                effective_metric: 5,
            }),
            dns_servers: Vec::new(),
        });
        let mut config = SplitterConfig::default();
        for (vpn, description, network) in [
            (VpnKind::F5, "F5 Networks VPN Adapter", "203.0.113.10/32"),
            (
                VpnKind::Ivanti,
                "Juniper Networks Virtual Adapter",
                "198.51.100.10/32",
            ),
        ] {
            let profile = config.profile_mut(vpn).expect("profile exists");
            profile.enabled = true;
            profile.networks = network.to_owned();
            profile.adapter_description = Some(description.to_owned());
        }

        let prepared = app
            .prepare_all_enabled_routes(&config)
            .expect("both full-tunnel VPNs must preserve normal internet access");
        let target_routes = prepared
            .routes
            .iter()
            .filter(|route| route.purpose == ManagedRoutePurpose::Target)
            .collect::<Vec<_>>();
        assert_eq!(target_routes.len(), 2);
        assert!(target_routes.iter().any(|route| {
            route.vpn == VpnKind::F5
                && route.prefix == "203.0.113.10/32"
                && route.interface_index == 43
        }));
        assert!(target_routes.iter().any(|route| {
            route.vpn == VpnKind::Ivanti
                && route.prefix == "198.51.100.10/32"
                && route.interface_index == 44
        }));

        let bypass_routes = prepared
            .routes
            .iter()
            .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
            .collect::<Vec<_>>();
        assert_eq!(bypass_routes.len(), INTERNET_BYPASS_PREFIXES.len());
        for prefix in INTERNET_BYPASS_PREFIXES {
            assert!(bypass_routes.iter().any(|route| {
                route.prefix == prefix
                    && route.interface_index == 7
                    && route.next_hop == "192.0.2.1"
            }));
        }
    }

    #[test]
    fn forticlient_full_tunnel_combinations_share_physical_internet_bypass_routes() {
        for vpns in [
            vec![VpnKind::FortiClient, VpnKind::F5],
            vec![VpnKind::FortiClient, VpnKind::Ivanti],
            vec![VpnKind::FortiClient, VpnKind::F5, VpnKind::Ivanti],
        ] {
            let mut app = full_tunnel_app(VpnKind::FortiClient);
            app.adapters.clear();
            let mut config = SplitterConfig::default();

            for (offset, vpn) in vpns.iter().copied().enumerate() {
                let (name, description, target) = match vpn {
                    VpnKind::FortiClient => (
                        "FortiClient VPN",
                        "Fortinet SSL VPN Virtual Ethernet Adapter",
                        "198.51.100.10/32",
                    ),
                    VpnKind::F5 => ("F5 VPN", "F5 Networks VPN Adapter", "203.0.113.10/32"),
                    VpnKind::Ivanti => (
                        "Ivanti VPN",
                        "Juniper Networks Virtual Adapter",
                        "192.0.2.10/32",
                    ),
                };
                app.adapters.push(NetworkAdapter {
                    index: 41 + offset as u32,
                    name: name.to_owned(),
                    description: description.to_owned(),
                    status: "Up".to_owned(),
                    next_hop: "0.0.0.0".to_owned(),
                    full_tunnel_priority: Some(RoutePriority {
                        prefix_length: 2,
                        effective_metric: 5,
                    }),
                    dns_servers: Vec::new(),
                });
                let profile = config.profile_mut(vpn).expect("profile exists");
                profile.enabled = true;
                profile.networks = target.to_owned();
                profile.adapter_description = Some(description.to_owned());
            }

            let prepared = app
                .prepare_all_enabled_routes(&config)
                .unwrap_or_else(|errors| panic!("{vpns:?} must be supported: {errors:?}"));
            assert_eq!(
                prepared
                    .routes
                    .iter()
                    .filter(|route| route.purpose == ManagedRoutePurpose::Target)
                    .count(),
                vpns.len(),
                "{vpns:?} must retain every VPN target"
            );
            let bypass_routes = prepared
                .routes
                .iter()
                .filter(|route| route.purpose == ManagedRoutePurpose::InternetBypass)
                .collect::<Vec<_>>();
            assert_eq!(
                bypass_routes.len(),
                INTERNET_BYPASS_PREFIXES.len(),
                "{vpns:?} must share one physical bypass set"
            );
            assert!(bypass_routes.iter().all(|route| {
                route.vpn == VpnKind::FortiClient
                    && route.interface_index == 7
                    && route.next_hop == "192.0.2.1"
            }));
        }
    }
}
