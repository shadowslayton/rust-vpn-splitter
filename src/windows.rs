use std::{
    io::Write,
    net::Ipv4Addr,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, SetLastError},
    NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    },
    Networking::WinSock::{AF_INET, SOCKADDR_INET},
    System::Threading::CreateMutexW,
};

use crate::domain::VpnKind;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SINGLE_INSTANCE_MUTEX_NAME: &str = "Local\\tw.layton.rust-vpn-splitter";

pub struct SingleInstanceGuard {
    handle: HANDLE,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        // SAFETY: `handle` is a non-null mutex handle owned by this guard and
        // is closed exactly once here.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn acquire_named_mutex(name: &str) -> Result<Option<SingleInstanceGuard>, String> {
    let wide_name = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the security-attributes pointer is null, and `wide_name` is a
    // valid NUL-terminated UTF-16 buffer for the duration of the call.
    let (handle, last_error) = unsafe {
        SetLastError(0);
        let handle = CreateMutexW(ptr::null(), 1, wide_name.as_ptr());
        (handle, GetLastError())
    };
    if handle.is_null() {
        return Err(format!(
            "無法建立應用程式單一實例鎖：{}",
            std::io::Error::last_os_error()
        ));
    }
    if last_error == ERROR_ALREADY_EXISTS {
        // SAFETY: this call received a valid handle, but another process owns
        // the named mutex, so this process immediately releases its reference.
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Ok(None);
    }

    Ok(Some(SingleInstanceGuard { handle }))
}

pub fn acquire_single_instance() -> Result<Option<SingleInstanceGuard>, String> {
    acquire_named_mutex(SINGLE_INSTANCE_MUTEX_NAME)
}

const DISCOVER_ADAPTERS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

$vpnPattern = '(?i)forti|f5|big-ip|ivanti|juniper|pulse secure'

# RAS/PPP interfaces can have an empty InterfaceDescription. Map their entry
# names back to the actual VPN device recorded in the Windows RAS phonebook.
$rasDevicesByEntry = @{}
$phonebookPaths = @()
if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
    $phonebookPaths += [IO.Path]::Combine(
        $env:APPDATA,
        'Microsoft\Network\Connections\Pbk\rasphone.pbk'
    )
}
if (-not [string]::IsNullOrWhiteSpace($env:PROGRAMDATA)) {
    $phonebookPaths += [IO.Path]::Combine(
        $env:PROGRAMDATA,
        'Microsoft\Network\Connections\Pbk\rasphone.pbk'
    )
}

foreach ($phonebookPath in @($phonebookPaths | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $phonebookPath)) {
        continue
    }

    $entryName = $null
    foreach ($line in Get-Content -LiteralPath $phonebookPath -ErrorAction Stop) {
        if ([string]$line -match '^\[(.+)\]$') {
            $entryName = [string]$Matches[1]
        } elseif (
            $null -ne $entryName -and
            [string]$line -cmatch '^Device=(.*)$'
        ) {
            $rasDevicesByEntry[$entryName] = [string]$Matches[1]
        }
    }
}

# Browser-launched F5 Network Access uses RAS. Its connected PPP interface is
# visible to NetTCPIP but not necessarily to Get-NetAdapter; the permanently
# installed F5 adapter can remain "Disconnected" for the whole session.
$netAdapterCandidates = @(
    Get-NetAdapter -IncludeHidden |
        Where-Object { "$($_.Name) $($_.InterfaceDescription)" -match $vpnPattern } |
        ForEach-Object {
            [pscustomobject]@{
                index = [uint32]$_.ifIndex
                name = [string]$_.Name
                description = [string]$_.InterfaceDescription
                status = [string]$_.Status
            }
        }
)

$ipInterfaceCandidates = @(
    Get-NetIPConfiguration -All -AllCompartments |
        ForEach-Object {
            $configuration = $_
            $alias = [string]$configuration.InterfaceAlias
            $description = [string]$configuration.InterfaceDescription
            if (
                [string]::IsNullOrWhiteSpace($description) -and
                $rasDevicesByEntry.ContainsKey($alias)
            ) {
                $description = [string]$rasDevicesByEntry[$alias]
            }

            if ("$alias $description" -match $vpnPattern) {
                $connected = @(
                    Get-NetIPInterface `
                        -AddressFamily IPv4 `
                        -InterfaceIndex ([uint32]$configuration.InterfaceIndex) `
                        -IncludeAllCompartments `
                        -ErrorAction SilentlyContinue |
                        Where-Object { [string]$_.ConnectionState -eq 'Connected' }
                ).Count -gt 0

                [pscustomobject]@{
                    index = [uint32]$configuration.InterfaceIndex
                    name = $alias
                    description = $description
                    status = if ($connected) { 'Up' } else { 'Disconnected' }
                }
            }
        }
)

$candidates = @($netAdapterCandidates) + @($ipInterfaceCandidates) |
    Group-Object index |
    ForEach-Object {
        $_.Group |
            Sort-Object @{ Expression = { [string]$_.status -ne 'Up' } } |
            Select-Object -First 1
    }

$adapters = @(
    $candidates |
        ForEach-Object {
            $candidate = $_
            $routes = @(
                Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $candidate.index -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            )

            $gatewayRoute = $routes |
                Where-Object {
                    $_.DestinationPrefix -eq '0.0.0.0/0' -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.NextHop) -and
                    [string]$_.NextHop -ne '0.0.0.0'
                } |
                Sort-Object RouteMetric |
                Select-Object -First 1

            if ($null -eq $gatewayRoute) {
                $gatewayRoute = $routes |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace([string]$_.NextHop) -and
                        [string]$_.NextHop -ne '0.0.0.0'
                    } |
                    Sort-Object RouteMetric |
                    Select-Object -First 1
            }

            $nextHop = if ($null -eq $gatewayRoute) {
                '0.0.0.0'
            } else {
                [string]$gatewayRoute.NextHop
            }

            [pscustomobject]@{
                index = [uint32]$candidate.index
                name = [string]$candidate.name
                description = [string]$candidate.description
                status = [string]$candidate.status
                next_hop = $nextHop
                has_default_route = [bool](@(
                    $routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
                ).Count -gt 0 -or (
                    @($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/1' }).Count -gt 0 -and
                    @($routes | Where-Object { $_.DestinationPrefix -eq '128.0.0.0/1' }).Count -gt 0
                ))
            }
        }
)

ConvertTo-Json -InputObject @($adapters) -Compress -Depth 4
"#;

const DISCOVER_INTERNET_GATEWAY_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

$vpnPattern = '(?i)forti|f5|big-ip|ivanti|juniper|pulse secure'
$physicalInterfaces = @(
    Get-NetIPConfiguration -All -AllCompartments |
        Where-Object {
            "$($_.InterfaceAlias) $($_.InterfaceDescription)" -notmatch $vpnPattern -and
            @($_.IPv4Address).Count -gt 0
        } |
        ForEach-Object {
            $configuration = $_
            $ipInterface = Get-NetIPInterface `
                -AddressFamily IPv4 `
                -InterfaceIndex ([uint32]$configuration.InterfaceIndex) `
                -IncludeAllCompartments `
                -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.ConnectionState -eq 'Connected' } |
                Select-Object -First 1

            if ($null -ne $ipInterface) {
                [pscustomobject]@{
                    index = [uint32]$configuration.InterfaceIndex
                    alias = [string]$configuration.InterfaceAlias
                    description = [string]$configuration.InterfaceDescription
                    interface_metric = [uint32]$ipInterface.InterfaceMetric
                }
            }
        }
)

function Find-PhysicalInterface([uint32]$index) {
    $physicalInterfaces |
        Where-Object { $_.index -eq $index } |
        Select-Object -First 1
}

$routes = @(
    Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
)

$selectedRoute = $routes |
    Where-Object {
        [string]$_.DestinationPrefix -eq '0.0.0.0/0' -and
        -not [string]::IsNullOrWhiteSpace([string]$_.NextHop) -and
        [string]$_.NextHop -ne '0.0.0.0' -and
        $null -ne (Find-PhysicalInterface ([uint32]$_.InterfaceIndex))
    } |
    Sort-Object `
        @{ Expression = {
            $interface = Find-PhysicalInterface ([uint32]$_.InterfaceIndex)
            [uint32]$_.RouteMetric + [uint32]$interface.interface_metric
        } } |
    Select-Object -First 1
$inferred = $false

if ($null -eq $selectedRoute) {
    # A full-tunnel client normally removes the ordinary default route but keeps
    # a host route to its own public server through the original gateway. That
    # escape route gives us the same physical interface and next hop.
    $selectedRoute = $routes |
        Where-Object {
            [string]$_.DestinationPrefix -ne '0.0.0.0/0' -and
            -not [string]::IsNullOrWhiteSpace([string]$_.NextHop) -and
            [string]$_.NextHop -ne '0.0.0.0' -and
            $null -ne (Find-PhysicalInterface ([uint32]$_.InterfaceIndex))
        } |
        Sort-Object `
            @{ Expression = { [string]$_.DestinationPrefix -notmatch '/32$' } }, `
            RouteMetric |
        Select-Object -First 1
    $inferred = $null -ne $selectedRoute
}

if ($null -eq $selectedRoute) {
    ConvertTo-Json -InputObject $null -Compress
} else {
    $interface = Find-PhysicalInterface ([uint32]$selectedRoute.InterfaceIndex)
    [pscustomobject]@{
        interface_index = [uint32]$selectedRoute.InterfaceIndex
        interface_alias = [string]$interface.alias
        interface_description = [string]$interface.description
        next_hop = [string]$selectedRoute.NextHop
        inferred_from_escape_route = [bool]$inferred
    } | ConvertTo-Json -Compress
}
"#;

const APPLY_ROUTES_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

function Find-ExactRoute($route) {
    @(
        Get-NetRoute `
            -AddressFamily IPv4 `
            -DestinationPrefix ([string]$route.prefix) `
            -InterfaceIndex ([uint32]$route.interface_index) `
            -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object {
                [string]$_.NextHop -eq [string]$route.next_hop -and
                [uint32]$_.RouteMetric -eq [uint32]$route.route_metric
            }
    )
}

function Same-Route($left, $right) {
    [string]$left.prefix -eq [string]$right.prefix -and
    [uint32]$left.interface_index -eq [uint32]$right.interface_index -and
    [string]$left.next_hop -eq [string]$right.next_hop -and
    [uint32]$left.route_metric -eq [uint32]$right.route_metric
}

function Contains-Route($routes, $candidate) {
    foreach ($route in @($routes)) {
        if (Same-Route $route $candidate) {
            return $true
        }
    }
    return $false
}

$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$toRemove = @(
    $request.previous | Where-Object {
        -not (Contains-Route $request.desired $_)
    }
)
$toAdd = @(
    $request.desired | Where-Object {
        -not (Contains-Route $request.previous $_)
    }
)
$removed = [Collections.Generic.List[object]]::new()
$added = [Collections.Generic.List[object]]::new()
$cleanupOnly = @($request.desired).Count -eq 0
$cleanupFailures = [Collections.Generic.List[string]]::new()

try {
    foreach ($route in $toAdd) {
        $ipInterface = Get-NetIPInterface `
            -AddressFamily IPv4 `
            -InterfaceIndex ([uint32]$route.interface_index) `
            -IncludeAllCompartments `
            -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.ConnectionState -eq 'Connected' } |
            Select-Object -First 1
        if ($null -eq $ipInterface) {
            throw "IP 介面 ifIndex $($route.interface_index) 尚未連線。"
        }

        $existing = @(Find-ExactRoute $route)
        if ($existing.Count -gt 0) {
            throw "路由 $($route.prefix) 已存在相同介面、閘道及 metric 的項目；為避免刪到非本程式建立的路由，已停止套用。"
        }
    }

    foreach ($route in $toRemove) {
        $existing = @(Find-ExactRoute $route)
        if ($existing.Count -gt 0) {
            try {
                $existing[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                $removed.Add($route)
            } catch {
                if (-not $cleanupOnly) {
                    throw
                }
                $cleanupFailures.Add("$($route.prefix): $($_.Exception.Message)")
            }
        }
    }

    if ($cleanupFailures.Count -gt 0) {
        throw "部分路由清理失敗：$($cleanupFailures -join '；')"
    }

    foreach ($route in $toAdd) {
        New-NetRoute `
            -AddressFamily IPv4 `
            -DestinationPrefix ([string]$route.prefix) `
            -InterfaceIndex ([uint32]$route.interface_index) `
            -NextHop ([string]$route.next_hop) `
            -RouteMetric ([uint32]$route.route_metric) `
            -PolicyStore ActiveStore `
            -ErrorAction Stop |
            Out-Null
        $added.Add($route)
    }

    [pscustomobject]@{
        ok = $true
        message = "已套用 $($request.desired.Count) 條分流路由。"
    } | ConvertTo-Json -Compress
} catch {
    $failure = $_.Exception.Message

    if (-not $cleanupOnly) {
        for ($index = $added.Count - 1; $index -ge 0; $index--) {
            try {
                $existing = @(Find-ExactRoute $added[$index])
                if ($existing.Count -gt 0) {
                    $existing[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                }
            } catch {}
        }

        foreach ($route in $removed) {
            try {
                $existing = @(Find-ExactRoute $route)
                if ($existing.Count -eq 0) {
                    New-NetRoute `
                        -AddressFamily IPv4 `
                        -DestinationPrefix ([string]$route.prefix) `
                        -InterfaceIndex ([uint32]$route.interface_index) `
                        -NextHop ([string]$route.next_hop) `
                        -RouteMetric ([uint32]$route.route_metric) `
                        -PolicyStore ActiveStore `
                        -ErrorAction Stop |
                        Out-Null
                }
            } catch {}
        }
    }

    [pscustomobject]@{
        ok = $false
        message = if ($cleanupOnly) {
            "路由清理未完全成功，已保留成功刪除的結果：$failure"
        } else {
            "套用失敗，已嘗試回復原有路由：$failure"
        }
    } | ConvertTo-Json -Compress
    exit 1
}
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub status: String,
    pub next_hop: String,
    pub has_default_route: bool,
}

impl NetworkAdapter {
    pub fn matches(&self, vpn: VpnKind) -> bool {
        let label = format!("{} {}", self.name, self.description).to_ascii_lowercase();
        match vpn {
            VpnKind::FortiClient => label.contains("forti"),
            VpnKind::F5 => label.contains("f5") || label.contains("big-ip"),
            VpnKind::Ivanti => {
                label.contains("ivanti")
                    || label.contains("juniper")
                    || label.contains("pulse secure")
            }
        }
    }

    pub fn is_up(&self) -> bool {
        self.status.eq_ignore_ascii_case("up")
    }

    pub fn display_label(&self) -> String {
        format!(
            "{} · ifIndex {} · {}",
            self.description, self.index, self.status
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternetGateway {
    pub interface_index: u32,
    pub interface_alias: String,
    pub interface_description: String,
    pub next_hop: String,
    pub inferred_from_escape_route: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRoutePurpose {
    #[default]
    Target,
    InternetBypass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRoute {
    pub vpn: VpnKind,
    #[serde(default)]
    pub purpose: ManagedRoutePurpose,
    pub prefix: String,
    pub interface_index: u32,
    pub next_hop: String,
    pub route_metric: u16,
}

#[derive(Deserialize)]
struct ApplyResponse {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
struct RouteRequest<'a> {
    previous: &'a [ManagedRoute],
    desired: &'a [ManagedRoute],
}

struct PowerShellOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

pub(crate) fn discover_vpn_adapters(
    cancellation: &AtomicBool,
) -> Result<Vec<NetworkAdapter>, String> {
    let output =
        run_powershell_with_cancellation(DISCOVER_ADAPTERS_SCRIPT, "", Some(cancellation))?;
    if !output.success {
        return Err(powershell_failure(&output));
    }

    let mut adapters: Vec<NetworkAdapter> = serde_json::from_str(output.stdout.trim())
        .map_err(|error| format!("無法解析 Windows 網路介面資料：{error}"))?;
    adapters.sort_by_key(|adapter| (!adapter.is_up(), adapter.description.clone()));
    Ok(adapters)
}

pub(crate) fn discover_internet_gateway(
    cancellation: &AtomicBool,
) -> Result<Option<InternetGateway>, String> {
    let output =
        run_powershell_with_cancellation(DISCOVER_INTERNET_GATEWAY_SCRIPT, "", Some(cancellation))?;
    if !output.success {
        return Err(powershell_failure(&output));
    }

    serde_json::from_str(output.stdout.trim())
        .map_err(|error| format!("無法解析一般網路閘道資料：{error}"))
}

pub fn existing_managed_routes(routes: &[ManagedRoute]) -> Result<Vec<ManagedRoute>, String> {
    if routes.is_empty() {
        return Ok(Vec::new());
    }

    let mut table = ptr::null_mut();
    // SAFETY: `table` is a valid out pointer. On success Windows allocates the
    // returned table, which is held by `MibTableGuard` and released exactly once.
    let error = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if error != 0 {
        return Err(format!(
            "無法讀取 Windows IPv4 路由表：{}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    if table.is_null() {
        return Err("Windows IPv4 路由表查詢成功但未回傳資料。".to_owned());
    }
    let _guard = MibTableGuard(table);

    // SAFETY: `GetIpForwardTable2` returned a table containing `NumEntries`
    // contiguous rows beginning at `Table` for the guard's lifetime.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };

    Ok(routes
        .iter()
        .filter(|route| rows.iter().any(|row| route_row_matches(row, route)))
        .cloned()
        .collect())
}

struct MibTableGuard(*mut MIB_IPFORWARD_TABLE2);

impl Drop for MibTableGuard {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `GetIpForwardTable2` and this guard is
        // the sole owner responsible for releasing it.
        unsafe {
            FreeMibTable(self.0.cast());
        }
    }
}

fn route_row_matches(row: &MIB_IPFORWARD_ROW2, route: &ManagedRoute) -> bool {
    let Some(destination) = sockaddr_ipv4(row.DestinationPrefix.Prefix) else {
        return false;
    };
    let Some(next_hop) = sockaddr_ipv4(row.NextHop) else {
        return false;
    };

    row.InterfaceIndex == route.interface_index
        && row.Metric == u32::from(route.route_metric)
        && format!("{destination}/{}", row.DestinationPrefix.PrefixLength) == route.prefix
        && next_hop.to_string() == route.next_hop
}

fn sockaddr_ipv4(address: SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: reading `si_family` determines which union member is active; an
    // AF_INET address contains a valid `Ipv4`/`IN_ADDR` representation.
    unsafe {
        if address.si_family != AF_INET {
            return None;
        }
        Some(Ipv4Addr::from(u32::from_be(
            address.Ipv4.sin_addr.S_un.S_addr,
        )))
    }
}

pub fn apply_routes(previous: &[ManagedRoute], desired: &[ManagedRoute]) -> Result<String, String> {
    let request = serde_json::to_string(&RouteRequest { previous, desired })
        .map_err(|error| format!("無法建立路由套用要求：{error}"))?;
    let output = run_powershell(APPLY_ROUTES_SCRIPT, &request)?;

    if let Ok(response) = serde_json::from_str::<ApplyResponse>(output.stdout.trim()) {
        if response.ok && output.success {
            Ok(response.message)
        } else {
            Err(response.message)
        }
    } else {
        Err(powershell_failure(&output))
    }
}

fn run_powershell(script: &str, stdin_text: &str) -> Result<PowerShellOutput, String> {
    run_powershell_with_cancellation(script, stdin_text, None)
}

fn run_powershell_with_cancellation(
    script: &str,
    stdin_text: &str,
    cancellation: Option<&AtomicBool>,
) -> Result<PowerShellOutput, String> {
    if cancellation.is_some_and(|token| token.load(Ordering::Acquire)) {
        return Err("PowerShell 工作已取消。".to_owned());
    }

    let mut child = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| format!("無法啟動 Windows PowerShell：{error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_text.as_bytes())
            .map_err(|error| format!("無法傳送資料給 Windows PowerShell：{error}"))?;
    }

    if let Some(cancellation) = cancellation {
        loop {
            if cancellation.load(Ordering::Acquire) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("PowerShell 工作已取消。".to_owned());
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    return Err(format!("檢查 Windows PowerShell 狀態時發生錯誤：{error}"));
                }
            }
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("等待 Windows PowerShell 時發生錯誤：{error}"))?;

    Ok(PowerShellOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn powershell_failure(output: &PowerShellOutput) -> String {
    let stderr = output.stderr.trim();
    let stdout = output.stdout.trim();

    if !stderr.is_empty() {
        format!("Windows PowerShell 執行失敗：{stderr}")
    } else if !stdout.is_empty() {
        format!("Windows PowerShell 執行失敗：{stdout}")
    } else {
        "Windows PowerShell 執行失敗，沒有回傳詳細訊息。".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const F5_RAS_FIXTURE: &str = r#"
$env:APPDATA = 'C:\Fixture\AppData'
$env:PROGRAMDATA = 'C:\Fixture\ProgramData'

function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath)

    return $LiteralPath -like '*\rasphone.pbk'
}

function Get-Content {
    [CmdletBinding()]
    param([string]$LiteralPath)

    @(
        '[_Common_SSLVPN-NA_V - sslvpn.example.test]',
        'Type=1',
        'MEDIA=rastapi',
        'Device=F5 Networks VPN Adapter',
        'DEVICE=rastapi'
    )
}

function Get-NetAdapter {
    [CmdletBinding()]
    param(
        [switch]$IncludeHidden,
        [uint32]$InterfaceIndex
    )

    $adapters = @(
        [pscustomobject]@{
            ifIndex = [uint32]18
            Name = 'Local Area Connection* 11'
            InterfaceDescription = 'F5 Networks VPN Adapter'
            Status = 'Disconnected'
        }
    )

    if ($PSBoundParameters.ContainsKey('InterfaceIndex')) {
        return $adapters | Where-Object { $_.ifIndex -eq $InterfaceIndex }
    }

    return $adapters
}

function Get-NetIPConfiguration {
    [CmdletBinding()]
    param(
        [switch]$All,
        [switch]$AllCompartments
    )

    [pscustomobject]@{
        InterfaceIndex = [uint32]43
        InterfaceAlias = '_Common_SSLVPN-NA_V - sslvpn.example.test'
        InterfaceDescription = ''
        IPv4Address = @(
            [pscustomobject]@{ IPAddress = '203.0.113.186' }
        )
    }
}

function Get-NetIPInterface {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [uint32]$InterfaceIndex,
        [switch]$IncludeAllCompartments
    )

    if ($InterfaceIndex -eq 43) {
        [pscustomobject]@{
            InterfaceIndex = [uint32]43
            InterfaceAlias = '_Common_SSLVPN-NA_V - sslvpn.example.test'
            ConnectionState = 'Connected'
        }
    } elseif ($InterfaceIndex -eq 7) {
        [pscustomobject]@{
            InterfaceIndex = [uint32]7
            InterfaceAlias = 'Wi-Fi'
            ConnectionState = 'Connected'
        }
    }
}

function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [uint32]$InterfaceIndex,
        [string]$PolicyStore
    )

    if ($InterfaceIndex -eq 43) {
        [pscustomobject]@{
            DestinationPrefix = '0.0.0.0/0'
            NextHop = '0.0.0.0'
            RouteMetric = [uint32]1
        }
    }
}
"#;

    const F5_RAS_APPLY_FIXTURE: &str = r#"
function Get-NetAdapter {
    [CmdletBinding()]
    param(
        [switch]$IncludeHidden,
        [uint32]$InterfaceIndex
    )

    # The live RAS/PPP interface is intentionally absent from Get-NetAdapter.
}

function Get-NetIPInterface {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [uint32]$InterfaceIndex,
        [switch]$IncludeAllCompartments
    )

    if ($InterfaceIndex -eq 43) {
        [pscustomobject]@{
            InterfaceIndex = [uint32]43
            InterfaceAlias = '_Common_SSLVPN-NA_V - sslvpn.example.test'
            ConnectionState = 'Connected'
        }
    } elseif ($InterfaceIndex -eq 7) {
        [pscustomobject]@{
            InterfaceIndex = [uint32]7
            InterfaceAlias = 'Wi-Fi'
            ConnectionState = 'Connected'
        }
    }
}

function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [string]$DestinationPrefix,
        [uint32]$InterfaceIndex,
        [string]$PolicyStore
    )

    # The requested managed route does not exist yet.
}

function New-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [string]$DestinationPrefix,
        [uint32]$InterfaceIndex,
        [string]$NextHop,
        [uint32]$RouteMetric,
        [string]$PolicyStore
    )

    [pscustomobject]@{ DestinationPrefix = $DestinationPrefix }
}

function Remove-NetRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param()
}
"#;

    const F5_FULL_TUNNEL_GATEWAY_FIXTURE: &str = r#"
function Get-NetIPConfiguration {
    [CmdletBinding()]
    param(
        [switch]$All,
        [switch]$AllCompartments
    )

    [pscustomobject]@{
        InterfaceIndex = [uint32]7
        InterfaceAlias = 'Wi-Fi'
        InterfaceDescription = 'Physical Wi-Fi Adapter'
        IPv4Address = @(
            [pscustomobject]@{ IPAddress = '192.0.2.46' }
        )
    }
}

function Get-NetIPInterface {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [uint32]$InterfaceIndex,
        [switch]$IncludeAllCompartments
    )

    if ($InterfaceIndex -eq 7) {
        [pscustomobject]@{
            InterfaceIndex = [uint32]7
            InterfaceAlias = 'Wi-Fi'
            InterfaceMetric = [uint32]30
            ConnectionState = 'Connected'
        }
    }
}

function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [string]$PolicyStore
    )

    @(
        [pscustomobject]@{
            InterfaceIndex = [uint32]43
            DestinationPrefix = '0.0.0.0/0'
            NextHop = '0.0.0.0'
            RouteMetric = [uint32]1
        },
        [pscustomobject]@{
            InterfaceIndex = [uint32]7
            DestinationPrefix = '198.51.100.25/32'
            NextHop = '192.0.2.1'
            RouteMetric = [uint32]30
        }
    )
}
"#;

    const BEST_EFFORT_CLEANUP_FIXTURE: &str = r#"
$script:fixtureRoutes = @(
    [pscustomobject]@{
        DestinationPrefix = '0.0.0.0/2'
        InterfaceIndex = [uint32]7
        NextHop = '192.0.2.1'
        RouteMetric = [uint32]5
    },
    [pscustomobject]@{
        DestinationPrefix = '64.0.0.0/2'
        InterfaceIndex = [uint32]7
        NextHop = '192.0.2.1'
        RouteMetric = [uint32]5
    }
)

function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [string]$DestinationPrefix,
        [uint32]$InterfaceIndex,
        [string]$PolicyStore
    )

    $script:fixtureRoutes | Where-Object {
        $_.DestinationPrefix -eq $DestinationPrefix -and
        $_.InterfaceIndex -eq $InterfaceIndex
    }
}

function Remove-NetRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]$InputObject
    )
    process {
        if ($InputObject.DestinationPrefix -eq '0.0.0.0/2') {
            throw 'fixture permanent removal failure'
        }
        [Console]::Error.WriteLine("FIXTURE_REMOVED:$($InputObject.DestinationPrefix)")
        $removedPrefix = [string]$InputObject.DestinationPrefix
        $script:fixtureRoutes = @(
            $script:fixtureRoutes | Where-Object {
                [string]$_.DestinationPrefix -ne $removedPrefix
            }
        )
    }
}
"#;

    #[test]
    fn discovers_connected_f5_ras_interface() {
        let script = format!("{F5_RAS_FIXTURE}\n{DISCOVER_ADAPTERS_SCRIPT}");
        let output = run_powershell(&script, "").expect("fixture discovery should run");
        assert!(output.success, "{}", powershell_failure(&output));

        let adapters: Vec<NetworkAdapter> =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(
            adapters.iter().any(|adapter| adapter.index == 18),
            "the installed F5 adapter should remain available as a disconnected candidate"
        );
        let connected_f5 = adapters
            .iter()
            .find(|adapter| adapter.index == 43)
            .expect("the connected F5 RAS interface must be discovered");

        assert!(connected_f5.matches(VpnKind::F5));
        assert!(connected_f5.is_up());
        assert!(connected_f5.has_default_route);
    }

    #[test]
    fn uncancelled_powershell_still_collects_its_output() {
        let cancellation = AtomicBool::new(false);

        let output = run_powershell_with_cancellation(
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); Write-Output 'ready'",
            "",
            Some(&cancellation),
        )
        .expect("uncancelled PowerShell must complete");

        assert!(output.success);
        assert_eq!(output.stdout.trim(), "ready");
        assert!(output.stderr.trim().is_empty());
    }

    #[test]
    fn cancellation_stops_powershell_without_waiting_for_the_script() {
        let cancellation = std::sync::Arc::new(AtomicBool::new(false));
        let worker_cancellation = std::sync::Arc::clone(&cancellation);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            worker_cancellation.store(true, Ordering::Release);
        });
        let started = std::time::Instant::now();

        let error = match run_powershell_with_cancellation(
            "Start-Sleep -Seconds 10",
            "",
            Some(&cancellation),
        ) {
            Ok(_) => panic!("cancelled PowerShell must not complete normally"),
            Err(error) => error,
        };
        canceller.join().expect("cancellation helper must finish");

        assert!(error.contains("已取消"), "unexpected error: {error}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancellation must stop PowerShell promptly; elapsed={:?}",
            started.elapsed()
        );
    }

    #[test]
    fn periodic_managed_route_lookup_does_not_pay_powershell_startup_cost() {
        let candidate = ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::Target,
            prefix: "198.51.100.253/32".to_owned(),
            interface_index: 7,
            next_hop: "0.0.0.0".to_owned(),
            route_metric: u16::MAX,
        };
        let started = std::time::Instant::now();

        existing_managed_routes(&[candidate]).expect("native route lookup should succeed");

        assert!(
            started.elapsed() < std::time::Duration::from_millis(300),
            "a five-second health check must not launch Windows PowerShell; elapsed={:?}",
            started.elapsed()
        );
    }

    #[test]
    fn native_route_row_matching_uses_exact_prefix_endpoint_and_metric() {
        fn sockaddr(address: Ipv4Addr) -> SOCKADDR_INET {
            let mut value = SOCKADDR_INET::default();
            value.Ipv4.sin_family = AF_INET;
            value.Ipv4.sin_addr.S_un.S_addr = u32::from(address).to_be();
            value
        }

        let row = MIB_IPFORWARD_ROW2 {
            InterfaceIndex: 7,
            DestinationPrefix: windows_sys::Win32::NetworkManagement::IpHelper::IP_ADDRESS_PREFIX {
                Prefix: sockaddr(Ipv4Addr::new(64, 0, 0, 0)),
                PrefixLength: 2,
            },
            NextHop: sockaddr(Ipv4Addr::new(192, 0, 2, 1)),
            Metric: 5,
            ..Default::default()
        };
        let route = ManagedRoute {
            vpn: VpnKind::F5,
            purpose: ManagedRoutePurpose::InternetBypass,
            prefix: "64.0.0.0/2".to_owned(),
            interface_index: 7,
            next_hop: "192.0.2.1".to_owned(),
            route_metric: 5,
        };

        assert!(route_row_matches(&row, &route));

        let row = MIB_IPFORWARD_ROW2 { Metric: 6, ..row };
        assert!(
            !route_row_matches(&row, &route),
            "a route modified by another process must not be mistaken for our exact route"
        );
    }

    #[test]
    fn applies_route_to_connected_f5_ras_interface() {
        let routes = vec![
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::Target,
                prefix: "203.0.113.10/32".to_owned(),
                interface_index: 43,
                next_hop: "0.0.0.0".to_owned(),
                route_metric: 5,
            },
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::InternetBypass,
                prefix: "0.0.0.0/1".to_owned(),
                interface_index: 7,
                next_hop: "192.0.2.1".to_owned(),
                route_metric: 5,
            },
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::InternetBypass,
                prefix: "128.0.0.0/1".to_owned(),
                interface_index: 7,
                next_hop: "192.0.2.1".to_owned(),
                route_metric: 5,
            },
        ];
        let request = serde_json::to_string(&RouteRequest {
            previous: &[],
            desired: &routes,
        })
        .expect("route request should serialize");
        let script = format!("{F5_RAS_APPLY_FIXTURE}\n{APPLY_ROUTES_SCRIPT}");
        let output = run_powershell(&script, &request).expect("fixture apply should run");

        assert!(output.success, "{}", powershell_failure(&output));
        let response: ApplyResponse =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(response.ok, "{}", response.message);
    }

    #[test]
    fn infers_physical_gateway_from_f5_server_escape_route() {
        let script =
            format!("{F5_FULL_TUNNEL_GATEWAY_FIXTURE}\n{DISCOVER_INTERNET_GATEWAY_SCRIPT}");
        let output = run_powershell(&script, "").expect("fixture discovery should run");
        assert!(output.success, "{}", powershell_failure(&output));

        let gateway: Option<InternetGateway> =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        let gateway = gateway.expect("the F5 escape route should reveal the physical gateway");

        assert_eq!(gateway.interface_index, 7);
        assert_eq!(gateway.interface_alias, "Wi-Fi");
        assert_eq!(gateway.next_hop, "192.0.2.1");
        assert!(gateway.inferred_from_escape_route);
    }

    #[test]
    fn shutdown_cleanup_keeps_removing_routes_after_one_failure() {
        let routes = vec![
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::InternetBypass,
                prefix: "0.0.0.0/2".to_owned(),
                interface_index: 7,
                next_hop: "192.0.2.1".to_owned(),
                route_metric: 5,
            },
            ManagedRoute {
                vpn: VpnKind::F5,
                purpose: ManagedRoutePurpose::InternetBypass,
                prefix: "64.0.0.0/2".to_owned(),
                interface_index: 7,
                next_hop: "192.0.2.1".to_owned(),
                route_metric: 5,
            },
        ];
        let request = serde_json::to_string(&RouteRequest {
            previous: &routes,
            desired: &[],
        })
        .expect("cleanup request should serialize");
        let script = format!("{BEST_EFFORT_CLEANUP_FIXTURE}\n{APPLY_ROUTES_SCRIPT}");

        let output = run_powershell(&script, &request).expect("fixture cleanup should run");

        assert!(
            !output.success,
            "one route is expected to remain in the fixture"
        );
        assert!(
            output.stderr.contains("FIXTURE_REMOVED:64.0.0.0/2"),
            "cleanup must continue past the first route failure: {}",
            output.stderr
        );
    }

    #[test]
    fn named_mutex_rejects_a_second_app_instance_and_recovers_after_close() {
        let unique_name = format!(
            "Local\\tw.layton.rust-vpn-splitter-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let first = acquire_named_mutex(&unique_name)
            .expect("first mutex acquisition should succeed")
            .expect("first app instance should own the mutex");

        assert!(
            acquire_named_mutex(&unique_name)
                .expect("second mutex call should be valid")
                .is_none(),
            "a second app instance must be rejected"
        );

        drop(first);
        assert!(
            acquire_named_mutex(&unique_name)
                .expect("mutex should remain usable after close")
                .is_some(),
            "normal close or process termination must release the named mutex"
        );
    }
}
