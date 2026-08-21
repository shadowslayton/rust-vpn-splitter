use std::{net::Ipv4Addr, ptr, sync::atomic::AtomicBool};

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

mod powershell;

use self::powershell::{Mutation as PowerShellMutation, Query as PowerShellQuery};

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
            $ipInterface = Get-NetIPInterface `
                -AddressFamily IPv4 `
                -InterfaceIndex ([uint32]$candidate.index) `
                -IncludeAllCompartments `
                -ErrorAction SilentlyContinue |
                Sort-Object InterfaceMetric |
                Select-Object -First 1
            $interfaceMetric = if ($null -eq $ipInterface) {
                [uint32]0
            } else {
                [uint32]$ipInterface.InterfaceMetric
            }

            $coverageSets = @(
                [pscustomobject]@{
                    prefixLength = [byte]4
                    prefixes = @(
                        '0.0.0.0/4', '16.0.0.0/4', '32.0.0.0/4', '48.0.0.0/4',
                        '64.0.0.0/4', '80.0.0.0/4', '96.0.0.0/4', '112.0.0.0/4',
                        '128.0.0.0/4', '144.0.0.0/4', '160.0.0.0/4', '176.0.0.0/4',
                        '192.0.0.0/4', '208.0.0.0/4', '224.0.0.0/4', '240.0.0.0/4'
                    )
                }
                [pscustomobject]@{
                    prefixLength = [byte]3
                    prefixes = @(
                        '0.0.0.0/3', '32.0.0.0/3', '64.0.0.0/3', '96.0.0.0/3',
                        '128.0.0.0/3', '160.0.0.0/3', '192.0.0.0/3', '224.0.0.0/3'
                    )
                }
                [pscustomobject]@{
                    prefixLength = [byte]2
                    prefixes = @('0.0.0.0/2', '64.0.0.0/2', '128.0.0.0/2', '192.0.0.0/2')
                }
                [pscustomobject]@{
                    prefixLength = [byte]1
                    prefixes = @('0.0.0.0/1', '128.0.0.0/1')
                }
            )
            $defaultRoutes = @(
                $routes |
                    Where-Object { [string]$_.DestinationPrefix -eq '0.0.0.0/0' } |
                    Sort-Object RouteMetric
            )
            $fullTunnelPrefixLength = $null
            $fullTunnelRoutes = @()
            foreach ($coverageSet in $coverageSets) {
                $coverageRoutes = @(
                    foreach ($prefix in @($coverageSet.prefixes)) {
                        $routes |
                            Where-Object { [string]$_.DestinationPrefix -eq $prefix } |
                            Sort-Object RouteMetric |
                            Select-Object -First 1
                    }
                )
                if ($coverageRoutes.Count -eq @($coverageSet.prefixes).Count) {
                    $fullTunnelPrefixLength = [byte]$coverageSet.prefixLength
                    $fullTunnelRoutes = $coverageRoutes
                    break
                }
            }
            if ($null -eq $fullTunnelPrefixLength -and $defaultRoutes.Count -gt 0) {
                $fullTunnelPrefixLength = [byte]0
                $fullTunnelRoutes = @($defaultRoutes | Select-Object -First 1)
            }
            $fullTunnelPriority = $null
            if ($null -ne $fullTunnelPrefixLength -and $null -ne $ipInterface) {
                $effectiveMetric = @(
                    $fullTunnelRoutes |
                        ForEach-Object {
                            [uint32]$_.RouteMetric + [uint32]$interfaceMetric
                        } |
                        Measure-Object -Maximum
                ).Maximum
                $fullTunnelPriority = [pscustomobject]@{
                    prefix_length = [byte]$fullTunnelPrefixLength
                    effective_metric = [uint32]$effectiveMetric
                }
            }

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

            $nextHop = if ($fullTunnelRoutes.Count -gt 0) {
                [string]$fullTunnelRoutes[0].NextHop
            } elseif ($null -eq $gatewayRoute) {
                '0.0.0.0'
            } else {
                [string]$gatewayRoute.NextHop
            }
            $dnsServers = @(
                Get-DnsClientServerAddress `
                    -InterfaceIndex ([uint32]$candidate.index) `
                    -AddressFamily IPv4 `
                    -ErrorAction SilentlyContinue |
                    ForEach-Object { @($_.ServerAddresses) } |
                    Where-Object {
                        try {
                            ([ipaddress]([string]$_)).AddressFamily -eq
                                [Net.Sockets.AddressFamily]::InterNetwork
                        } catch {
                            $false
                        }
                    } |
                    Select-Object -Unique
            )

            [pscustomobject]@{
                index = [uint32]$candidate.index
                name = [string]$candidate.name
                description = [string]$candidate.description
                status = [string]$candidate.status
                next_hop = $nextHop
                full_tunnel_priority = $fullTunnelPriority
                dns_servers = @($dnsServers)
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
    $routePriority = $null
    if (-not $inferred -and [string]$selectedRoute.DestinationPrefix -eq '0.0.0.0/0') {
        $routePriority = [pscustomobject]@{
            prefix_length = [byte]0
            effective_metric = [uint32]$selectedRoute.RouteMetric + [uint32]$interface.interface_metric
        }
    }
    $dnsServers = @(
        Get-DnsClientServerAddress `
            -InterfaceIndex ([uint32]$selectedRoute.InterfaceIndex) `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
            ForEach-Object { @($_.ServerAddresses) } |
            Where-Object {
                try {
                    ([ipaddress]([string]$_)).AddressFamily -eq
                        [Net.Sockets.AddressFamily]::InterNetwork
                } catch {
                    $false
                }
            } |
            Select-Object -Unique
    )
    $fallbackDnsServers = @()
    $netAdapter = Get-NetAdapter `
        -IncludeHidden `
        -InterfaceIndex ([uint32]$selectedRoute.InterfaceIndex) `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $netAdapter -and $null -ne $netAdapter.InterfaceGuid) {
        $registryPath =
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($netAdapter.InterfaceGuid)"
        $interfaceSettings = Get-ItemProperty `
            -LiteralPath $registryPath `
            -ErrorAction SilentlyContinue
        if ($null -ne $interfaceSettings) {
            $fallbackDnsServers = @(
                @(
                    ([string]$interfaceSettings.NameServer) -split '[,\s]+'
                    ([string]$interfaceSettings.DhcpNameServer) -split '[,\s]+'
                ) |
                    Where-Object {
                        try {
                            ([ipaddress]([string]$_)).AddressFamily -eq
                                [Net.Sockets.AddressFamily]::InterNetwork
                        } catch {
                            $false
                        }
                    } |
                    Select-Object -Unique
            )
        }
    }
    [pscustomobject]@{
        interface_index = [uint32]$selectedRoute.InterfaceIndex
        interface_alias = [string]$interface.alias
        interface_description = [string]$interface.description
        next_hop = [string]$selectedRoute.NextHop
        inferred_from_escape_route = [bool]$inferred
        route_priority = $routePriority
        dns_servers = @($dnsServers)
        fallback_dns_servers = @($fallbackDnsServers)
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

const APPLY_DNS_POLICY_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

$marker = 'tw.layton.rust-vpn-splitter'
$requestText = [Console]::In.ReadToEnd()
$request = $requestText | ConvertFrom-Json
$desired = @($request.rules)

function Normalized-Strings($values) {
    @($values | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
        Where-Object { $_ -ne '' } | Sort-Object -Unique)
}

function Same-StringSet($left, $right) {
    $leftValues = @(Normalized-Strings $left)
    $rightValues = @(Normalized-Strings $right)
    if ($leftValues.Count -ne $rightValues.Count) {
        return $false
    }
    return @(Compare-Object -ReferenceObject $leftValues -DifferenceObject $rightValues).Count -eq 0
}

function Same-Rule($left, $right) {
    (Same-StringSet $left.Namespace $right.namespaces) -and
        (Same-StringSet $left.NameServers $right.name_servers)
}

function Rules-Match($current, $wanted) {
    if (@($current).Count -ne @($wanted).Count) {
        return $false
    }
    foreach ($candidate in @($wanted)) {
        $matches = @($current | Where-Object { Same-Rule $_ $candidate })
        if ($matches.Count -ne 1) {
            return $false
        }
    }
    return $true
}

function Rule-Spec($rule) {
    [pscustomobject]@{
        vpn = $null
        namespaces = @(Normalized-Strings $rule.Namespace)
        name_servers = @(Normalized-Strings $rule.NameServers)
    }
}

function Add-ManagedRule($rule) {
    $owner = if ($null -eq $rule.vpn -or [string]::IsNullOrWhiteSpace([string]$rule.vpn)) {
        'current-network'
    } else {
        ([string]$rule.vpn).ToLowerInvariant()
    }
    Add-DnsClientNrptRule `
        -Namespace @($rule.namespaces) `
        -NameServers @($rule.name_servers) `
        -Comment $marker `
        -DisplayName "VPN Splitter: $owner" `
        -PassThru `
        -ErrorAction Stop
}

$allRules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
$current = @($allRules | Where-Object { [string]$_.Comment -eq $marker })
$foreign = @($allRules | Where-Object { [string]$_.Comment -ne $marker })

foreach ($wanted in $desired) {
    foreach ($namespace in @($wanted.namespaces)) {
        $conflict = $foreign | Where-Object {
            @(Normalized-Strings $_.Namespace) -contains
                ([string]$namespace).Trim().ToLowerInvariant()
        } | Select-Object -First 1
        if ($null -ne $conflict) {
            [pscustomobject]@{
                ok = $false
                changed = $false
                message = "DNS namespace $namespace 已由其他 NRPT 規則管理，為避免覆寫系統或公司原有設定，已停止套用。"
            } | ConvertTo-Json -Compress
            exit 1
        }
    }
}

if (Rules-Match $current $desired) {
    [pscustomobject]@{
        ok = $true
        changed = $false
        message = "DNS 分流規則已是最新狀態。"
    } | ConvertTo-Json -Compress
    exit 0
}

$removed = [Collections.Generic.List[object]]::new()
$added = [Collections.Generic.List[object]]::new()
try {
    foreach ($rule in $current) {
        $spec = Rule-Spec $rule
        Remove-DnsClientNrptRule -Name ([string]$rule.Name) -Force -ErrorAction Stop
        $removed.Add($spec)
    }

    foreach ($rule in $desired) {
        $created = Add-ManagedRule $rule
        $added.Add($created)
    }

    Clear-DnsClientCache -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ok = $true
        changed = $true
        message = "已套用 $($desired.Count) 組 DNS 分流規則。"
    } | ConvertTo-Json -Compress
} catch {
    $failure = $_.Exception.Message
    foreach ($rule in $added) {
        try {
            Remove-DnsClientNrptRule -Name ([string]$rule.Name) -Force -ErrorAction Stop
        } catch {}
    }
    foreach ($rule in $removed) {
        try {
            Add-ManagedRule $rule | Out-Null
        } catch {}
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ok = $false
        changed = $false
        message = "套用 DNS 分流失敗，已嘗試回復原有規則：$failure"
    } | ConvertTo-Json -Compress
    exit 1
}
"#;

const RESOLVE_DNS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

$requestText = [Console]::In.ReadToEnd()
$request = $requestText | ConvertFrom-Json
$errors = [Collections.Generic.List[string]]::new()

foreach ($server in @($request.servers)) {
    try {
        $addresses = @(
            Resolve-DnsName `
                -Name ([string]$request.hostname) `
                -Type A `
                -Server ([string]$server) `
                -DnsOnly `
                -QuickTimeout `
                -ErrorAction Stop |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.IPAddress) } |
                ForEach-Object { [string]$_.IPAddress } |
                Sort-Object -Unique
        )
        if ($addresses.Count -gt 0) {
            [pscustomobject]@{
                ok = $true
                addresses = @($addresses)
                message = ""
            } | ConvertTo-Json -Compress
            exit 0
        }
        $errors.Add("$server 未回傳 IPv4 位址")
    } catch {
        $errors.Add("$server：$($_.Exception.Message)")
    }
}

[pscustomobject]@{
    ok = $false
    addresses = @()
    message = if ($errors.Count -eq 0) {
        '沒有可用的 IPv4 DNS server。'
    } else {
        $errors -join '；'
    }
} | ConvertTo-Json -Compress
exit 1
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePriority {
    pub prefix_length: u8,
    pub effective_metric: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub status: String,
    pub next_hop: String,
    #[serde(default)]
    pub full_tunnel_priority: Option<RoutePriority>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
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
    #[serde(default)]
    pub route_priority: Option<RoutePriority>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub fallback_dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRoutePurpose {
    #[default]
    Target,
    InternetBypass,
    VpnDnsServer,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedDnsRule {
    pub vpn: Option<VpnKind>,
    pub namespaces: Vec<String>,
    pub name_servers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsApplyResult {
    pub changed: bool,
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

#[derive(Serialize)]
struct DnsPolicyRequest<'a> {
    rules: &'a [ManagedDnsRule],
}

#[derive(Deserialize)]
struct DnsApplyResponse {
    ok: bool,
    changed: bool,
    message: String,
}

#[derive(Serialize)]
struct DnsResolutionRequest<'a> {
    hostname: &'a str,
    servers: &'a [String],
}

#[derive(Deserialize)]
struct DnsResolutionResponse {
    ok: bool,
    addresses: Vec<String>,
    message: String,
}

pub(crate) fn discover_vpn_adapters(
    cancellation: &AtomicBool,
) -> Result<Vec<NetworkAdapter>, String> {
    let output =
        powershell::run_query(PowerShellQuery::DiscoverVpnAdapters, "", Some(cancellation))?;
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
    let output = powershell::run_query(
        PowerShellQuery::DiscoverInternetGateway,
        "",
        Some(cancellation),
    )?;
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
    let output = powershell::run_mutation(PowerShellMutation::ApplyRoutes, &request, None)?;

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

pub fn apply_dns_policy(rules: &[ManagedDnsRule]) -> Result<DnsApplyResult, String> {
    apply_dns_policy_with_prestart_cancellation(rules, None)
}

pub(crate) fn apply_dns_policy_unless_cancelled_before_start(
    rules: &[ManagedDnsRule],
    cancellation: &AtomicBool,
) -> Result<DnsApplyResult, String> {
    apply_dns_policy_with_prestart_cancellation(rules, Some(cancellation))
}

fn apply_dns_policy_with_prestart_cancellation(
    rules: &[ManagedDnsRule],
    cancellation: Option<&AtomicBool>,
) -> Result<DnsApplyResult, String> {
    let request = serde_json::to_string(&DnsPolicyRequest { rules })
        .map_err(|error| format!("無法建立 DNS 分流套用要求：{error}"))?;
    let output =
        powershell::run_mutation(PowerShellMutation::ApplyDnsPolicy, &request, cancellation)?;

    if let Ok(response) = serde_json::from_str::<DnsApplyResponse>(output.stdout.trim()) {
        if response.ok && output.success {
            Ok(DnsApplyResult {
                changed: response.changed,
            })
        } else {
            Err(response.message)
        }
    } else {
        Err(powershell_failure(&output))
    }
}

pub fn resolve_ipv4_with_dns_servers(
    hostname: &str,
    servers: &[String],
) -> Result<Vec<Ipv4Addr>, String> {
    let request = serde_json::to_string(&DnsResolutionRequest { hostname, servers })
        .map_err(|error| format!("無法建立 DNS 解析要求：{error}"))?;
    let output = powershell::run_query(PowerShellQuery::ResolveIpv4, &request, None)?;

    if let Ok(response) = serde_json::from_str::<DnsResolutionResponse>(output.stdout.trim()) {
        if !response.ok || !output.success {
            return Err(response.message);
        }
        response
            .addresses
            .into_iter()
            .map(|address| {
                address
                    .parse::<Ipv4Addr>()
                    .map_err(|error| format!("DNS 回傳無效 IPv4 位址 {address}：{error}"))
            })
            .collect()
    } else {
        Err(powershell_failure(&output))
    }
}

fn powershell_failure(output: &powershell::Output) -> String {
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
    use std::{sync::atomic::Ordering, thread, time::Duration};

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

function Get-DnsClientServerAddress {
    [CmdletBinding()]
    param(
        [uint32]$InterfaceIndex,
        [string]$AddressFamily
    )

    if ($InterfaceIndex -eq 43) {
        [pscustomobject]@{ ServerAddresses = @('203.0.113.53') }
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

function Get-DnsClientServerAddress {
    [CmdletBinding()]
    param(
        [uint32]$InterfaceIndex,
        [string]$AddressFamily
    )

    if ($InterfaceIndex -eq 7) {
        [pscustomobject]@{
            ServerAddresses = @('203.0.113.53', '192.0.2.53')
        }
    }
}

function Get-NetAdapter {
    [CmdletBinding()]
    param(
        [switch]$IncludeHidden,
        [uint32]$InterfaceIndex
    )

    if ($InterfaceIndex -eq 7) {
        [pscustomobject]@{
            InterfaceGuid = '{00000000-0000-0000-0000-000000000007}'
        }
    }
}

function Get-ItemProperty {
    [CmdletBinding()]
    param(
        [string]$LiteralPath
    )

    [pscustomobject]@{
        NameServer = ''
        DhcpNameServer = '192.0.2.53'
    }
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

    const DNS_POLICY_FIXTURE: &str = r#"
$script:fixtureRules = @(
    [pscustomobject]@{
        Name = 'foreign-rule'
        Namespace = @('foreign.example.test')
        NameServers = @('192.0.2.200')
        Comment = 'owned-by-someone-else'
        DisplayName = 'Foreign rule'
    }
)
$script:nextRule = 0

function Get-DnsClientNrptRule {
    [CmdletBinding()]
    param()
    @($script:fixtureRules)
}

function Add-DnsClientNrptRule {
    [CmdletBinding()]
    param(
        [string[]]$Namespace,
        [string[]]$NameServers,
        [string]$Comment,
        [string]$DisplayName,
        [switch]$PassThru
    )
    if (
        -not [string]::IsNullOrWhiteSpace([string]$script:failNamespace) -and
        @($Namespace) -contains [string]$script:failNamespace
    ) {
        [Console]::Error.WriteLine("FIXTURE_ADD_FAILED:$script:failNamespace")
        throw "fixture rejected namespace $script:failNamespace"
    }
    $script:nextRule++
    $created = [pscustomobject]@{
        Name = "managed-$($script:nextRule)"
        Namespace = @($Namespace)
        NameServers = @($NameServers)
        Comment = $Comment
        DisplayName = $DisplayName
    }
    $script:fixtureRules += $created
    [Console]::Error.WriteLine(
        "FIXTURE_ADD:$($created.Name):$(@($Namespace) -join ','):$(@($NameServers) -join ',')"
    )
    if ($PassThru) {
        $created
    }
}

function Remove-DnsClientNrptRule {
    [CmdletBinding()]
    param(
        [string]$Name,
        [switch]$Force
    )
    [Console]::Error.WriteLine("FIXTURE_REMOVE:$Name")
    $script:fixtureRules = @($script:fixtureRules | Where-Object { $_.Name -ne $Name })
}

function Clear-DnsClientCache {
    [CmdletBinding()]
    param()
}
"#;

    const DNS_RESOLUTION_FIXTURE: &str = r#"
function Resolve-DnsName {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Type,
        [string]$Server,
        [switch]$DnsOnly,
        [switch]$QuickTimeout
    )
    if ($Name -eq 'service.example.test' -and $Server -eq '203.0.113.53') {
        [pscustomobject]@{ IPAddress = '198.51.100.20' }
        return
    }
    throw "fixture DNS server rejected $Name via $Server"
}
"#;

    #[test]
    fn discovers_connected_f5_ras_interface() {
        let script = format!("{F5_RAS_FIXTURE}\n{DISCOVER_ADAPTERS_SCRIPT}");
        let output =
            powershell::run_test_script(&script, "", None).expect("fixture discovery should run");
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
        assert_eq!(
            connected_f5.full_tunnel_priority,
            Some(RoutePriority {
                prefix_length: 0,
                effective_metric: 1,
            })
        );
        assert_eq!(connected_f5.dns_servers, vec!["203.0.113.53"]);
    }

    #[test]
    fn discovers_four_quarter_routes_as_a_more_specific_full_tunnel() {
        let quarter_routes = r#"
function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [uint32]$InterfaceIndex,
        [string]$PolicyStore
    )

    if ($InterfaceIndex -eq 43) {
        foreach ($prefix in @('0.0.0.0/2', '64.0.0.0/2', '128.0.0.0/2', '192.0.0.0/2')) {
            [pscustomobject]@{
                DestinationPrefix = $prefix
                NextHop = '0.0.0.0'
                RouteMetric = [uint32]7
            }
        }
    }
}
"#;
        let script = format!("{F5_RAS_FIXTURE}\n{quarter_routes}\n{DISCOVER_ADAPTERS_SCRIPT}");
        let output =
            powershell::run_test_script(&script, "", None).expect("fixture discovery should run");
        assert!(output.success, "{}", powershell_failure(&output));

        let adapters: Vec<NetworkAdapter> =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        let connected = adapters
            .iter()
            .find(|adapter| adapter.index == 43)
            .expect("connected fixture adapter must be discovered");

        assert_eq!(
            connected.full_tunnel_priority,
            Some(RoutePriority {
                prefix_length: 2,
                effective_metric: 7,
            })
        );
    }

    #[test]
    fn discovers_sixteen_sixteenth_routes_as_a_more_specific_full_tunnel() {
        let sixteenth_routes = r#"
function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string]$AddressFamily,
        [uint32]$InterfaceIndex,
        [string]$PolicyStore
    )

    if ($InterfaceIndex -eq 43) {
        foreach ($prefix in @(
            '0.0.0.0/4', '16.0.0.0/4', '32.0.0.0/4', '48.0.0.0/4',
            '64.0.0.0/4', '80.0.0.0/4', '96.0.0.0/4', '112.0.0.0/4',
            '128.0.0.0/4', '144.0.0.0/4', '160.0.0.0/4', '176.0.0.0/4',
            '192.0.0.0/4', '208.0.0.0/4', '224.0.0.0/4', '240.0.0.0/4'
        )) {
            [pscustomobject]@{
                DestinationPrefix = $prefix
                NextHop = '0.0.0.0'
                RouteMetric = [uint32]7
            }
        }
    }
}
"#;
        let script = format!("{F5_RAS_FIXTURE}\n{sixteenth_routes}\n{DISCOVER_ADAPTERS_SCRIPT}");
        let output =
            powershell::run_test_script(&script, "", None).expect("fixture discovery should run");
        assert!(output.success, "{}", powershell_failure(&output));

        let adapters: Vec<NetworkAdapter> =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        let connected = adapters
            .iter()
            .find(|adapter| adapter.index == 43)
            .expect("connected fixture adapter must be discovered");

        assert_eq!(
            connected.full_tunnel_priority,
            Some(RoutePriority {
                prefix_length: 4,
                effective_metric: 7,
            })
        );
    }

    #[test]
    fn uncancelled_powershell_still_collects_its_output() {
        let cancellation = AtomicBool::new(false);

        let output = powershell::run_test_script(
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

        let error =
            match powershell::run_test_script("Start-Sleep -Seconds 10", "", Some(&cancellation)) {
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
    fn started_powershell_mutation_finishes_after_late_cancellation() {
        let cancellation = std::sync::Arc::new(AtomicBool::new(false));
        let worker_cancellation = std::sync::Arc::clone(&cancellation);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            worker_cancellation.store(true, Ordering::Release);
        });

        let output = powershell::run_test_mutation_script(
            "Start-Sleep -Milliseconds 300; Write-Output 'finished'",
            "",
            Some(&cancellation),
        )
        .expect("a PowerShell mutation that already started must finish");
        canceller.join().expect("cancellation helper must finish");

        assert!(output.success);
        assert_eq!(output.stdout.trim(), "finished");
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
        let output =
            powershell::run_test_script(&script, &request, None).expect("fixture apply should run");

        assert!(output.success, "{}", powershell_failure(&output));
        let response: ApplyResponse =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(response.ok, "{}", response.message);
    }

    #[test]
    fn infers_physical_gateway_from_f5_server_escape_route() {
        let script =
            format!("{F5_FULL_TUNNEL_GATEWAY_FIXTURE}\n{DISCOVER_INTERNET_GATEWAY_SCRIPT}");
        let output =
            powershell::run_test_script(&script, "", None).expect("fixture discovery should run");
        assert!(output.success, "{}", powershell_failure(&output));

        let gateway: Option<InternetGateway> =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        let gateway = gateway.expect("the F5 escape route should reveal the physical gateway");

        assert_eq!(gateway.interface_index, 7);
        assert_eq!(gateway.interface_alias, "Wi-Fi");
        assert_eq!(gateway.next_hop, "192.0.2.1");
        assert!(gateway.inferred_from_escape_route);
        assert_eq!(gateway.dns_servers, vec!["203.0.113.53", "192.0.2.53"]);
        assert_eq!(gateway.fallback_dns_servers, vec!["192.0.2.53"]);
    }

    #[test]
    fn applies_current_network_and_all_three_vpn_dns_rules() {
        let rules = vec![
            ManagedDnsRule {
                vpn: None,
                namespaces: vec![".".to_owned()],
                name_servers: vec!["192.0.2.53".to_owned()],
            },
            ManagedDnsRule {
                vpn: Some(VpnKind::FortiClient),
                namespaces: vec!["forti.example.test".to_owned()],
                name_servers: vec!["203.0.113.51".to_owned()],
            },
            ManagedDnsRule {
                vpn: Some(VpnKind::F5),
                namespaces: vec!["f5.example.test".to_owned()],
                name_servers: vec!["203.0.113.52".to_owned()],
            },
            ManagedDnsRule {
                vpn: Some(VpnKind::Ivanti),
                namespaces: vec!["ivanti.example.test".to_owned()],
                name_servers: vec!["203.0.113.53".to_owned()],
            },
        ];
        let request = serde_json::to_string(&DnsPolicyRequest { rules: &rules })
            .expect("DNS policy request should serialize");
        let script = format!("{DNS_POLICY_FIXTURE}\n{APPLY_DNS_POLICY_SCRIPT}");

        let output = powershell::run_test_script(&script, &request, None)
            .expect("fixture DNS apply should run");

        assert!(output.success, "{}", powershell_failure(&output));
        let response: DnsApplyResponse =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(response.ok, "{}", response.message);
        assert!(response.changed);
        assert_eq!(output.stderr.matches("FIXTURE_ADD:").count(), 4);
        assert!(!output.stderr.contains("FIXTURE_REMOVE:foreign-rule"));
    }

    #[test]
    fn dns_cleanup_removes_only_rules_owned_by_this_app() {
        let request = serde_json::to_string(&DnsPolicyRequest { rules: &[] })
            .expect("DNS cleanup request should serialize");
        let prior_rule = r#"
$script:fixtureRules += [pscustomobject]@{
    Name = 'previous-managed-rule'
    Namespace = @('.')
    NameServers = @('192.0.2.53')
    Comment = 'tw.layton.rust-vpn-splitter'
    DisplayName = 'VPN Splitter: current-network'
}
"#;
        let script = format!("{DNS_POLICY_FIXTURE}\n{prior_rule}\n{APPLY_DNS_POLICY_SCRIPT}");

        let output = powershell::run_test_script(&script, &request, None)
            .expect("fixture DNS cleanup should run");

        assert!(output.success, "{}", powershell_failure(&output));
        let response: DnsApplyResponse =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(response.ok, "{}", response.message);
        assert!(response.changed);
        assert!(
            output
                .stderr
                .contains("FIXTURE_REMOVE:previous-managed-rule")
        );
        assert!(!output.stderr.contains("FIXTURE_REMOVE:foreign-rule"));
    }

    #[test]
    fn dns_apply_failure_restores_the_previous_managed_policy() {
        let rules = vec![
            ManagedDnsRule {
                vpn: None,
                namespaces: vec![".".to_owned()],
                name_servers: vec!["192.0.2.53".to_owned()],
            },
            ManagedDnsRule {
                vpn: Some(VpnKind::F5),
                namespaces: vec!["fail.example.test".to_owned()],
                name_servers: vec!["203.0.113.53".to_owned()],
            },
        ];
        let request = serde_json::to_string(&DnsPolicyRequest { rules: &rules })
            .expect("DNS policy request should serialize");
        let prior_rule = r#"
$script:fixtureRules += [pscustomobject]@{
    Name = 'previous-managed-rule'
    Namespace = @('.')
    NameServers = @('192.0.2.99')
    Comment = 'tw.layton.rust-vpn-splitter'
    DisplayName = 'VPN Splitter: current-network'
}
$script:failNamespace = 'fail.example.test'
"#;
        let script = format!("{DNS_POLICY_FIXTURE}\n{prior_rule}\n{APPLY_DNS_POLICY_SCRIPT}");

        let output = powershell::run_test_script(&script, &request, None)
            .expect("fixture DNS apply should run");

        assert!(!output.success);
        let response: DnsApplyResponse =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(!response.ok);
        assert!(!response.changed);
        assert!(
            output
                .stderr
                .contains("FIXTURE_REMOVE:previous-managed-rule")
        );
        assert!(
            output
                .stderr
                .contains("FIXTURE_ADD_FAILED:fail.example.test")
        );
        assert!(
            output.stderr.contains(":.:192.0.2.99"),
            "the previous catch-all rule must be restored: {}",
            output.stderr
        );
        assert!(!output.stderr.contains("FIXTURE_REMOVE:foreign-rule"));
    }

    #[test]
    fn resolves_a_vpn_hostname_through_the_requested_dns_server() {
        let servers = vec!["203.0.113.53".to_owned()];
        let request = serde_json::to_string(&DnsResolutionRequest {
            hostname: "service.example.test",
            servers: &servers,
        })
        .expect("DNS resolution request should serialize");
        let script = format!("{DNS_RESOLUTION_FIXTURE}\n{RESOLVE_DNS_SCRIPT}");

        let output = powershell::run_test_script(&script, &request, None)
            .expect("fixture DNS query should run");

        assert!(output.success, "{}", powershell_failure(&output));
        let response: DnsResolutionResponse =
            serde_json::from_str(output.stdout.trim()).expect("fixture output should be JSON");
        assert!(response.ok, "{}", response.message);
        assert_eq!(response.addresses, vec!["198.51.100.20"]);
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

        let output = powershell::run_test_script(&script, &request, None)
            .expect("fixture cleanup should run");

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
