use std::{
    io::Write,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use super::{
    APPLY_DNS_POLICY_SCRIPT, APPLY_ROUTES_SCRIPT, DISCOVER_ADAPTERS_SCRIPT,
    DISCOVER_INTERNET_GATEWAY_SCRIPT, RESOLVE_DNS_SCRIPT,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Query {
    DiscoverVpnAdapters,
    DiscoverInternetGateway,
    ResolveIpv4,
}

impl Query {
    fn script(self) -> &'static str {
        match self {
            Self::DiscoverVpnAdapters => DISCOVER_ADAPTERS_SCRIPT,
            Self::DiscoverInternetGateway => DISCOVER_INTERNET_GATEWAY_SCRIPT,
            Self::ResolveIpv4 => RESOLVE_DNS_SCRIPT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mutation {
    ApplyRoutes,
    ApplyDnsPolicy,
}

impl Mutation {
    fn script(self) -> &'static str {
        match self {
            Self::ApplyRoutes => APPLY_ROUTES_SCRIPT,
            Self::ApplyDnsPolicy => APPLY_DNS_POLICY_SCRIPT,
        }
    }
}

pub(super) struct Output {
    pub(super) success: bool,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

pub(super) fn run_query(
    query: Query,
    stdin_text: &str,
    cancellation: Option<&AtomicBool>,
) -> Result<Output, String> {
    run_script(query.script(), stdin_text, cancellation)
}

pub(super) fn run_mutation(
    mutation: Mutation,
    stdin_text: &str,
    cancellation_before_start: Option<&AtomicBool>,
) -> Result<Output, String> {
    run_mutation_script(mutation.script(), stdin_text, cancellation_before_start)
}

fn run_mutation_script(
    script: &str,
    stdin_text: &str,
    cancellation_before_start: Option<&AtomicBool>,
) -> Result<Output, String> {
    if cancellation_before_start.is_some_and(|token| token.load(Ordering::Acquire)) {
        return Err("PowerShell 工作已取消。".to_owned());
    }

    // A mutation that has started must finish so callers can observe its final
    // state and roll it back. Cancellation is intentionally checked only before
    // spawning PowerShell.
    run_script(script, stdin_text, None)
}

// Keep raw script execution private. Production callers can only select one of
// the fixed query or mutation variants above, so new PowerShell capabilities
// require an explicit change at this allowlist boundary.
fn run_script(
    script: &str,
    stdin_text: &str,
    cancellation: Option<&AtomicBool>,
) -> Result<Output, String> {
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

    Ok(Output {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(test)]
pub(super) fn run_test_script(
    script: &str,
    stdin_text: &str,
    cancellation: Option<&AtomicBool>,
) -> Result<Output, String> {
    run_script(script, stdin_text, cancellation)
}

#[cfg(test)]
pub(super) fn run_test_mutation_script(
    script: &str,
    stdin_text: &str,
    cancellation_before_start: Option<&AtomicBool>,
) -> Result<Output, String> {
    run_mutation_script(script, stdin_text, cancellation_before_start)
}
