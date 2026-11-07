use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tokio::process::Command;
use tokio::time::timeout;

/// Device info parsed from xperable -A output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub unlocked: Option<bool>,
    pub bootloader_version: Option<String>,
    pub baseband_version: Option<String>,
    pub product: Option<String>,
    pub secure: Option<bool>,
    pub platform: Option<String>, // "yoshino" or "tama"
}

/// Result of an exploit operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitResult {
    pub success: bool,
    pub stage: String,
    pub message: String,
    pub log_lines: Vec<String>,
}

/// Check if the xperable binary exists and is executable
#[tauri::command]
pub async fn check_xperable_binary(app: AppHandle) -> Result<String, String> {
    let bin_path = find_xperable_binary(&app)?;
    Ok(bin_path.to_string_lossy().to_string())
}

/// Locate the xperable binary relative to the app bundle or in PATH
fn find_xperable_binary(app: &AppHandle) -> Result<PathBuf, String> {
    // 1. Check alongside the app binary (bundled)
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(std::path::Path::new("."));
        let candidate = dir.join("xperable");
        if candidate.exists() {
            return Ok(candidate);
        }
        // macOS .app bundle: Contents/MacOS/../Resources/xperable
        let resources = dir.join("../Resources/xperable");
        if resources.exists() {
            return Ok(resources);
        }
    }
    // 2. Check resource dir from tauri
    if let Ok(resource_dir) = app.path().resource_dir() {
        let candidate = resource_dir.join("xperable");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    // 3. Fallback: look in PATH
    if let Ok(output) = std::process::Command::new("which").arg("xperable").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }
    Err("xperable binary not found. Please build it and place it in the app Resources folder or PATH.".into())
}

/// Default timeout for xperable operations (seconds)
const XPERABLE_TIMEOUT_SECS: u64 = 120;

/// Run xperable with given args asynchronously with timeout
async fn run_xperable(app: &AppHandle, args: &[&str]) -> Result<(i32, String, String), String> {
    let bin = find_xperable_binary(app)?;
    log::info!("Running xperable: {:?} {:?}", bin, args);

    let child = Command::new(&bin)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute xperable: {}", e))?;

    let output = timeout(
        Duration::from_secs(XPERABLE_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| format!("xperable timed out after {}s", XPERABLE_TIMEOUT_SECS))?
    .map_err(|e| format!("Failed to wait for xperable: {}", e))?;

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    log::info!("xperable exited with code {}", code);
    log::debug!("stdout: {}", stdout);
    log::debug!("stderr: {}", stderr);

    Ok((code, stdout, stderr))
}

/// Parse the output of xperable -A into structured DeviceInfo
fn parse_getvar_all(stderr: &str) -> DeviceInfo {
    let mut info = DeviceInfo {
        unlocked: None,
        bootloader_version: None,
        baseband_version: None,
        product: None,
        secure: None,
        platform: None,
    };

    for line in stderr.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("unlocked:") {
            info.unlocked = Some(val.trim() == "yes");
        } else if let Some(val) = line.strip_prefix("version-bootloader:") {
            let v = val.trim().to_string();
            // Detect platform from bootloader string
            if v.contains("MSM8998") {
                info.platform = Some("yoshino".into());
            } else if v.contains("SDM845") {
                info.platform = Some("tama".into());
            }
            info.bootloader_version = Some(v);
        } else if let Some(val) = line.strip_prefix("version-baseband:") {
            info.baseband_version = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("product:") {
            info.product = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("secure:") {
            info.secure = Some(val.trim() == "yes");
        }
    }
    info
}

/// Detect if a Sony device is connected in fastboot mode
#[tauri::command]
pub async fn detect_device(app: AppHandle) -> Result<bool, String> {
    // Try running xperable -B; if it succeeds, device is present
    let result = run_xperable(&app, &["-B"]).await;
    match result {
        Ok((code, _, stderr)) => {
            Ok(code == 0 && stderr.contains("version-bootloader:"))
        }
        Err(_) => Ok(false),
    }
}

/// Get full device info via xperable -A
#[tauri::command]
pub async fn get_device_info(app: AppHandle) -> Result<DeviceInfo, String> {
    let (code, stdout, stderr) = run_xperable(&app, &["-A"]).await?;
    // xperable outputs getvar info to stdout
    let combined = format!("{}\n{}", stdout, stderr);
    let info = parse_getvar_all(&combined);

    if info.bootloader_version.is_none() {
        return Err(format!(
            "Could not read device info (exit code {}). Is the device in fastboot mode?",
            code
        ));
    }
    Ok(info)
}

/// Run the exploit (-4 for yoshino, -5 for tama)
#[tauri::command]
pub async fn run_exploit(app: AppHandle) -> Result<ExploitResult, String> {
    // Step 1: Get device info to determine platform
    let (_, stdout, stderr) = run_xperable(&app, &["-A"]).await?;
    let combined = format!("{}\n{}", stdout, stderr);
    let info = parse_getvar_all(&combined);

    let platform = info.platform.as_deref().unwrap_or("unknown");
    let exploit_flag = match platform {
        "yoshino" => "-4",
        "tama" => "-5",
        _ => return Err(format!("Unknown platform: {}", platform)),
    };

    // Step 2: Run the exploit
    // -B sets up the target (required before test4/test5), then exploit_flag runs the actual exploit
    let (code, stdout2, stderr2) = run_xperable(&app, &["-B", exploit_flag]).await?;
    let all_output = format!("{}\n{}", stdout2, stderr2);
    let log_lines: Vec<String> = all_output.lines().map(|l| l.to_string()).collect();

    let success = code == 0 && all_output.contains("patched successfully");
    Ok(ExploitResult {
        success,
        stage: "exploit".into(),
        message: if success {
            "ABL LinuxLoader patched successfully".into()
        } else {
            format!("Exploit failed (exit code {})", code)
        },
        log_lines,
    })
}

/// Unlock bootloader (requires exploit to have run first)
#[tauri::command]
pub async fn unlock_bootloader(app: AppHandle) -> Result<ExploitResult, String> {
    let (code, stdout, stderr) = run_xperable(
        &app,
        &["-B", "-c", "oem unlock Y", "-1", "-c", "reboot", "-1"],
    ).await?;
    let all_output = format!("{}\n{}", stdout, stderr);
    let log_lines: Vec<String> = all_output.lines().map(|l| l.to_string()).collect();

    Ok(ExploitResult {
        success: code == 0,
        stage: "unlock".into(),
        message: if code == 0 {
            "Bootloader unlock command sent, device rebooting".into()
        } else {
            format!("Unlock failed (exit code {})", code)
        },
        log_lines,
    })
}

/// Re-lock bootloader (requires exploit to have run first)
#[tauri::command]
pub async fn relock_bootloader(app: AppHandle) -> Result<ExploitResult, String> {
    let (code, stdout, stderr) = run_xperable(
        &app,
        &["-B", "-c", "oem unlock X", "-1", "-c", "reboot", "-1"],
    ).await?;
    let all_output = format!("{}\n{}", stdout, stderr);
    let log_lines: Vec<String> = all_output.lines().map(|l| l.to_string()).collect();

    Ok(ExploitResult {
        success: code == 0,
        stage: "relock".into(),
        message: if code == 0 {
            "Bootloader re-lock command sent, device rebooting".into()
        } else {
            format!("Re-lock failed (exit code {})", code)
        },
        log_lines,
    })
}
