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

/// Check that a path is a regular file with execute permission
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => meta.permissions().mode() & 0o111 != 0,
        _ => false,
    }
}

/// Locate the xperable binary relative to the app bundle or in PATH
fn find_xperable_binary(app: &AppHandle) -> Result<PathBuf, String> {
    // 1. Check alongside the app binary (bundled — most trusted)
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(std::path::Path::new("."));
        let candidate = dir.join("xperable");
        if is_executable(&candidate) {
            return Ok(candidate);
        }
        // macOS .app bundle: Contents/MacOS/../Resources/xperable
        let resources = dir.join("../Resources/xperable");
        if is_executable(&resources) {
            return Ok(resources);
        }
    }
    // 2. Check resource dir from tauri
    if let Ok(resource_dir) = app.path().resource_dir() {
        let candidate = resource_dir.join("xperable");
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    // 3. Fallback: search PATH directories directly (no subprocess)
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join("xperable");
            if is_executable(&candidate) {
                return Ok(candidate);
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

    // Set working directory to the binary's parent so relative payload paths
    // (LinuxLoader-*.pe, target-*.c) resolve correctly.
    let work_dir = bin.parent().unwrap_or(std::path::Path::new("."));

    let child = Command::new(&bin)
        .args(args)
        .current_dir(work_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
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

/// Parse the combined stdout+stderr output of xperable -A into structured DeviceInfo
fn parse_getvar_all(output: &str) -> DeviceInfo {
    let mut info = DeviceInfo {
        unlocked: None,
        bootloader_version: None,
        baseband_version: None,
        product: None,
        secure: None,
        platform: None,
    };

    for line in output.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("unlocked:") {
            info.unlocked = match val.trim() {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            };
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
            info.secure = match val.trim() {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            };
        }
    }
    info
}

/// Detect if a Sony device is connected in fastboot mode
#[tauri::command]
pub async fn detect_device(app: AppHandle) -> Result<bool, String> {
    // -B calls getvar_single which outputs to stdout via POUT
    let result = run_xperable(&app, &["-B"]).await;
    match result {
        Ok((code, stdout, _stderr)) => {
            Ok(code == 0 && stdout.contains("version-bootloader:"))
        }
        Err(e) => {
            // Distinguish binary-not-found from device-not-found
            if e.contains("not found") || e.contains("execute") {
                Err(e)
            } else {
                Ok(false)
            }
        }
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
    // Step 1: Send the unlock command only (no reboot yet)
    let (code1, stdout1, stderr1) = run_xperable(
        &app,
        &["-B", "-c", "oem unlock Y", "-1"],
    ).await?;
    let out1 = format!("{}\n{}", stdout1, stderr1);
    let mut log_lines: Vec<String> = out1.lines().map(|l| l.to_string()).collect();

    // Check for FAIL in output — upstream test1 returns FASTBOOT_FAIL on failure
    let unlock_failed = out1.contains("FAIL") || code1 != 0;
    if unlock_failed {
        return Ok(ExploitResult {
            success: false,
            stage: "unlock".into(),
            message: format!("Unlock command failed (exit code {}). Device not rebooted.", code1),
            log_lines,
        });
    }

    // Step 2: Only reboot if unlock succeeded
    let (code2, stdout2, stderr2) = run_xperable(
        &app,
        &["-B", "-c", "reboot", "-1"],
    ).await?;
    let out2 = format!("{}\n{}", stdout2, stderr2);
    log_lines.extend(out2.lines().map(|l| l.to_string()));

    Ok(ExploitResult {
        success: code2 == 0,
        stage: "unlock".into(),
        message: if code2 == 0 {
            "Bootloader unlock command sent, device rebooting".into()
        } else {
            format!("Unlock succeeded but reboot failed (exit code {})", code2)
        },
        log_lines,
    })
}

/// Re-lock bootloader (requires exploit to have run first)
#[tauri::command]
pub async fn relock_bootloader(app: AppHandle) -> Result<ExploitResult, String> {
    // Step 1: Send the re-lock command only (no reboot yet)
    let (code1, stdout1, stderr1) = run_xperable(
        &app,
        &["-B", "-c", "oem unlock X", "-1"],
    ).await?;
    let out1 = format!("{}\n{}", stdout1, stderr1);
    let mut log_lines: Vec<String> = out1.lines().map(|l| l.to_string()).collect();

    // Check for FAIL in output
    let relock_failed = out1.contains("FAIL") || code1 != 0;
    if relock_failed {
        return Ok(ExploitResult {
            success: false,
            stage: "relock".into(),
            message: format!("Re-lock command failed (exit code {}). Device not rebooted.", code1),
            log_lines,
        });
    }

    // Step 2: Only reboot if re-lock succeeded
    let (code2, stdout2, stderr2) = run_xperable(
        &app,
        &["-B", "-c", "reboot", "-1"],
    ).await?;
    let out2 = format!("{}\n{}", stdout2, stderr2);
    log_lines.extend(out2.lines().map(|l| l.to_string()));

    Ok(ExploitResult {
        success: code2 == 0,
        stage: "relock".into(),
        message: if code2 == 0 {
            "Bootloader re-lock command sent, device rebooting".into()
        } else {
            format!("Re-lock succeeded but reboot failed (exit code {})", code2)
        },
        log_lines,
    })
}
