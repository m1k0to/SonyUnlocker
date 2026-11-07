const { invoke } = window.__TAURI__.core;

const logOutput = document.getElementById("log-output");
const deviceStatus = document.getElementById("device-status");
const deviceInfoPanel = document.getElementById("device-info-panel");
const actionsPanel = document.getElementById("actions-panel");
const btnDetect = document.getElementById("btn-detect");
const btnExploit = document.getElementById("btn-exploit");
const btnUnlock = document.getElementById("btn-unlock");
const btnRelock = document.getElementById("btn-relock");

let exploitDone = false;

function appendLog(msg) {
  const ts = new Date().toLocaleTimeString();
  logOutput.textContent += `[${ts}] ${msg}\n`;
  logOutput.scrollTop = logOutput.scrollHeight;
}

function setStatus(html, className) {
  deviceStatus.innerHTML = `<p class="${className}">${html}</p>`;
}

function setDeviceInfo(info) {
  document.getElementById("info-product").textContent = info.product || "—";
  document.getElementById("info-platform").textContent = info.platform || "—";
  document.getElementById("info-bootloader").textContent =
    info.bootloader_version || "—";
  document.getElementById("info-baseband").textContent =
    info.baseband_version || "—";
  document.getElementById("info-locked").textContent =
    info.unlocked === true ? "No (unlocked)" : info.unlocked === false ? "Yes (locked)" : "—";
  document.getElementById("info-secure").textContent =
    info.secure === true ? "Yes" : info.secure === false ? "No" : "—";
}

function disableAll() {
  btnDetect.disabled = true;
  btnExploit.disabled = true;
  btnUnlock.disabled = true;
  btnRelock.disabled = true;
}

function enableDetect() {
  btnDetect.disabled = false;
}

// --- Detect Device ---
btnDetect.addEventListener("click", async () => {
  disableAll();
  appendLog("Detecting device...");
  setStatus("Scanning for device in fastboot mode...", "status-scanning");

  try {
    const found = await invoke("detect_device");
    if (!found) {
      setStatus("No device detected. Ensure device is in fastboot mode.", "status-disconnected");
      appendLog("No device found.");
      enableDetect();
      return;
    }

    appendLog("Device detected! Reading info...");
    const info = await invoke("get_device_info");
    setStatus(`Connected: ${info.product || "Unknown"} (${info.platform || "?"})`, "status-connected");
    setDeviceInfo(info);
    deviceInfoPanel.style.display = "";
    actionsPanel.style.display = "";

    appendLog(`Product: ${info.product}, Platform: ${info.platform}`);
    appendLog(`Bootloader: ${info.bootloader_version}`);
    appendLog(`Locked: ${info.unlocked === false ? "yes" : "no"}`);
  } catch (e) {
    setStatus("Error detecting device", "status-error");
    appendLog(`Error: ${e}`);
  }

  enableDetect();
  btnExploit.disabled = false;
});

// --- Run Exploit ---
btnExploit.addEventListener("click", async () => {
  disableAll();
  appendLog("Running exploit...");

  try {
    const result = await invoke("run_exploit");
    result.log_lines.forEach((l) => {
      if (l.trim()) appendLog(l);
    });

    if (result.success) {
      appendLog("✓ Exploit succeeded — unlock/relock buttons enabled.");
      exploitDone = true;
      btnUnlock.disabled = false;
      btnRelock.disabled = false;
    } else {
      appendLog(`✗ Exploit failed: ${result.message}`);
    }
  } catch (e) {
    appendLog(`Error: ${e}`);
  }

  enableDetect();
  btnExploit.disabled = false;
});

// --- Unlock ---
btnUnlock.addEventListener("click", async () => {
  if (!confirm("Unlock bootloader? The device will reboot.")) return;
  disableAll();
  appendLog("Sending unlock command...");

  try {
    const result = await invoke("unlock_bootloader");
    result.log_lines.forEach((l) => {
      if (l.trim()) appendLog(l);
    });
    appendLog(result.success ? "✓ Unlock command sent." : `✗ ${result.message}`);
  } catch (e) {
    appendLog(`Error: ${e}`);
  }

  enableDetect();
});

// --- Re-lock ---
btnRelock.addEventListener("click", async () => {
  if (!confirm("Re-lock bootloader? The device will reboot.")) return;
  disableAll();
  appendLog("Sending re-lock command...");

  try {
    const result = await invoke("relock_bootloader");
    result.log_lines.forEach((l) => {
      if (l.trim()) appendLog(l);
    });
    appendLog(result.success ? "✓ Re-lock command sent." : `✗ ${result.message}`);
  } catch (e) {
    appendLog(`Error: ${e}`);
  }

  enableDetect();
});

// --- Init ---
(async () => {
  try {
    const binPath = await invoke("check_xperable_binary");
    appendLog(`xperable binary found: ${binPath}`);
  } catch (e) {
    appendLog(`⚠ ${e}`);
    appendLog("You need to build the xperable binary first (see upstream README).");
  }
})();
