const { invoke } = window.__TAURI__.core;

const logOutput = document.getElementById("log-output");
const deviceStatus = document.getElementById("device-status");
const deviceInfoPanel = document.getElementById("device-info-panel");
const actionsPanel = document.getElementById("actions-panel");
const btnDetect = document.getElementById("btn-detect");
const btnRetry = document.getElementById("btn-retry");
const btnExploit = document.getElementById("btn-exploit");
const btnUnlock = document.getElementById("btn-unlock");
const btnRelock = document.getElementById("btn-relock");
const errorPanel = document.getElementById("status-error-panel");
const errorMessage = document.getElementById("status-error-message");
const actionResult = document.getElementById("action-result");
const steps = [...document.querySelectorAll(".progress-step")];
const stepLabels = ["检测设备", "读取信息", "运行 Exploit", "解锁/重锁"];

let busy = false;
let binaryReady = false;
let deviceConnected = false;
let exploitDone = false;

function appendLog(msg) {
  const ts = new Date().toLocaleTimeString();
  logOutput.textContent += `[${ts}] ${msg}\n`;
  logOutput.scrollTop = logOutput.scrollHeight;
}

function setStatus(text, className) {
  const status = document.createElement("p");
  status.className = className;
  status.textContent = text;
  deviceStatus.replaceChildren(status);
}

function setStep(current) {
  steps.forEach((step, index) => {
    const completed = index < current;
    const active = index === current;
    step.classList.toggle("is-complete", completed);
    step.classList.toggle("is-current", active);
    step.querySelector(".step-marker").textContent = completed ? "✓" : active ? "●" : String(index + 1);
    if (active) step.setAttribute("aria-current", "step");
    else step.removeAttribute("aria-current");
    step.setAttribute("aria-label", `${stepLabels[index]}：${completed ? "已完成" : active ? "当前步骤" : "未开始"}`);
  });
  document.getElementById("step-summary").textContent =
    current < steps.length ? `当前步骤：${stepLabels[current]}` : "流程已完成，设备正在重启";
}

function setDeviceInfo(info) {
  document.getElementById("info-product").textContent = info.product || "—";
  document.getElementById("info-platform").textContent = info.platform || "—";
  document.getElementById("info-bootloader").textContent = info.bootloader_version || "—";
  document.getElementById("info-baseband").textContent = info.baseband_version || "—";
  document.getElementById("info-locked").textContent =
    info.unlocked === true ? "No (unlocked)" : info.unlocked === false ? "Yes (locked)" : "—";
  document.getElementById("info-secure").textContent =
    info.secure === true ? "Yes" : info.secure === false ? "No" : "—";
}

function syncButtons() {
  btnDetect.disabled = busy;
  btnRetry.disabled = busy;
  btnExploit.disabled = busy || !binaryReady || !deviceConnected;
  btnUnlock.disabled = busy || !binaryReady || !deviceConnected || !exploitDone;
  btnRelock.disabled = btnUnlock.disabled;
}

async function withLoading(button, label, operation) {
  if (busy) return;
  busy = true;
  const originalText = button.textContent;
  const originalLabel = button.getAttribute("aria-label");
  button.textContent = label;
  button.setAttribute("aria-label", label);
  button.setAttribute("aria-busy", "true");
  button.classList.add("is-loading");
  syncButtons();
  try {
    await operation();
  } finally {
    busy = false;
    button.textContent = originalText;
    button.setAttribute("aria-label", originalLabel);
    button.removeAttribute("aria-busy");
    button.classList.remove("is-loading");
    syncButtons();
  }
}

function clearError() {
  errorPanel.hidden = true;
  errorMessage.textContent = "";
}

function showError(error) {
  const message = String(error?.message ?? error);
  let guidance = message;
  if (/xperable.*(?:not found|no such file)/i.test(message)) {
    binaryReady = false;
    guidance = "找不到 xperable 二进制文件。请先编译 xperable，并将其放到 PATH 或应用的 Resources 目录，然后重试。";
  } else if (/timed?\s*out|timeout|超时/i.test(message)) {
    guidance = "操作超时(120s)，请检查 USB 连接后重试";
  }
  errorMessage.textContent = guidance;
  errorPanel.hidden = false;
  appendLog(`Error: ${message}`);
  return guidance;
}

function showResult(type, message, detail = "") {
  actionResult.className = `feedback-card feedback-${type}`;
  document.getElementById("action-result-message").textContent = message;
  document.getElementById("action-result-detail").textContent = detail;
  actionResult.hidden = false;
}

function appendResultLog(result) {
  (result.log_lines || []).forEach((line) => {
    if (line.trim()) appendLog(line);
  });
}

// Detecting again always invalidates permissions granted for the previous device.
async function detectDevice(button) {
  await withLoading(button, "Detecting...", async () => {
    // Keep the retry button visible while its own spinner is running.
    if (button === btnRetry) errorMessage.textContent = "正在重新检测设备，请稍候...";
    else clearError();
    actionResult.hidden = true;
    deviceConnected = false;
    exploitDone = false;
    deviceInfoPanel.style.display = "none";
    actionsPanel.style.display = "none";
    setStep(0);
    setStatus("Scanning for device in fastboot mode...", "status-scanning");
    appendLog("Detecting device...");
    try {
      // Re-check on retry so installing a missing binary does not require a restart.
      await invoke("check_xperable_binary");
      binaryReady = true;
      const found = await invoke("detect_device");
      if (!found) {
        setStatus("No device detected", "status-disconnected");
        showError("请将设备连接到 USB 并进入 fastboot 模式");
        return;
      }
      setStep(1);
      setStatus("Device detected. Reading information...", "status-scanning");
      const info = await invoke("get_device_info");
      setDeviceInfo(info);
      clearError();
      deviceConnected = true;
      deviceInfoPanel.style.display = "";
      actionsPanel.style.display = "";
      setStep(2);
      setStatus(`Connected: ${info.product || "Unknown"} (${info.platform || "?"})`, "status-connected");
      appendLog(`Product: ${info.product}, Platform: ${info.platform}`);
      appendLog(`Bootloader: ${info.bootloader_version}`);
      appendLog(`Locked: ${info.unlocked === false ? "yes" : info.unlocked === true ? "no" : "unknown"}`);
    } catch (error) {
      setStatus("Error detecting device", "status-error");
      showError(error);
    }
  });
}

btnDetect.addEventListener("click", () => detectDevice(btnDetect));
btnRetry.addEventListener("click", async () => {
  await detectDevice(btnRetry);
  if (errorPanel.hidden) btnDetect.focus();
});

btnExploit.addEventListener("click", async () => {
  if (!deviceConnected || !binaryReady) return;
  await withLoading(btnExploit, "Running Exploit...", async () => {
    clearError();
    actionResult.hidden = true;
    exploitDone = false;
    setStep(2);
    appendLog("Running exploit...");
    try {
      const result = await invoke("run_exploit");
      appendResultLog(result);
      if (!result.success) throw new Error(result.message || "Exploit failed");
      exploitDone = true;
      setStep(3);
      showResult("success", "✓ ABL LinuxLoader 已成功修补");
      appendLog("✓ Exploit succeeded — unlock/relock buttons enabled.");
    } catch (error) {
      const guidance = showError(error);
      showResult("error", "✗ Exploit 失败", `${guidance} 常见原因：USB 连接不稳定、设备未处于 fastboot 模式，或设备平台/固件不受支持。请检查后重新检测或重试 Exploit。`);
    }
  });
});

async function changeBootloader(button, command, label, confirmation) {
  if (busy || !deviceConnected || !exploitDone || !binaryReady) return;
  if (!confirm(confirmation)) return;
  await withLoading(button, label, async () => {
    clearError();
    actionResult.hidden = true;
    setStep(3);
    appendLog(`Sending ${command} command...`);
    try {
      const result = await invoke(command);
      appendResultLog(result);
      if (!result.success) throw new Error(result.message || "Bootloader command failed");
      showResult("info", "设备正在重启...", "命令已发送。设备重新进入 fastboot 模式后，请重新检测设备以刷新状态。");
      setStatus("Device is rebooting. Detect again when it returns to fastboot mode.", "status-scanning");
      setStep(4);
      deviceConnected = false;
      exploitDone = false;
      deviceInfoPanel.style.display = "none";
      appendLog(`✓ ${result.message}`);
    } catch (error) {
      showResult("error", "✗ 操作失败", showError(error));
    }
  });
}

btnUnlock.addEventListener("click", () => changeBootloader(
  btnUnlock, "unlock_bootloader", "Unlocking...", "Unlock bootloader? The device will reboot.",
));
btnRelock.addEventListener("click", () => changeBootloader(
  btnRelock, "relock_bootloader", "Re-locking...", "Re-lock bootloader? The device will reboot.",
));

// Keep detection disabled until the initial binary check has settled.
withLoading(btnDetect, "Checking xperable...", async () => {
  try {
    const binPath = await invoke("check_xperable_binary");
    binaryReady = true;
    appendLog(`xperable binary found: ${binPath}`);
  } catch (error) {
    setStatus("xperable is unavailable", "status-error");
    showError(error);
  }
});
