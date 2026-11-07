mod xperable;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            xperable::detect_device,
            xperable::get_device_info,
            xperable::run_exploit,
            xperable::unlock_bootloader,
            xperable::relock_bootloader,
            xperable::check_xperable_binary,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
