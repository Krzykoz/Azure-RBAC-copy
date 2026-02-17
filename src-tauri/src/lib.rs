pub mod analysis_service;
pub mod azure_service;
pub mod commands;
pub mod constants;
pub mod export_utils;
pub mod token_utils;
pub mod types;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::validate_token,
            commands::get_user_name,
            commands::get_tenant_id,
            commands::get_subscriptions,
            commands::get_tenants,
            commands::get_key_vaults,
            commands::get_role_definitions,
            commands::get_role_assignments,
            commands::resolve_identities,
            commands::run_analysis,
            commands::analyze_single_policy,
            commands::export_csv,
            commands::export_json,
            commands::export_powershell,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
