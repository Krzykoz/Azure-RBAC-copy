use std::collections::HashMap;
use tauri::command;

use crate::analysis_service;
use crate::azure_service;
use crate::export_utils;
use crate::token_utils;
use crate::types::*;

// --- Token Commands ---

#[command]
pub async fn validate_token(token: String) -> Result<(), String> {
    azure_service::validate_token(&token)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub fn get_user_name(token: String) -> String {
    token_utils::get_user_name_from_token(&token)
}

#[command]
pub fn get_tenant_id(token: String) -> Option<String> {
    token_utils::get_tenant_id_from_token(&token)
}

// --- Azure Data Commands ---

#[command]
pub async fn get_subscriptions(token: String) -> Result<Vec<Subscription>, String> {
    azure_service::get_subscriptions(&token)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_tenants(token: String) -> Result<HashMap<String, String>, String> {
    azure_service::get_tenants(&token)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_key_vaults(
    token: String,
    subscription_id: String,
) -> Result<Vec<KeyVault>, String> {
    azure_service::get_key_vaults(&token, &subscription_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_role_definitions(
    token: String,
    subscription_id: String,
) -> Result<Vec<RoleDefinition>, String> {
    azure_service::get_role_definitions(&token, &subscription_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn get_role_assignments(
    token: String,
    subscription_id: String,
) -> Result<Vec<RoleAssignment>, String> {
    azure_service::get_role_assignments(&token, &subscription_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
pub async fn resolve_identities(
    object_ids: Vec<String>,
    token: String,
) -> Result<HashMap<String, ResolvedIdentity>, String> {
    Ok(azure_service::resolve_batch_identities(&object_ids, &token).await)
}

// --- Analysis Commands ---

/// Batched analysis: all policies analyzed in parallel using Rayon inside
/// a single spawn_blocking call. Eliminates per-identity IPC serialization
/// overhead while keeping the main thread free.
#[command]
pub async fn run_analysis(
    policies: Vec<AccessPolicyEntry>,
    available_roles: Vec<RoleDefinition>,
    role_assignments: Vec<RoleAssignment>,
    vault_id: String,
    include_custom_roles: bool,
) -> Result<Vec<MigrationAnalysis>, String> {
    tokio::task::spawn_blocking(move || {
        // Avoid cloning when using all roles - use reference filtering instead
        let filtered_roles: Vec<RoleDefinition>;
        let roles_to_analyze: &[RoleDefinition] = if include_custom_roles {
            &available_roles
        } else {
            filtered_roles = available_roles
                .iter()
                .filter(|r| r.properties.role_type == "BuiltInRole")
                .cloned()
                .collect();
            &filtered_roles
        };

        let mut analysis = analysis_service::analyze_policies(&policies, roles_to_analyze);

        // Enhance with existing coverage
        for a in &mut analysis {
            let coverage = analysis_service::analyze_existing_coverage(
                &a.original_policy,
                &role_assignments,
                &available_roles,
                Some(&vault_id),
            );
            a.existing_coverage = Some(coverage);
        }

        analysis
    })
    .await
    .map_err(|e| e.to_string())
}

/// Analyze a single policy (kept for compatibility / small batch sizes).
#[command]
pub async fn analyze_single_policy(
    policy: AccessPolicyEntry,
    available_roles: Vec<RoleDefinition>,
    role_assignments: Vec<RoleAssignment>,
    vault_id: String,
    include_custom_roles: bool,
) -> Result<MigrationAnalysis, String> {
    tokio::task::spawn_blocking(move || {
        // Avoid cloning when using all roles
        let filtered_roles: Vec<RoleDefinition>;
        let roles_to_analyze: &[RoleDefinition] = if include_custom_roles {
            &available_roles
        } else {
            filtered_roles = available_roles
                .iter()
                .filter(|r| r.properties.role_type == "BuiltInRole")
                .cloned()
                .collect();
            &filtered_roles
        };

        let mut results = analysis_service::analyze_policies(&[policy], roles_to_analyze);
        let mut result = results.remove(0);

        let coverage = analysis_service::analyze_existing_coverage(
            &result.original_policy,
            &role_assignments,
            &available_roles,
            Some(&vault_id),
        );
        result.existing_coverage = Some(coverage);

        result
    })
    .await
    .map_err(|e| e.to_string())
}

// --- Export Commands ---

#[command]
pub fn export_csv(
    results: Vec<MigrationAnalysis>,
    selected_roles: HashMap<String, usize>,
    resolved_names: HashMap<String, ResolvedIdentity>,
    selected_for_export: Vec<String>,
) -> Result<String, String> {
    let filtered: Vec<MigrationAnalysis> = results
        .into_iter()
        .filter(|r| selected_for_export.contains(&r.original_policy.object_id))
        .collect();

    if filtered.is_empty() {
        return Err("Please select at least one identity to export.".to_string());
    }

    Ok(export_utils::export_to_csv(
        &filtered,
        &selected_roles,
        &resolved_names,
    ))
}

#[command]
pub fn export_json(
    results: Vec<MigrationAnalysis>,
    selected_roles: HashMap<String, usize>,
    resolved_names: HashMap<String, ResolvedIdentity>,
    selected_for_export: Vec<String>,
) -> Result<String, String> {
    let filtered: Vec<MigrationAnalysis> = results
        .into_iter()
        .filter(|r| selected_for_export.contains(&r.original_policy.object_id))
        .collect();

    if filtered.is_empty() {
        return Err("Please select at least one identity to export.".to_string());
    }

    Ok(export_utils::export_to_json(
        &filtered,
        &selected_roles,
        &resolved_names,
    ))
}

#[command]
pub fn export_powershell(
    results: Vec<MigrationAnalysis>,
    selected_roles: HashMap<String, usize>,
    resolved_names: HashMap<String, ResolvedIdentity>,
    selected_for_export: Vec<String>,
    vault_name: String,
    subscription_id: String,
    vault_resource_id: String,
) -> Result<String, String> {
    let filtered: Vec<MigrationAnalysis> = results
        .into_iter()
        .filter(|r| selected_for_export.contains(&r.original_policy.object_id))
        .collect();

    if filtered.is_empty() {
        return Err("Please select at least one identity to export.".to_string());
    }

    Ok(export_utils::export_to_powershell(
        &filtered,
        &selected_roles,
        &resolved_names,
        &vault_name,
        &subscription_id,
        &vault_resource_id,
    ))
}
