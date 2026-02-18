use std::collections::HashMap;
use chrono::Utc;

use crate::types::*;

/// Escape a string for safe inclusion in CSV to prevent formula injection.
/// Prefixes cells starting with =, +, -, @, \t, \r with a single quote.
fn csv_escape(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r')
    {
        format!("'{}", value)
    } else {
        value.to_string()
    }
}

/// Escape a string for safe inclusion in a PowerShell double-quoted string.
/// Escapes backticks, dollar signs, and double quotes.
fn ps_escape(value: &str) -> String {
    value
        .replace('`', "``")
        .replace('$', "`$")
        .replace('"', "`\"")
}

/// Generate CSV export
pub fn export_to_csv(
    results: &[MigrationAnalysis],
    selected_roles: &HashMap<String, usize>,
    resolved_names: &HashMap<String, ResolvedIdentity>,
) -> String {
    let headers = "Identity Name,Object ID,Type,Strategy,Recommended Role,Confidence,Missing Permissions,Excess Permissions";

    let rows: Vec<String> = results
        .iter()
        .map(|r| {
            let selected_idx = selected_roles
                .get(&r.original_policy.object_id)
                .copied()
                .unwrap_or(0);
            let rec = &r.recommendations[selected_idx.min(r.recommendations.len() - 1)];
            let resolved_info = resolved_names.get(&r.original_policy.object_id);

            let mut display_name = resolved_info
                .map(|ri| ri.name.clone())
                .or_else(|| r.original_policy.display_name.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let has_app_id = r
                .original_policy
                .application_id
                .as_ref()
                .map(|id| !id.trim().is_empty())
                .unwrap_or(false);

            if has_app_id {
                let app_id = r.original_policy.application_id.as_ref().unwrap();
                let app_info = resolved_names.get(app_id);
                let app_name = app_info
                    .map(|ai| ai.name.clone())
                    .unwrap_or_else(|| app_id.clone());
                display_name = format!("{} on behalf of ({})", display_name, app_name);
            }

            let identity_type = if has_app_id {
                "Compound Identity".to_string()
            } else {
                resolved_info
                    .map(|ri| format!("{:?}", ri.identity_type))
                    .unwrap_or_else(|| format!("{:?}", r.original_policy.identity_type))
            };

            format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}%\",\"{}\",\"{}\"",
                csv_escape(&display_name),
                csv_escape(&r.original_policy.object_id),
                csv_escape(&identity_type),
                csv_escape(&rec.strategy),
                csv_escape(&rec.role_name),
                rec.confidence,
                rec.missing_permissions.len(),
                rec.excess_permissions.len()
            )
        })
        .collect();

    format!("{}\n{}", headers, rows.join("\n"))
}

/// Generate JSON export
pub fn export_to_json(
    results: &[MigrationAnalysis],
    selected_roles: &HashMap<String, usize>,
    resolved_names: &HashMap<String, ResolvedIdentity>,
) -> String {
    let export_data: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let selected_idx = selected_roles
                .get(&r.original_policy.object_id)
                .copied()
                .unwrap_or(0);
            let rec = &r.recommendations[selected_idx.min(r.recommendations.len() - 1)];
            let resolved_info = resolved_names.get(&r.original_policy.object_id);

            let mut display_name = resolved_info
                .map(|ri| ri.name.clone())
                .or_else(|| r.original_policy.display_name.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let has_app_id = r
                .original_policy
                .application_id
                .as_ref()
                .map(|id| !id.trim().is_empty())
                .unwrap_or(false);

            let mut app_name: Option<String> = None;
            if has_app_id {
                let app_id = r.original_policy.application_id.as_ref().unwrap();
                let app_info = resolved_names.get(app_id);
                app_name = Some(
                    app_info
                        .map(|ai| ai.name.clone())
                        .unwrap_or_else(|| app_id.clone()),
                );
                display_name = format!(
                    "{} on behalf of ({})",
                    display_name,
                    app_name.as_ref().unwrap()
                );
            }

            let identity_type = if has_app_id {
                "Compound Identity".to_string()
            } else {
                resolved_info
                    .map(|ri| format!("{:?}", ri.identity_type))
                    .unwrap_or_else(|| format!("{:?}", r.original_policy.identity_type))
            };

            serde_json::json!({
                "identity": {
                    "objectId": r.original_policy.object_id,
                    "name": display_name,
                    "type": identity_type,
                    "applicationId": r.original_policy.application_id,
                    "applicationName": app_name,
                },
                "originalPermissions": {
                    "keys": r.original_policy.permissions.keys,
                    "secrets": r.original_policy.permissions.secrets,
                    "certificates": r.original_policy.permissions.certificates,
                    "storage": r.original_policy.permissions.storage,
                },
                "recommendation": {
                    "strategy": rec.strategy,
                    "roleName": rec.role_name,
                    "roleNames": rec.role_names,
                    "confidence": rec.confidence,
                    "coveredPermissions": rec.covered_permissions,
                    "missingPermissions": rec.missing_permissions,
                    "excessPermissions": rec.excess_permissions,
                    "roleBreakdown": rec.role_breakdown.iter().map(|rb| {
                        serde_json::json!({
                            "roleName": rb.role_name,
                            "covered": rb.covered,
                            "excess": rb.excess,
                        })
                    }).collect::<Vec<_>>(),
                }
            })
        })
        .collect();

    serde_json::to_string_pretty(&export_data).unwrap_or_else(|_| "[]".to_string())
}

/// Generate PowerShell export script
pub fn export_to_powershell(
    results: &[MigrationAnalysis],
    selected_roles: &HashMap<String, usize>,
    resolved_names: &HashMap<String, ResolvedIdentity>,
    vault_name: &str,
    subscription_id: &str,
    vault_resource_id: &str,
) -> String {
    let timestamp = Utc::now().to_rfc3339();
    let mut script = vec![
        format!("# Azure Key Vault RBAC Migration Script"),
        format!("# Generated: {}", timestamp),
        format!("# Vault: {}", vault_name),
        format!("# Subscription: {}", subscription_id),
        String::new(),
        "# WARNING: Review this script carefully before running!".to_string(),
        "# This script will create role assignments for the Key Vault.".to_string(),
        String::new(),
        format!("$vaultName = \"{}\"", ps_escape(vault_name)),
        format!("$subscriptionId = \"{}\"", ps_escape(subscription_id)),
        format!("$scope = \"{}\"", ps_escape(vault_resource_id)),
        String::new(),
        "# Get the Key Vault resource".to_string(),
        "$vault = Get-AzKeyVault -VaultName $vaultName".to_string(),
        "if (-not $scope) { $scope = $vault.ResourceId }".to_string(),
        String::new(),
        "Write-Host \"Starting RBAC migration for Key Vault: $vaultName\" -ForegroundColor Green".to_string(),
        "Write-Host \"\"".to_string(),
        String::new(),
    ];

    // Categorize results
    let mut apps: Vec<&MigrationAnalysis> = Vec::new();
    let mut compounds: Vec<&MigrationAnalysis> = Vec::new();
    let mut groups: Vec<&MigrationAnalysis> = Vec::new();
    let mut users: Vec<&MigrationAnalysis> = Vec::new();
    let mut unknowns: Vec<&MigrationAnalysis> = Vec::new();

    for r in results {
        let resolved_info = resolved_names.get(&r.original_policy.object_id);
        let identity_type = resolved_info
            .map(|ri| &ri.identity_type)
            .unwrap_or(&r.original_policy.identity_type);

        let has_app_id = r
            .original_policy
            .application_id
            .as_ref()
            .map(|id| !id.trim().is_empty())
            .unwrap_or(false);

        if has_app_id {
            compounds.push(r);
        } else {
            match identity_type {
                IdentityType::Application | IdentityType::ServicePrincipal => apps.push(r),
                IdentityType::Group => groups.push(r),
                IdentityType::User => users.push(r),
                IdentityType::Unknown => unknowns.push(r),
            }
        }
    }

    let generate_identity_script =
        |r: &MigrationAnalysis,
         selected_roles: &HashMap<String, usize>,
         resolved_names: &HashMap<String, ResolvedIdentity>|
         -> Vec<String> {
            let mut lines = Vec::new();
            let selected_idx = selected_roles
                .get(&r.original_policy.object_id)
                .copied()
                .unwrap_or(0);
            let rec = &r.recommendations[selected_idx.min(r.recommendations.len() - 1)];
            let resolved_info = resolved_names.get(&r.original_policy.object_id);

            let mut display_name = resolved_info
                .map(|ri| ri.name.clone())
                .or_else(|| r.original_policy.display_name.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let has_app_id = r
                .original_policy
                .application_id
                .as_ref()
                .map(|id| !id.trim().is_empty())
                .unwrap_or(false);

            if has_app_id {
                let app_id = r.original_policy.application_id.as_ref().unwrap();
                let app_info = resolved_names.get(app_id);
                let app_name = app_info
                    .map(|ai| ai.name.clone())
                    .unwrap_or_else(|| app_id.clone());
                display_name = format!("{} on behalf of ({})", display_name, app_name);
            }

            lines.push(format!(
                "# {} ({})",
                display_name, r.original_policy.object_id
            ));
            lines.push(format!(
                "# Strategy: {} | Confidence: {}%",
                rec.strategy, rec.confidence
            ));

            if !rec.role_names.is_empty() {
                for role_name in &rec.role_names {
                    lines.push("New-AzRoleAssignment `".to_string());
                    lines.push(format!(
                        "  -ObjectId \"{}\" `",
                        ps_escape(&r.original_policy.object_id)
                    ));
                    lines.push(format!("  -RoleDefinitionName \"{}\" `", ps_escape(role_name)));
                    lines.push("  -Scope $scope".to_string());
                }
            } else {
                lines.push("# No matching role found for this identity".to_string());
            }

            if !rec.missing_permissions.is_empty() {
                lines.push(format!(
                    "# WARNING: {} permissions will NOT be covered:",
                    rec.missing_permissions.len()
                ));
                for perm in &rec.missing_permissions {
                    lines.push(format!("#   - {}", perm));
                }
            }

            if !rec.excess_permissions.is_empty() {
                lines.push(
                    "# NOTE: Additional permissions that will be granted:".to_string(),
                );
                let mut perm_to_roles: HashMap<String, Vec<String>> = HashMap::new();
                for rb in &rec.role_breakdown {
                    for perm in &rb.excess {
                        perm_to_roles
                            .entry(perm.clone())
                            .or_default()
                            .push(rb.role_name.clone());
                    }
                }

                for perm in &rec.excess_permissions {
                    if let Some(roles) = perm_to_roles.get(perm) {
                        lines.push(format!("#   - {} (added by: {})", perm, roles.join(", ")));
                    } else {
                        lines.push(format!("#   - {}", perm));
                    }
                }
            }

            lines.push(String::new());
            lines
        };

    let categories: Vec<(&str, &Vec<&MigrationAnalysis>)> = vec![
        ("Applications & Service Principals", &apps),
        ("Compound Identities", &compounds),
        ("Groups", &groups),
        ("Users", &users),
        ("Unknown Identities", &unknowns),
    ];

    for (category, items) in categories {
        if !items.is_empty() {
            script.push("#".repeat(80));
            script.push(format!("# {} ({})", category, items.len()));
            script.push("#".repeat(80));
            script.push(String::new());

            for item in items.iter() {
                let lines = generate_identity_script(item, selected_roles, resolved_names);
                script.extend(lines);
            }
        }
    }

    script.push(
        "Write-Host \"Migration script completed\" -ForegroundColor Green".to_string(),
    );

    script.join("\n")
}
