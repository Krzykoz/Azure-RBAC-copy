use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use rayon::prelude::*;

use crate::constants::*;
use crate::types::*;

/// The CSV mapping content is embedded at compile time
const RBAC_MAPPING_CSV: &str = include_str!("../../src/assets/AcessPolicyRBACMapping.csv");

/// Parsed permission mapping: category -> (action -> [rbac_actions])
type PermissionMap = HashMap<String, HashMap<String, Vec<String>>>;

/// Lazily parsed permission map — computed once on first access
static PERM_MAP: LazyLock<PermissionMap> = LazyLock::new(parse_permission_map);
/// Lazily computed set of all known RBAC actions
static KNOWN_ACTIONS: LazyLock<HashSet<String>> =
    LazyLock::new(|| all_known_rbac_actions(&PERM_MAP));

fn parse_permission_map() -> PermissionMap {
    let mut map: PermissionMap = HashMap::new();
    map.insert("keys".to_string(), HashMap::new());
    map.insert("secrets".to_string(), HashMap::new());
    map.insert("certificates".to_string(), HashMap::new());
    map.insert("storage".to_string(), HashMap::new());

    for line in RBAC_MAPPING_CSV.lines().skip(1) {
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() < 2 {
            continue;
        }

        let policy_perm = parts[0].trim();
        let rbac_actions = parts[1].trim();

        let perm_parts: Vec<&str> = policy_perm.splitn(2, ' ').collect();
        if perm_parts.len() < 2 {
            continue;
        }

        let category_raw = perm_parts[0].to_lowercase();
        let action_raw = perm_parts[1].to_lowercase();

        let category = match category_raw.as_str() {
            "key" => "keys",
            "secret" => "secrets",
            "certificate" => "certificates",
            "storage" => "storage",
            _ => continue,
        };

        let actions_list: Vec<String> = rbac_actions
            .split(';')
            .map(|s| s.trim().to_string())
            .collect();

        map.entry(category.to_string())
            .or_default()
            .insert(action_raw, actions_list);
    }

    map
}

/// Get all known RBAC actions from the permission map
fn all_known_rbac_actions(perm_map: &PermissionMap) -> HashSet<String> {
    let mut actions = HashSet::new();
    for cat_map in perm_map.values() {
        for action_list in cat_map.values() {
            for action in action_list {
                actions.insert(action.clone());
            }
        }
    }
    actions
}

/// Check if a role action matches a required action (supports wildcards).
/// Uses simple string matching for common patterns to avoid regex overhead.
fn action_matches(role_action: &str, required_action: &str) -> bool {
    let r = role_action.to_lowercase();
    let req = required_action.to_lowercase();

    if r == "*" || r == req {
        return true;
    }

    // Fast path: prefix/* pattern (most common wildcard)
    if r.ends_with("/*") {
        let prefix = &r[..r.len() - 1]; // keep the trailing /
        return req.starts_with(prefix);
    }

    // Fast path: single * in the middle — split and check prefix/suffix
    if r.contains('*') {
        let parts: Vec<&str> = r.splitn(2, '*').collect();
        if parts.len() == 2 {
            return req.starts_with(parts[0]) && req.ends_with(parts[1]);
        }
    }

    false
}

/// Get required RBAC actions for an access policy
fn get_required_actions(
    policy: &AccessPolicyEntry,
    perm_map: &PermissionMap,
) -> HashSet<String> {
    let mut actions = HashSet::new();

    let categories = [
        ("keys", &policy.permissions.keys),
        ("secrets", &policy.permissions.secrets),
        ("certificates", &policy.permissions.certificates),
        ("storage", &policy.permissions.storage),
    ];

    for (type_key, perms) in &categories {
        if perms.is_empty() {
            continue;
        }

        if let Some(cat_map) = perm_map.get(*type_key) {
            for p in *perms {
                let perm_key = p.to_lowercase();
                if perm_key == "all" || perm_key == "*" {
                    for rbac_list in cat_map.values() {
                        for action in rbac_list {
                            actions.insert(action.clone());
                        }
                    }
                } else if let Some(mapped_list) = cat_map.get(&perm_key) {
                    for action in mapped_list {
                        actions.insert(action.clone());
                    }
                }
            }
        }
    }

    actions
}

/// Precomputed coverage for a single role: (covered actions, excess actions)
struct RoleCoverage {
    covered: HashSet<String>,
    excess: HashSet<String>,
}

/// Calculate coverage of a role against required permissions
fn calculate_coverage(
    required: &HashSet<String>,
    role: &RoleDefinition,
    known_actions: &HashSet<String>,
) -> RoleCoverage {
    let mut covered = HashSet::new();
    let mut excess = HashSet::new();

    for p in &role.properties.permissions {
        for da in &p.data_actions {
            let da_lower = da.to_lowercase();
            if !da_lower.contains("microsoft.keyvault") {
                continue;
            }

            let is_wildcard = da.contains('*');

            if is_wildcard {
                for known_action in known_actions {
                    if action_matches(da, known_action) {
                        if required.contains(known_action) {
                            covered.insert(known_action.clone());
                        } else {
                            excess.insert(known_action.clone());
                        }
                    }
                }
            } else if let Some(matched_req) = required.iter().find(|req| {
                req.to_lowercase() == da_lower
            }) {
                covered.insert(matched_req.clone());
            } else if known_actions.contains(&da_lower) || da_lower.ends_with("/action") {
                excess.insert(da.clone());
            }
        }
    }

    RoleCoverage { covered, excess }
}

/// Calculate confidence score
fn calculate_confidence(total_needed: usize, covered: usize) -> u32 {
    if total_needed == 0 {
        return 100;
    }
    let coverage_ratio = covered as f64 / total_needed as f64;
    (coverage_ratio * 100.0).round().clamp(0.0, 100.0) as u32
}

/// Merge strategies with identical outputs
fn merge_duplicate_strategies(strategies: Vec<SuggestedRole>) -> Vec<SuggestedRole> {
    let mut groups: HashMap<String, Vec<SuggestedRole>> = HashMap::new();

    for strategy in strategies {
        let mut sorted_names = strategy.role_names.clone();
        sorted_names.sort();
        let signature = sorted_names.join(",");
        groups.entry(signature).or_default().push(strategy);
    }

    let mut unique_strategies = Vec::new();

    for (_signature, group) in groups {
        if group.len() > 1 && !_signature.is_empty() {
            let merged_names: Vec<String> = group.iter().map(|s| s.strategy.clone()).collect();
            let mut merged = group.into_iter().next().unwrap();
            merged.strategy = merged_names.join(" / ");
            merged.reasoning =
                "Multiple strategies produced identical role assignments for this policy."
                    .to_string();
            unique_strategies.push(merged);
        } else {
            unique_strategies.extend(group);
        }
    }

    unique_strategies
}

/// Run weighted analysis for a single strategy, using precomputed per-role
/// coverage to avoid redundant computation in the combination search.
fn run_weighted_analysis(
    required: &HashSet<String>,
    precomputed: &[RoleCoverage],
    roles: &[RoleDefinition],
    config: &StrategyConfig,
) -> SuggestedRole {
    let mut best_combination: Vec<usize> = Vec::new();
    let mut best_score = f64::NEG_INFINITY;
    let mut best_covered: HashSet<String> = HashSet::new();
    let mut best_excess: HashSet<String> = HashSet::new();

    // Filter to indices of roles that cover at least one required permission
    let useful_indices: Vec<usize> = precomputed
        .iter()
        .enumerate()
        .filter(|(_, cov)| !cov.covered.is_empty())
        .map(|(i, _)| i)
        .collect();

    // Generate and evaluate combinations using precomputed coverage
    fn generate_combinations(
        start_idx: usize,
        current_combo: &mut Vec<usize>,
        useful_indices: &[usize],
        precomputed: &[RoleCoverage],
        config: &StrategyConfig,
        best_score: &mut f64,
        best_combination: &mut Vec<usize>,
        best_covered: &mut HashSet<String>,
        best_excess: &mut HashSet<String>,
    ) {
        if !current_combo.is_empty() {
            // Union precomputed coverage — no per-role recalculation
            let mut combined_covered = HashSet::new();
            let mut combined_excess = HashSet::new();

            for &idx in current_combo.iter() {
                combined_covered.extend(precomputed[idx].covered.iter().cloned());
                combined_excess.extend(precomputed[idx].excess.iter().cloned());
            }

            let score = combined_covered.len() as f64 * config.weight_coverage
                - combined_excess.len() as f64 * config.weight_excess
                - (current_combo.len() as f64 - 1.0) * config.weight_role_count;

            if score > *best_score {
                *best_score = score;
                *best_combination = current_combo.clone();
                *best_covered = combined_covered;
                *best_excess = combined_excess;
            }
        }

        if current_combo.len() >= MAX_COMBINATION_SIZE {
            return;
        }

        for i in start_idx..useful_indices.len() {
            current_combo.push(useful_indices[i]);
            generate_combinations(
                i + 1,
                current_combo,
                useful_indices,
                precomputed,
                config,
                best_score,
                best_combination,
                best_covered,
                best_excess,
            );
            current_combo.pop();
        }
    }

    let mut current_combo: Vec<usize> = Vec::new();
    generate_combinations(
        0,
        &mut current_combo,
        &useful_indices,
        precomputed,
        config,
        &mut best_score,
        &mut best_combination,
        &mut best_covered,
        &mut best_excess,
    );

    if best_combination.is_empty() || best_score < config.threshold {
        return SuggestedRole {
            strategy: config.name.to_string(),
            role_name: "No Match".to_string(),
            role_names: vec![],
            confidence: 0,
            reasoning: format!(
                "Could not find roles fitting the \"{}\" criteria.",
                config.name
            ),
            covered_permissions: vec![],
            missing_permissions: required.iter().cloned().collect(),
            excess_permissions: vec![],
            role_breakdown: vec![],
        };
    }

    let role_breakdown: Vec<RoleBreakdown> = best_combination
        .iter()
        .map(|&idx| RoleBreakdown {
            role_name: roles[idx].properties.role_name.clone(),
            covered: precomputed[idx].covered.iter().cloned().collect(),
            excess: precomputed[idx].excess.iter().cloned().collect(),
        })
        .collect();

    let missing: Vec<String> = required
        .iter()
        .filter(|x| !best_covered.contains(*x))
        .cloned()
        .collect();

    let role_names: Vec<String> = best_combination
        .iter()
        .map(|&idx| roles[idx].properties.role_name.clone())
        .collect();

    SuggestedRole {
        strategy: config.name.to_string(),
        role_name: role_names.join(" + "),
        role_names,
        confidence: calculate_confidence(required.len(), best_covered.len()),
        reasoning: config.description.to_string(),
        covered_permissions: best_covered.into_iter().collect(),
        missing_permissions: missing,
        excess_permissions: best_excess.into_iter().collect(),
        role_breakdown,
    }
}

/// Analyze policies and return migration analysis results.
/// Uses Rayon for parallel iteration across policies and shared
/// precomputed data to eliminate redundant work.
pub fn analyze_policies(
    policies: &[AccessPolicyEntry],
    available_roles: &[RoleDefinition],
) -> Vec<MigrationAnalysis> {
    let perm_map = &*PERM_MAP;
    let known_actions = &*KNOWN_ACTIONS;

    // Filter roles to those relevant to Key Vault (done once)
    let kv_roles: Vec<RoleDefinition> = available_roles
        .iter()
        .filter(|r| {
            r.properties.permissions.iter().any(|p| {
                p.data_actions
                    .iter()
                    .any(|da| da.to_lowercase().contains("microsoft.keyvault"))
            })
        })
        .cloned()
        .collect();

    // Use Rayon to parallelize across policies
    policies
        .par_iter()
        .map(|policy| {
            let required_actions = get_required_actions(policy, perm_map);

            // Precompute per-role coverage ONCE for this policy
            let precomputed: Vec<RoleCoverage> = kv_roles
                .iter()
                .map(|role| calculate_coverage(&required_actions, role, known_actions))
                .collect();

            let all_recommendations: Vec<SuggestedRole> = STRATEGIES
                .iter()
                .map(|strategy| {
                    run_weighted_analysis(
                        &required_actions,
                        &precomputed,
                        &kv_roles,
                        strategy,
                    )
                })
                .collect();

            let recommendations = merge_duplicate_strategies(all_recommendations);

            MigrationAnalysis {
                original_policy: policy.clone(),
                recommendations,
                existing_coverage: None,
            }
        })
        .collect()
}

/// Analyze existing RBAC coverage for a policy
pub fn analyze_existing_coverage(
    policy: &AccessPolicyEntry,
    assignments: &[RoleAssignment],
    available_roles: &[RoleDefinition],
    scope_filter: Option<&str>,
) -> ExistingCoverageResult {
    let perm_map = &*PERM_MAP;
    let known_actions = &*KNOWN_ACTIONS;
    let required_actions = get_required_actions(policy, perm_map);

    let user_assignments: Vec<&RoleAssignment> = assignments
        .iter()
        .filter(|a| {
            let same_principal = a.properties.principal_id == policy.object_id;
            if !same_principal {
                return false;
            }

            match scope_filter {
                None => true,
                Some(target) => {
                    let scope = a.properties.scope.to_lowercase();
                    let target_lower = target.to_lowercase();
                    scope == target_lower || scope.starts_with(&format!("{}/", target_lower))
                }
            }
        })
        .collect();

    let mut covered = HashSet::new();
    let mut excess = HashSet::new();
    let mut role_matches = Vec::new();
    let mut processed_roles = HashSet::new();

    for assignment in &user_assignments {
        let role_def_id = assignment
            .properties
            .role_definition_id
            .split('/')
            .last()
            .unwrap_or("");

        let role_def = available_roles
            .iter()
            .find(|r| r.name == role_def_id);

        if let Some(role_def) = role_def {
            if processed_roles.contains(&role_def.properties.role_name) {
                continue;
            }
            processed_roles.insert(role_def.properties.role_name.clone());

            let cov = calculate_coverage(&required_actions, role_def, known_actions);

            for perm in &cov.covered {
                covered.insert(perm.clone());
            }
            for perm in &cov.excess {
                excess.insert(perm.clone());
            }

            if !cov.covered.is_empty() {
                role_matches.push(RoleBreakdown {
                    role_name: role_def.properties.role_name.clone(),
                    covered: cov.covered.into_iter().collect(),
                    excess: cov.excess.into_iter().collect(),
                });
            }
        }
    }

    let missing: Vec<String> = required_actions
        .iter()
        .filter(|p| !covered.contains(*p))
        .cloned()
        .collect();

    ExistingCoverageResult {
        is_fully_covered: missing.is_empty(),
        covered_permissions: covered.into_iter().collect(),
        missing_permissions: missing,
        excess_permissions: excess.into_iter().collect(),
        role_matches,
    }
}
