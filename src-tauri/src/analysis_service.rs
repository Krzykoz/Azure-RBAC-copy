use std::collections::{HashMap, HashSet};

use crate::constants::*;
use crate::types::*;

/// The CSV mapping content is embedded at compile time
const RBAC_MAPPING_CSV: &str = include_str!("../../src/assets/AcessPolicyRBACMapping.csv");

/// Parsed permission mapping: category -> (action -> [rbac_actions])
type PermissionMap = HashMap<String, HashMap<String, Vec<String>>>;

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

fn escape_regex(s: &str) -> String {
    let special_chars = r".*+?^${}()|[]\";
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if special_chars.contains(c) {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

/// Check if a role action matches a required action (supports wildcards)
fn action_matches(role_action: &str, required_action: &str) -> bool {
    let r = role_action.to_lowercase();
    let req = required_action.to_lowercase();

    if r == "*" || r == req {
        return true;
    }

    if r.ends_with("/*") {
        let prefix = &r[..r.len() - 2];
        return req.starts_with(prefix);
    }

    if r.contains('*') {
        let pattern = r
            .split('*')
            .map(|part| escape_regex(part))
            .collect::<Vec<_>>()
            .join(".*");
        let pattern = format!("^{}$", pattern);
        if let Ok(re) = regex::Regex::new(&pattern) {
            return re.is_match(&req);
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
                    // Map to ALL permissions in this category
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

/// Calculate coverage of a role against required permissions
fn calculate_coverage(
    required: &HashSet<String>,
    role: &RoleDefinition,
    known_actions: &HashSet<String>,
) -> (HashSet<String>, HashSet<String>) {
    let mut covered = HashSet::new();
    let mut excess = HashSet::new();

    for p in &role.properties.permissions {
        for da in &p.data_actions {
            if !da.to_lowercase().contains("microsoft.keyvault") {
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
            } else {
                let matched = required.iter().find(|req| {
                    req.to_lowercase() == da.to_lowercase()
                });

                if let Some(matched_req) = matched {
                    covered.insert(matched_req.clone());
                } else {
                    let da_lower = da.to_lowercase();
                    if known_actions.contains(&da_lower) || da_lower.ends_with("/action") {
                        excess.insert(da.clone());
                    }
                }
            }
        }
    }

    (covered, excess)
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

/// Run weighted analysis for a single strategy
fn run_weighted_analysis(
    required: &HashSet<String>,
    roles: &[RoleDefinition],
    config: &StrategyConfig,
    known_actions: &HashSet<String>,
) -> SuggestedRole {
    let mut best_combination: Vec<&RoleDefinition> = Vec::new();
    let mut best_score = f64::NEG_INFINITY;
    let mut best_covered: HashSet<String> = HashSet::new();
    let mut best_excess: HashSet<String> = HashSet::new();

    // Filter to roles that cover at least one required permission
    let useful_roles: Vec<&RoleDefinition> = roles
        .iter()
        .filter(|r| {
            let (covered, _) = calculate_coverage(required, r, known_actions);
            !covered.is_empty()
        })
        .collect();

    // Generate and evaluate combinations
    fn generate_combinations<'a>(
        start_idx: usize,
        current_combo: &mut Vec<&'a RoleDefinition>,
        useful_roles: &[&'a RoleDefinition],
        required: &HashSet<String>,
        config: &StrategyConfig,
        known_actions: &HashSet<String>,
        best_score: &mut f64,
        best_combination: &mut Vec<&'a RoleDefinition>,
        best_covered: &mut HashSet<String>,
        best_excess: &mut HashSet<String>,
    ) {
        if !current_combo.is_empty() {
            let mut combined_covered = HashSet::new();
            let mut combined_excess = HashSet::new();

            for role in current_combo.iter() {
                let (covered, excess) = calculate_coverage(required, role, known_actions);
                combined_covered.extend(covered);
                combined_excess.extend(excess);
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

        for i in start_idx..useful_roles.len() {
            current_combo.push(useful_roles[i]);
            generate_combinations(
                i + 1,
                current_combo,
                useful_roles,
                required,
                config,
                known_actions,
                best_score,
                best_combination,
                best_covered,
                best_excess,
            );
            current_combo.pop();
        }
    }

    let mut current_combo: Vec<&RoleDefinition> = Vec::new();
    generate_combinations(
        0,
        &mut current_combo,
        &useful_roles,
        required,
        config,
        known_actions,
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
        .map(|role| {
            let (covered, excess) = calculate_coverage(required, role, known_actions);
            RoleBreakdown {
                role_name: role.properties.role_name.clone(),
                covered: covered.into_iter().collect(),
                excess: excess.into_iter().collect(),
            }
        })
        .collect();

    let missing: Vec<String> = required
        .iter()
        .filter(|x| !best_covered.contains(*x))
        .cloned()
        .collect();

    let role_names: Vec<String> = best_combination
        .iter()
        .map(|r| r.properties.role_name.clone())
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

/// Analyze policies and return migration analysis results
pub fn analyze_policies(
    policies: &[AccessPolicyEntry],
    available_roles: &[RoleDefinition],
) -> Vec<MigrationAnalysis> {
    let perm_map = parse_permission_map();
    let known_actions = all_known_rbac_actions(&perm_map);

    // Filter roles to those relevant to Key Vault
    let kv_roles: Vec<&RoleDefinition> = available_roles
        .iter()
        .filter(|r| {
            r.properties.permissions.iter().any(|p| {
                p.data_actions
                    .iter()
                    .any(|da| da.to_lowercase().contains("microsoft.keyvault"))
            })
        })
        .collect();

    let kv_roles_owned: Vec<RoleDefinition> = kv_roles.into_iter().cloned().collect();

    policies
        .iter()
        .map(|policy| {
            let required_actions = get_required_actions(policy, &perm_map);

            let all_recommendations: Vec<SuggestedRole> = STRATEGIES
                .iter()
                .map(|strategy| {
                    run_weighted_analysis(
                        &required_actions,
                        &kv_roles_owned,
                        strategy,
                        &known_actions,
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
    let perm_map = parse_permission_map();
    let known_actions = all_known_rbac_actions(&perm_map);
    let required_actions = get_required_actions(policy, &perm_map);

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

            let (c, e) = calculate_coverage(&required_actions, role_def, &known_actions);
            let role_covered: HashSet<String> = c.iter().cloned().collect();

            for perm in &c {
                covered.insert(perm.clone());
            }
            for perm in &e {
                excess.insert(perm.clone());
            }

            if !role_covered.is_empty() {
                role_matches.push(RoleBreakdown {
                    role_name: role_def.properties.role_name.clone(),
                    covered: role_covered.into_iter().collect(),
                    excess: e.into_iter().collect(),
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
