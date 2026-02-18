/// Azure API version constants
pub const API_SUBSCRIPTIONS: &str = "2022-12-01";
pub const API_RESOURCES: &str = "2021-04-01";
pub const API_AUTHORIZATION: &str = "2022-04-01";
pub const API_KEYVAULT: &str = "2024-11-01";

/// Azure endpoints
pub const ARM_ENDPOINT: &str = "https://management.azure.com";
pub const GRAPH_ENDPOINT: &str = "https://graph.microsoft.com/v1.0";

/// Analysis constants
pub const MAX_COMBINATION_SIZE: usize = 10;
pub const GRAPH_BATCH_SIZE: usize = 20;
pub const VAULT_CONCURRENCY_LIMIT: usize = 5;

/// Strategy configuration
#[derive(Debug, Clone)]
pub struct StrategyConfig {
    pub name: &'static str,
    pub description: &'static str,
    pub weight_coverage: f64,
    pub weight_excess: f64,
    pub weight_role_count: f64,
    pub threshold: f64,
}

pub const STRATEGIES: [StrategyConfig; 3] = [
    StrategyConfig {
        name: "Max Coverage",
        description: "Prioritizes covering all permissions, even if it means granting some excess access.",
        weight_coverage: 10.0,
        weight_excess: 0.15,
        weight_role_count: 0.1,
        threshold: -100.0,
    },
    StrategyConfig {
        name: "Minimize Excess",
        description: "Strictly avoids excess permissions. May leave gaps if no clean role exists.",
        weight_coverage: 2.0,
        weight_excess: 5.0,
        weight_role_count: 0.1,
        threshold: 0.1,
    },
    StrategyConfig {
        name: "Balanced",
        description: "A middle ground that seeks coverage while avoiding large security risks.",
        weight_coverage: 5.0,
        weight_excess: 1.0,
        weight_role_count: 0.1,
        threshold: 0.0,
    },
];

/// Permission definitions for Key Vault
pub fn key_vault_all_permissions() -> std::collections::HashMap<&'static str, Vec<&'static str>> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "keys",
        vec![
            "Get", "List", "Update", "Create", "Import", "Delete", "Recover",
            "Backup", "Restore", "Decrypt", "Encrypt", "UnwrapKey", "WrapKey",
            "Verify", "Sign", "Rotate", "GetRotationPolicy", "SetRotationPolicy",
        ],
    );
    map.insert(
        "secrets",
        vec!["Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"],
    );
    map.insert(
        "certificates",
        vec![
            "Get", "List", "Update", "Create", "Import", "Delete", "Recover",
            "Backup", "Restore", "ManageContacts", "ManageIssuers", "GetIssuers",
            "ListIssuers", "SetIssuers", "DeleteIssuers",
        ],
    );
    map.insert(
        "storage",
        vec![
            "Get", "List", "Delete", "Set", "Update", "RegenerateKey", "GetSas",
            "ListSas", "DeleteSas", "SetSas", "Recover", "Backup", "Restore",
        ],
    );
    map
}

/// Strategy priority for tie-breaking
pub fn strategy_priority(name: &str) -> u32 {
    match name {
        "Minimize Excess" => 3,
        "Balanced" => 2,
        "Max Coverage" => 1,
        _ => 0,
    }
}
