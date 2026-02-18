use std::collections::HashMap;
use std::sync::LazyLock;
use reqwest::Client;
use serde::Deserialize;

use crate::constants::*;
use crate::types::*;

/// Custom error type for Azure API operations
#[derive(Debug, thiserror::Error)]
pub enum AzureError {
    #[error("Azure API Error {status}: {message}")]
    ApiError { status: u16, message: String },
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Token error: {0}")]
    TokenError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

impl serde::Serialize for AzureError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Shared HTTP client — reuses connections, enables HTTP/2 multiplexing
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .pool_max_idle_per_host(20)
        .build()
        .expect("Failed to build HTTP client")
});

/// Validate that a subscription ID has a valid GUID-like format
fn validate_subscription_id(subscription_id: &str) -> Result<(), AzureError> {
    let is_valid = subscription_id.len() == 36
        && subscription_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-');
    if !is_valid {
        return Err(AzureError::ParseError(format!(
            "Invalid subscription ID format: {}",
            subscription_id
        )));
    }
    Ok(())
}

/// Generic Azure API GET request
async fn azure_fetch<T: serde::de::DeserializeOwned>(
    url: &str,
    token: &str,
) -> Result<T, AzureError> {
    let response = HTTP_CLIENT
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(AzureError::NetworkError)?;

    let status = response.status().as_u16();
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(AzureError::ApiError {
            status,
            message: error_text,
        });
    }

    response
        .json::<T>()
        .await
        .map_err(AzureError::NetworkError)
}

// --- Azure API Response Types ---

#[derive(Deserialize)]
struct SubscriptionListResponse {
    value: Vec<SubscriptionRaw>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionRaw {
    id: String,
    display_name: String,
    subscription_id: String,
}

#[derive(Deserialize)]
struct TenantListResponse {
    value: Vec<TenantRaw>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TenantRaw {
    tenant_id: String,
    display_name: String,
}

#[derive(Deserialize)]
struct ResourceListResponse {
    value: Vec<ResourceRef>,
}

#[derive(Deserialize)]
struct ResourceRef {
    id: String,
}

#[derive(Deserialize)]
struct KeyVaultResponse {
    id: String,
    name: String,
    location: String,
    properties: KeyVaultPropertiesRaw,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyVaultPropertiesRaw {
    sku: Option<SkuRaw>,
    access_policies: Option<Vec<AccessPolicyRaw>>,
}

#[derive(Deserialize)]
struct SkuRaw {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessPolicyRaw {
    tenant_id: String,
    object_id: String,
    application_id: Option<String>,
    permissions: Option<HashMap<String, Vec<String>>>,
}

#[derive(Deserialize)]
struct RoleDefinitionListResponse {
    value: Vec<RoleDefinition>,
}

#[derive(Deserialize)]
struct RoleAssignmentListResponse {
    value: Vec<RoleAssignmentRaw>,
}

#[derive(Deserialize)]
struct RoleAssignmentRaw {
    id: String,
    name: String,
    #[serde(rename = "type")]
    assignment_type: String,
    properties: RoleAssignmentPropertiesRaw,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleAssignmentPropertiesRaw {
    role_definition_id: String,
    principal_id: String,
    principal_type: String,
    #[serde(default)]
    scope: String,
}

#[derive(Deserialize)]
struct GraphBatchResponse {
    value: Vec<GraphObject>,
}

#[derive(Deserialize)]
struct GraphObject {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "appDisplayName")]
    app_display_name: Option<String>,
    #[serde(rename = "userPrincipalName")]
    user_principal_name: Option<String>,
    #[serde(rename = "mailNickname")]
    mail_nickname: Option<String>,
    #[serde(rename = "@odata.type")]
    odata_type: Option<String>,
}

// --- Public API Functions ---

/// Validate a token by attempting to list subscriptions
pub async fn validate_token(token: &str) -> Result<(), AzureError> {
    let url = format!(
        "{}/subscriptions?api-version={}",
        ARM_ENDPOINT, API_SUBSCRIPTIONS
    );
    match azure_fetch::<serde_json::Value>(&url, token).await {
        Ok(_) => Ok(()),
        Err(AzureError::ApiError { status, message }) => {
            if message.contains("InvalidAuthenticationTokenAudience") || message.contains("audience") {
                Err(AzureError::TokenError(
                    "Token Error: It looks like you pasted a Graph Token into the Management Token field. Please generate a Management token using the first command.".to_string(),
                ))
            } else if status == 401 {
                Err(AzureError::TokenError(
                    "Authentication Failed: The token has expired or is invalid.".to_string(),
                ))
            } else {
                Err(AzureError::ApiError { status, message })
            }
        }
        Err(e) => Err(e),
    }
}

/// Get list of subscriptions
pub async fn get_subscriptions(token: &str) -> Result<Vec<Subscription>, AzureError> {
    let url = format!(
        "{}/subscriptions?api-version={}",
        ARM_ENDPOINT, API_SUBSCRIPTIONS
    );
    let data: SubscriptionListResponse = azure_fetch(&url, token).await?;
    Ok(data
        .value
        .into_iter()
        .map(|s| Subscription {
            id: s.id,
            display_name: s.display_name,
            subscription_id: s.subscription_id,
        })
        .collect())
}

/// Get tenant display names
pub async fn get_tenants(token: &str) -> Result<HashMap<String, String>, AzureError> {
    let url = format!(
        "{}/tenants?api-version={}",
        ARM_ENDPOINT, API_SUBSCRIPTIONS
    );
    let data: TenantListResponse = azure_fetch(&url, token).await?;
    let mut map = HashMap::new();
    for t in data.value {
        map.insert(t.tenant_id, t.display_name);
    }
    Ok(map)
}

/// Get role definitions filtered to Key Vault related roles
pub async fn get_role_definitions(
    token: &str,
    subscription_id: &str,
) -> Result<Vec<RoleDefinition>, AzureError> {
    validate_subscription_id(subscription_id)?;
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions?api-version={}",
        ARM_ENDPOINT, subscription_id, API_AUTHORIZATION
    );
    let data: RoleDefinitionListResponse = azure_fetch(&url, token).await?;

    // Filter to Key Vault related roles
    Ok(data
        .value
        .into_iter()
        .filter(|role| {
            role.properties.permissions.iter().any(|p| {
                p.data_actions
                    .iter()
                    .any(|da| da.to_lowercase().contains("microsoft.keyvault"))
            })
        })
        .collect())
}

/// Get principal types from role assignments (for type inference)
async fn get_principal_types_cache(
    token: &str,
    subscription_id: &str,
) -> HashMap<String, IdentityType> {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Authorization/roleAssignments?api-version={}",
        ARM_ENDPOINT, subscription_id, API_AUTHORIZATION
    );

    match azure_fetch::<RoleAssignmentListResponse>(&url, token).await {
        Ok(data) => {
            let mut cache = HashMap::new();
            for assignment in data.value {
                let pid = assignment.properties.principal_id;
                let ptype = IdentityType::from(assignment.properties.principal_type.as_str());
                cache.insert(pid, ptype);
            }
            cache
        }
        Err(_) => HashMap::new(),
    }
}

/// Get role assignments for a subscription
pub async fn get_role_assignments(
    token: &str,
    subscription_id: &str,
) -> Result<Vec<RoleAssignment>, AzureError> {
    validate_subscription_id(subscription_id)?;
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Authorization/roleAssignments?api-version={}",
        ARM_ENDPOINT, subscription_id, API_AUTHORIZATION
    );
    let data: RoleAssignmentListResponse = azure_fetch(&url, token).await?;
    Ok(data
        .value
        .into_iter()
        .map(|a| RoleAssignment {
            id: a.id,
            name: a.name,
            assignment_type: a.assignment_type,
            properties: RoleAssignmentProperties {
                role_definition_id: a.properties.role_definition_id,
                principal_id: a.properties.principal_id,
                principal_type: a.properties.principal_type,
                scope: a.properties.scope,
            },
        })
        .collect())
}

/// Expand "all" permissions to the full standard set (excluding Purge and Release)
fn expand_permissions(
    raw_permissions: &HashMap<String, Vec<String>>,
) -> PolicyPermissions {
    let all_perms = key_vault_all_permissions();

    let expand_category = |category: &str, perms: &[String]| -> Vec<String> {
        let has_all = perms.iter().any(|p| p.to_lowercase() == "all");
        if has_all {
            if let Some(standard_perms) = all_perms.get(category) {
                let mut result: Vec<String> = standard_perms.iter().map(|s| s.to_string()).collect();
                // Add other non-"all" perms like "Purge"
                for p in perms {
                    if p.to_lowercase() != "all" {
                        let normalized = capitalize_first(p);
                        if !result.contains(&normalized) {
                            result.push(normalized);
                        }
                    }
                }
                result
            } else {
                perms.to_vec()
            }
        } else {
            perms.to_vec()
        }
    };

    PolicyPermissions {
        keys: raw_permissions
            .get("keys")
            .map(|p| expand_category("keys", p))
            .unwrap_or_default(),
        secrets: raw_permissions
            .get("secrets")
            .map(|p| expand_category("secrets", p))
            .unwrap_or_default(),
        certificates: raw_permissions
            .get("certificates")
            .map(|p| expand_category("certificates", p))
            .unwrap_or_default(),
        storage: raw_permissions
            .get("storage")
            .map(|p| expand_category("storage", p))
            .unwrap_or_default(),
    }
}

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + c.as_str(),
    }
}

/// Get Key Vaults for a subscription
pub async fn get_key_vaults(
    token: &str,
    subscription_id: &str,
) -> Result<Vec<KeyVault>, AzureError> {
    validate_subscription_id(subscription_id)?;
    let list_url = format!(
        "{}/subscriptions/{}/resources?$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version={}",
        ARM_ENDPOINT, subscription_id, API_RESOURCES
    );

    let (list_data, principal_type_cache) = tokio::join!(
        azure_fetch::<ResourceListResponse>(&list_url, token),
        get_principal_types_cache(token, subscription_id)
    );

    let list_data = list_data?;
    if list_data.value.is_empty() {
        return Ok(vec![]);
    }

    let mut results = Vec::new();

    for chunk in list_data.value.chunks(VAULT_CONCURRENCY_LIMIT) {
        let futures: Vec<_> = chunk
            .iter()
            .map(|resource| {
                let vault_url = format!(
                    "{}{}?api-version={}",
                    ARM_ENDPOINT, resource.id, API_KEYVAULT
                );
                let token = token.to_string();
                let cache = principal_type_cache.clone();
                async move {
                    match azure_fetch::<KeyVaultResponse>(&vault_url, &token).await {
                        Ok(vault_data) => Some(parse_key_vault_response(vault_data, &cache)),
                        Err(e) => {
                            eprintln!("Failed to fetch vault details: {}", e);
                            None
                        }
                    }
                }
            })
            .collect();

        let chunk_results = futures::future::join_all(futures).await;
        for result in chunk_results {
            if let Some(vault) = result {
                results.push(vault);
            }
        }
    }

    Ok(results)
}

fn parse_key_vault_response(
    vault_data: KeyVaultResponse,
    principal_type_cache: &HashMap<String, IdentityType>,
) -> KeyVault {
    let access_policies = vault_data
        .properties
        .access_policies
        .unwrap_or_default()
        .into_iter()
        .map(|ap| {
            let identity_type = if ap.application_id.is_some()
                && ap.application_id.as_deref() != Some("")
            {
                IdentityType::Application
            } else if let Some(cached_type) = principal_type_cache.get(&ap.object_id) {
                cached_type.clone()
            } else {
                IdentityType::Unknown
            };

            let permissions = ap
                .permissions
                .map(|p| expand_permissions(&p))
                .unwrap_or_default();

            AccessPolicyEntry {
                tenant_id: ap.tenant_id,
                object_id: ap.object_id,
                application_id: ap.application_id,
                display_name: None,
                identity_type,
                permissions,
            }
        })
        .collect();

    KeyVault {
        id: vault_data.id,
        name: vault_data.name,
        location: vault_data.location,
        sku: vault_data
            .properties
            .sku
            .map(|s| s.name)
            .unwrap_or_else(|| "Unknown".to_string()),
        access_policies,
    }
}

/// Resolve batch identities using Microsoft Graph API
pub async fn resolve_batch_identities(
    object_ids: &[String],
    token: &str,
) -> HashMap<String, ResolvedIdentity> {
    if object_ids.is_empty() {
        return HashMap::new();
    }

    let unique_ids: Vec<&String> = {
        let mut seen = std::collections::HashSet::new();
        object_ids.iter().filter(|id| seen.insert(id.as_str())).collect()
    };

    let mut results = HashMap::new();

    for chunk in unique_ids.chunks(GRAPH_BATCH_SIZE) {
        let chunk_ids: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        let body = serde_json::json!({
            "ids": chunk_ids,
            "types": ["user", "group", "servicePrincipal", "application"]
        });

        match HTTP_CLIENT
            .post(&format!("{}/directoryObjects/getByIds", GRAPH_ENDPOINT))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                if let Ok(data) = response.json::<GraphBatchResponse>().await {
                    for item in data.value {
                        let name = item
                            .display_name
                            .or(item.app_display_name)
                            .or(item.user_principal_name)
                            .or(item.mail_nickname);

                        let identity_type = match item.odata_type.as_deref() {
                            Some("#microsoft.graph.user") => IdentityType::User,
                            Some("#microsoft.graph.group") => IdentityType::Group,
                            Some("#microsoft.graph.servicePrincipal") => {
                                IdentityType::ServicePrincipal
                            }
                            Some("#microsoft.graph.application") => IdentityType::Application,
                            _ => IdentityType::Unknown,
                        };

                        if let Some(name) = name {
                            results.insert(
                                item.id,
                                ResolvedIdentity {
                                    name,
                                    identity_type,
                                },
                            );
                        }
                    }
                }
            }
            Ok(response) => {
                eprintln!(
                    "Graph API resolution failed (Status: {})",
                    response.status()
                );
            }
            Err(e) => {
                eprintln!("Graph API call failed: {}", e);
            }
        }
    }

    results
}
