use serde::{Deserialize, Serialize};

// --- Migration Status ---
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MigrationStatus {
    Idle,
    Loading,
    Analyzing,
    Complete,
    Error,
}

// --- Identity Types ---
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IdentityType {
    User,
    Group,
    Application,
    ServicePrincipal,
    Unknown,
}

impl Default for IdentityType {
    fn default() -> Self {
        IdentityType::Unknown
    }
}

impl From<&str> for IdentityType {
    fn from(s: &str) -> Self {
        match s {
            "User" => IdentityType::User,
            "Group" => IdentityType::Group,
            "Application" => IdentityType::Application,
            "ServicePrincipal" => IdentityType::ServicePrincipal,
            _ => IdentityType::Unknown,
        }
    }
}

// --- Subscription ---
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: String,
    pub display_name: String,
    pub subscription_id: String,
}

// --- Key Vault ---
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVault {
    pub id: String,
    pub name: String,
    pub location: String,
    pub sku: String,
    pub access_policies: Vec<AccessPolicyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicyEntry {
    pub tenant_id: String,
    pub object_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "type")]
    pub identity_type: IdentityType,
    pub permissions: PolicyPermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyPermissions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<String>,
}

// --- Role Definitions ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermission {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, rename = "notActions")]
    pub not_actions: Vec<String>,
    #[serde(default, rename = "dataActions")]
    pub data_actions: Vec<String>,
    #[serde(default, rename = "notDataActions")]
    pub not_data_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleDefinitionProperties {
    pub role_name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub role_type: String,
    pub permissions: Vec<RolePermission>,
    pub assignable_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub def_type: String,
    pub properties: RoleDefinitionProperties,
}

// --- Role Assignments ---
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAssignmentProperties {
    pub role_definition_id: String,
    pub principal_id: String,
    pub principal_type: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub assignment_type: String,
    pub properties: RoleAssignmentProperties,
}

// --- Analysis Results ---
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleBreakdown {
    pub role_name: String,
    pub covered: Vec<String>,
    pub excess: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestedRole {
    pub strategy: String,
    pub role_name: String,
    pub role_names: Vec<String>,
    pub confidence: u32,
    pub reasoning: String,
    pub covered_permissions: Vec<String>,
    pub missing_permissions: Vec<String>,
    pub excess_permissions: Vec<String>,
    pub role_breakdown: Vec<RoleBreakdown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingCoverageResult {
    pub is_fully_covered: bool,
    pub covered_permissions: Vec<String>,
    pub missing_permissions: Vec<String>,
    pub excess_permissions: Vec<String>,
    pub role_matches: Vec<RoleBreakdown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationAnalysis {
    pub original_policy: AccessPolicyEntry,
    pub recommendations: Vec<SuggestedRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_coverage: Option<ExistingCoverageResult>,
}

// --- Resolved Identity ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIdentity {
    pub name: String,
    #[serde(rename = "type")]
    pub identity_type: IdentityType,
}
