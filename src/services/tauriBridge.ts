/**
 * Bridge module that routes all business logic to the Rust backend via Tauri IPC.
 * No browser fallbacks — this app requires the Tauri runtime.
 */

import { invoke } from '@tauri-apps/api/core';
import type {
  Subscription,
  KeyVault,
  RoleDefinition,
  RoleAssignment,
  MigrationAnalysis,
  AccessPolicyEntry,
  IdentityType,
} from '../types';

// Re-export ResolvedIdentity for convenience
export type ResolvedIdentity = { name: string; type: IdentityType };

// --- Token Commands ---

export function validateToken(token: string): Promise<void> {
  return invoke('validate_token', { token });
}

export function getUserName(token: string): Promise<string> {
  return invoke('get_user_name', { token });
}

export function getTenantId(token: string): Promise<string | null> {
  return invoke('get_tenant_id', { token });
}

// --- Azure Data Commands ---

export function getSubscriptions(token: string): Promise<Subscription[]> {
  return invoke('get_subscriptions', { token });
}

export function getTenants(token: string): Promise<Record<string, string>> {
  return invoke('get_tenants', { token });
}

export function getKeyVaults(token: string, subscriptionId: string): Promise<KeyVault[]> {
  return invoke('get_key_vaults', { token, subscriptionId });
}

export function getRoleDefinitions(
  token: string,
  subscriptionId: string
): Promise<RoleDefinition[]> {
  return invoke('get_role_definitions', { token, subscriptionId });
}

export function getRoleAssignments(
  token: string,
  subscriptionId: string
): Promise<RoleAssignment[]> {
  return invoke('get_role_assignments', { token, subscriptionId });
}

export function resolveIdentities(
  objectIds: string[],
  token: string
): Promise<Record<string, ResolvedIdentity>> {
  return invoke('resolve_identities', { objectIds, token });
}

// --- Analysis Commands ---

export function runAnalysis(
  policies: AccessPolicyEntry[],
  availableRoles: RoleDefinition[],
  roleAssignments: RoleAssignment[],
  vaultId: string,
  includeCustomRoles: boolean
): Promise<MigrationAnalysis[]> {
  return invoke('run_analysis', {
    policies,
    availableRoles,
    roleAssignments,
    vaultId,
    includeCustomRoles,
  });
}

export function analyzeSinglePolicy(
  policy: AccessPolicyEntry,
  availableRoles: RoleDefinition[],
  roleAssignments: RoleAssignment[],
  vaultId: string,
  includeCustomRoles: boolean
): Promise<MigrationAnalysis> {
  return invoke('analyze_single_policy', {
    policy,
    availableRoles,
    roleAssignments,
    vaultId,
    includeCustomRoles,
  });
}

// --- Export Commands ---

export type ExportFormat = 'csv' | 'json' | 'powershell';

export function exportData(
  format: ExportFormat,
  results: MigrationAnalysis[],
  selectedRoles: Record<string, number>,
  resolvedNames: Record<string, ResolvedIdentity>,
  selectedForExport: string[],
  vaultName: string,
  subscriptionId: string,
  vaultResourceId: string
): Promise<string> {
  switch (format) {
    case 'csv':
      return invoke('export_csv', {
        results,
        selectedRoles,
        resolvedNames,
        selectedForExport,
      });
    case 'json':
      return invoke('export_json', {
        results,
        selectedRoles,
        resolvedNames,
        selectedForExport,
      });
    case 'powershell':
      return invoke('export_powershell', {
        results,
        selectedRoles,
        resolvedNames,
        selectedForExport,
        vaultName,
        subscriptionId,
        vaultResourceId,
      });
  }
}
