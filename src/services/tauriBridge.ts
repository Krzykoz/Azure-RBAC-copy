/**
 * Bridge module that routes business logic calls to the Rust backend via Tauri IPC.
 * Falls back to browser-based implementations when not running in Tauri (e.g., dev mode).
 */

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

const isTauri = (): boolean => {
  return !!(window as any).__TAURI_INTERNALS__;
};

let invokeImpl: ((cmd: string, args?: Record<string, unknown>) => Promise<any>) | null = null;

async function getInvoke() {
  if (invokeImpl) return invokeImpl;
  if (isTauri()) {
    const { invoke } = await import('@tauri-apps/api/core');
    invokeImpl = invoke;
    return invoke;
  }
  return null;
}

// --- Token Commands ---

export async function validateToken(token: string): Promise<void> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('validate_token', { token });
  }
  // Fallback to browser fetch
  const { validateToken: browserValidate } = await import('../services/azureService');
  return browserValidate(token);
}

export function getUserName(token: string): Promise<string> {
  return getInvoke().then(async (invoke) => {
    if (invoke) {
      return invoke('get_user_name', { token });
    }
    const { getUserNameFromToken } = await import('../utils/tokenUtils');
    return getUserNameFromToken(token);
  });
}

export function getTenantId(token: string): Promise<string | null> {
  return getInvoke().then(async (invoke) => {
    if (invoke) {
      return invoke('get_tenant_id', { token });
    }
    const { getTenantIdFromToken } = await import('../utils/tokenUtils');
    return getTenantIdFromToken(token);
  });
}

// --- Azure Data Commands ---

export async function getSubscriptions(token: string): Promise<Subscription[]> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('get_subscriptions', { token });
  }
  const { getSubscriptions: browserGet } = await import('../services/azureService');
  return browserGet(token);
}

export async function getTenants(token: string): Promise<Record<string, string>> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('get_tenants', { token });
  }
  const { getTenants: browserGet } = await import('../services/azureService');
  return browserGet(token);
}

export async function getKeyVaults(token: string, subscriptionId: string): Promise<KeyVault[]> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('get_key_vaults', { token, subscriptionId });
  }
  const { getKeyVaults: browserGet } = await import('../services/azureService');
  return browserGet(token, subscriptionId);
}

export async function getRoleDefinitions(
  token: string,
  subscriptionId: string
): Promise<RoleDefinition[]> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('get_role_definitions', { token, subscriptionId });
  }
  const { getRoleDefinitions: browserGet } = await import('../services/azureService');
  return browserGet(token, subscriptionId);
}

export async function getRoleAssignments(
  token: string,
  subscriptionId: string
): Promise<RoleAssignment[]> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('get_role_assignments', { token, subscriptionId });
  }
  const { getRoleAssignments: browserGet } = await import('../services/azureService');
  return browserGet(token, subscriptionId);
}

export async function resolveIdentities(
  objectIds: string[],
  token: string
): Promise<Record<string, ResolvedIdentity>> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('resolve_identities', { objectIds, token });
  }
  const { resolveBatchIdentities } = await import('../services/azureService');
  return resolveBatchIdentities(objectIds, token);
}

// --- Analysis Commands ---

export async function runAnalysis(
  policies: AccessPolicyEntry[],
  availableRoles: RoleDefinition[],
  roleAssignments: RoleAssignment[],
  vaultId: string,
  includeCustomRoles: boolean
): Promise<MigrationAnalysis[]> {
  const invoke = await getInvoke();
  if (invoke) {
    return invoke('run_analysis', {
      policies,
      availableRoles,
      roleAssignments,
      vaultId,
      includeCustomRoles,
    });
  }
  // Fallback to browser-based analysis
  const { analyzePolicies, analyzeExistingCoverage } = await import(
    '../services/analysisService'
  );
  const rolesToAnalyze = includeCustomRoles
    ? availableRoles
    : availableRoles.filter((r) => r.properties.type === 'BuiltInRole');

  const analysis = analyzePolicies(policies, rolesToAnalyze);
  return analysis.map((a) => {
    const coverage = analyzeExistingCoverage(
      a.originalPolicy,
      roleAssignments,
      availableRoles,
      vaultId
    );
    return { ...a, existingCoverage: coverage };
  });
}

// --- Export Commands ---

export type ExportFormat = 'csv' | 'json' | 'powershell';

export async function exportData(
  format: ExportFormat,
  results: MigrationAnalysis[],
  selectedRoles: Record<string, number>,
  resolvedNames: Record<string, ResolvedIdentity>,
  selectedForExport: string[],
  vaultName: string,
  subscriptionId: string,
  vaultResourceId: string
): Promise<string> {
  const invoke = await getInvoke();
  if (invoke) {
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

  // Fallback to browser-based export
  const { exportToCSV, exportToJSON, exportToPowerShell } = await import(
    '../utils/exportUtils'
  );
  const filteredResults = results.filter((r) =>
    selectedForExport.includes(r.originalPolicy.objectId)
  );

  switch (format) {
    case 'csv':
      return exportToCSV(filteredResults, selectedRoles, resolvedNames);
    case 'json':
      return exportToJSON(filteredResults, selectedRoles, resolvedNames);
    case 'powershell':
      return exportToPowerShell(
        filteredResults,
        selectedRoles,
        resolvedNames,
        vaultName,
        subscriptionId,
        vaultResourceId
      );
  }
}
