import { useState, useCallback, useMemo } from 'react';
import {
    KeyVault,
    RoleDefinition,
    RoleAssignment,
    MigrationAnalysis,
    MigrationStatus,
    IdentityType,
} from '../types';
import { runAnalysis as runAnalysisBridge } from '../services/tauriBridge';
import { STRATEGY_PRIORITY } from '../constants';

interface UseAnalysisProps {
    selectedVault: KeyVault | null;
    availableRoles: RoleDefinition[];
    roleAssignments: RoleAssignment[];
    resolvedNames: Record<string, { name: string; type: IdentityType }>;
    includeCustomRoles: boolean;
}

export interface AnalysisProgress {
    total: number;
    completed: number;
    /** objectId -> progress state */
    identities: Record<string, 'pending' | 'analyzing' | 'done'>;
}

interface UseAnalysisResult {
    results: MigrationAnalysis[];
    selectedRoles: Record<string, number>;
    setSelectedRoles: React.Dispatch<React.SetStateAction<Record<string, number>>>;
    selectedForExport: Set<string>;
    setSelectedForExport: React.Dispatch<React.SetStateAction<Set<string>>>;
    runAnalysis: () => Promise<void>;
    clearResults: () => void;
    progress: AnalysisProgress | null;
}

/**
 * Determines the best strategy index for a given analysis result
 */
const findBestStrategyIndex = (recommendations: MigrationAnalysis['recommendations']): number => {
    if (recommendations.length === 0) return 0;

    let bestIndex = 0;
    let bestConfidence = recommendations[0]?.confidence || 0;

    for (let i = 1; i < recommendations.length; i++) {
        const current = recommendations[i];
        const currentConfidence = current.confidence;

        if (currentConfidence > bestConfidence) {
            bestIndex = i;
            bestConfidence = currentConfidence;
        } else if (currentConfidence === bestConfidence) {
            const currentPriority = STRATEGY_PRIORITY[current.strategy] || 0;
            const bestPriority = STRATEGY_PRIORITY[recommendations[bestIndex].strategy] || 0;

            if (currentPriority > bestPriority) {
                bestIndex = i;
            }
        }
    }

    return bestIndex;
};

/**
 * Hook for managing RBAC analysis state and execution.
 * Sends all policies in a single batched IPC call to the Rust backend,
 * which uses Rayon for true multi-core parallelism internally.
 */
export const useAnalysis = ({
    selectedVault,
    availableRoles,
    roleAssignments,
    resolvedNames,
    includeCustomRoles,
}: UseAnalysisProps): UseAnalysisResult => {
    const [results, setResults] = useState<MigrationAnalysis[]>([]);
    const [selectedRoles, setSelectedRoles] = useState<Record<string, number>>({});
    const [selectedForExport, setSelectedForExport] = useState<Set<string>>(new Set());
    const [progress, setProgress] = useState<AnalysisProgress | null>(null);

    // Filter roles based on custom role toggle
    const rolesToAnalyze = useMemo(() => {
        if (includeCustomRoles) return availableRoles;
        return availableRoles.filter((r) => r.properties.type === 'BuiltInRole');
    }, [availableRoles, includeCustomRoles]);

    const runAnalysis = useCallback(async () => {
        if (!selectedVault) return;

        const policies = selectedVault.accessPolicies;
        const total = policies.length;

        // Initialize progress — mark all as analyzing (batch runs all at once)
        const identities: Record<string, 'pending' | 'analyzing' | 'done'> = {};
        policies.forEach((p) => {
            identities[p.objectId] = 'analyzing';
        });
        setProgress({ total, completed: 0, identities: { ...identities } });

        // Reset state
        setResults([]);
        setSelectedRoles({});
        setSelectedForExport(new Set());

        try {
            // Single IPC call — Rust parallelizes internally via Rayon
            const enhancedAnalysis = await runAnalysisBridge(
                policies,
                rolesToAnalyze,
                roleAssignments,
                selectedVault.id,
                includeCustomRoles,
            );

            setResults(enhancedAnalysis);

            // Set default strategy selections
            const defaults: Record<string, number> = {};
            enhancedAnalysis.forEach((a) => {
                defaults[a.originalPolicy.objectId] = findBestStrategyIndex(a.recommendations);
            });
            setSelectedRoles(defaults);

            // Initialize export selection (all except Unknown type)
            const exportIds = new Set<string>();
            enhancedAnalysis.forEach((a) => {
                const resolvedType = resolvedNames[a.originalPolicy.objectId]?.type;
                const policyType = a.originalPolicy.type;
                const type = resolvedType || policyType || 'Unknown';
                if (type !== 'Unknown') {
                    exportIds.add(a.originalPolicy.objectId);
                }
            });
            setSelectedForExport(exportIds);

            // Mark all done
            const doneIdentities: Record<string, 'pending' | 'analyzing' | 'done'> = {};
            policies.forEach((p) => {
                doneIdentities[p.objectId] = 'done';
            });
            setProgress({ total, completed: total, identities: doneIdentities });
        } catch (err) {
            console.error('Analysis failed:', err);
            throw err;
        } finally {
            // Clear progress after a brief delay so user sees completion
            setTimeout(() => setProgress(null), 500);
        }
    }, [selectedVault, rolesToAnalyze, roleAssignments, includeCustomRoles, resolvedNames]);

    const clearResults = useCallback(() => {
        setResults([]);
        setSelectedRoles({});
        setSelectedForExport(new Set());
        setProgress(null);
    }, []);

    return {
        results,
        selectedRoles,
        setSelectedRoles,
        selectedForExport,
        setSelectedForExport,
        runAnalysis,
        clearResults,
        progress,
    };
};
