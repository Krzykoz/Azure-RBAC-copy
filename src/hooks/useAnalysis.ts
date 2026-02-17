import { useState, useCallback, useMemo } from 'react';
import {
    KeyVault,
    RoleDefinition,
    RoleAssignment,
    MigrationAnalysis,
    MigrationStatus,
    IdentityType,
} from '../types';
import { analyzeSinglePolicy } from '../services/tauriBridge';
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
 * Analyzes each identity in parallel and streams results as they complete.
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

        // Initialize progress tracking
        const identities: Record<string, 'pending' | 'analyzing' | 'done'> = {};
        policies.forEach((p) => {
            identities[p.objectId] = 'pending';
        });
        setProgress({ total, completed: 0, identities: { ...identities } });

        // Reset state
        setResults([]);
        setSelectedRoles({});
        setSelectedForExport(new Set());

        // Launch all analyses in parallel — each identity gets its own IPC call
        const promises = policies.map(async (policy) => {
            // Mark as analyzing
            setProgress((prev) => {
                if (!prev) return prev;
                return {
                    ...prev,
                    identities: { ...prev.identities, [policy.objectId]: 'analyzing' },
                };
            });

            try {
                const result = await analyzeSinglePolicy(
                    policy,
                    rolesToAnalyze,
                    roleAssignments,
                    selectedVault.id,
                    includeCustomRoles,
                );

                const bestIdx = findBestStrategyIndex(result.recommendations);

                // Use functional state updates to avoid race conditions
                setResults((prev) => [...prev, result]);
                setSelectedRoles((prev) => ({
                    ...prev,
                    [result.originalPolicy.objectId]: bestIdx,
                }));

                // Update export selection
                const resolvedType = resolvedNames[result.originalPolicy.objectId]?.type;
                const policyType = result.originalPolicy.type;
                const type = resolvedType || policyType || 'Unknown';
                if (type !== 'Unknown') {
                    setSelectedForExport((prev) => {
                        const next = new Set(prev);
                        next.add(result.originalPolicy.objectId);
                        return next;
                    });
                }

                // Mark as done using functional update for accurate count
                setProgress((prev) => {
                    if (!prev) return prev;
                    return {
                        ...prev,
                        completed: prev.completed + 1,
                        identities: { ...prev.identities, [policy.objectId]: 'done' },
                    };
                });
            } catch (err) {
                console.error(`Analysis failed for ${policy.objectId}:`, err);
                setProgress((prev) => {
                    if (!prev) return prev;
                    return {
                        ...prev,
                        completed: prev.completed + 1,
                        identities: { ...prev.identities, [policy.objectId]: 'done' },
                    };
                });
            }
        });

        await Promise.all(promises);

        // Clear progress after completion
        setProgress(null);
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
