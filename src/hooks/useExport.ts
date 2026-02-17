import { useCallback, useState } from 'react';
import { MigrationAnalysis, IdentityType } from '../types';
import { exportData, ExportFormat } from '../services/tauriBridge';
import { downloadFile } from '../utils/exportUtils';

export type { ExportFormat } from '../services/tauriBridge';

interface UseExportProps {
    results: MigrationAnalysis[];
    selectedRoles: Record<string, number>;
    resolvedNames: Record<string, { name: string; type: IdentityType }>;
    selectedForExport: Set<string>;
    vaultName: string;
    subscriptionId: string;
    vaultResourceId: string;
}

interface UseExportResult {
    showExportMenu: boolean;
    setShowExportMenu: (show: boolean) => void;
    handleExport: (format: ExportFormat) => boolean;
}

/**
 * Hook for handling export functionality
 */
export const useExport = ({
    results,
    selectedRoles,
    resolvedNames,
    selectedForExport,
    vaultName,
    subscriptionId,
    vaultResourceId,
}: UseExportProps): UseExportResult => {
    const [showExportMenu, setShowExportMenu] = useState(false);

    const handleExport = useCallback(
        (format: ExportFormat): boolean => {
            const selectedForExportArray = Array.from(selectedForExport);

            if (selectedForExportArray.length === 0) {
                alert('Please select at least one identity to export.');
                return false;
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);

            const doExport = async () => {
                try {
                    const content = await exportData(
                        format,
                        results,
                        selectedRoles,
                        resolvedNames,
                        selectedForExportArray,
                        vaultName,
                        subscriptionId,
                        vaultResourceId
                    );

                    const mimeTypes: Record<ExportFormat, string> = {
                        csv: 'text/csv',
                        json: 'application/json',
                        powershell: 'text/plain',
                    };
                    const extensions: Record<ExportFormat, string> = {
                        csv: 'csv',
                        json: 'json',
                        powershell: 'ps1',
                    };

                    downloadFile(
                        content,
                        `${vaultName}-migration-${timestamp}.${extensions[format]}`,
                        mimeTypes[format]
                    );
                } catch (err) {
                    console.error('Export failed:', err);
                }
            };

            doExport();
            setShowExportMenu(false);
            return true;
        },
        [
            results,
            selectedRoles,
            resolvedNames,
            selectedForExport,
            vaultName,
            subscriptionId,
            vaultResourceId,
        ]
    );

    return {
        showExportMenu,
        setShowExportMenu,
        handleExport,
    };
};
