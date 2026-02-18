/**
 * Frontend-only constants for Azure RBAC Migration Tool.
 * Backend constants (API versions, endpoints, analysis config) are in Rust: src-tauri/src/constants.rs
 */

// UI Constants
export const UI_CONSTANTS = {
    PERMISSION_VISIBLE_LIMIT: 6,
    COPY_FEEDBACK_DURATION_MS: 2000,
} as const;

// Strategy Priority for tie-breaking (used in useAnalysis hook)
export const STRATEGY_PRIORITY: Record<string, number> = {
    'Minimize Excess': 3,
    'Balanced': 2,
    'Max Coverage': 1,
};
