# Azure Key Vault RBAC Migrator

A **Tauri desktop application** that helps you migrate Azure Key Vault access policies to modern RBAC role mappings. All business logic runs in a **Rust backend** for performance and security, with a React frontend for the UI.

## Overview

- **Desktop application** – Built with [Tauri](https://tauri.app/) for native performance with a small binary size.
- **Rust backend** – All Azure API calls, token handling, RBAC analysis, and export generation run in Rust.
- **Token‑based authentication** – Paste Azure CLI tokens (Management and optional Graph) directly.
- **Multi‑strategy analysis** – Three weighted greedy algorithms:
  - **Minimize Excess** – Strict, avoids unnecessary permissions.
  - **Balanced** – Good trade‑off between coverage and security.
  - **Max Coverage** – Prioritises full permission coverage.
- **Export results** – Download analysis as CSV, JSON, or PowerShell script.
- **Dark / Light mode** – Tailwind‑based theming with enhanced contrast for readability.
- **Browser fallback** – The frontend can also run in dev mode without Tauri, falling back to browser‑based implementations.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (1.70+ recommended)
- [Node.js](https://nodejs.org/) (v18+)
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) installed.
- System dependencies for Tauri:
  - **Linux**: `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `libsoup-3.0-dev`
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Microsoft Visual Studio C++ Build Tools, WebView2

## Setup

```bash
# Clone the repo
git clone git@github.com:Krzykoz/Azure-RBAC-Migration-Tool.git
cd Azure-RBAC-Migration-Tool

# Install frontend dependencies
npm install

# Run in development mode (starts Vite + Tauri together)
npm run tauri:dev
```

## Build for Production

```bash
npm run tauri:build
```

The production binary will be in `src-tauri/target/release/`.

## Usage

1. **Generate tokens**:
   ```bash
   # Management token (required)
   az account get-access-token --resource https://management.azure.com -o tsv --query accessToken

   # Graph token (optional, for name resolution)
   az account get-access-token --resource https://graph.microsoft.com -o tsv --query accessToken
   ```
2. Open the app, paste the Management token (and optionally the Graph token), and click **Connect**.
3. Select a subscription and a Key Vault, then click **Run Analysis**.
4. Review the recommended role combinations. Switch between the three strategies using the buttons.
5. Export the results via the **Export** button in the workspace header.

## Architecture

```
├── src/                         # React frontend (Vite + TypeScript)
│   ├── components/              # React UI components
│   ├── hooks/                   # React hooks for state management
│   ├── services/
│   │   ├── tauriBridge.ts       # IPC bridge to Rust backend (with browser fallback)
│   │   ├── azureService.ts      # Browser-based Azure API (fallback)
│   │   └── analysisService.ts   # Browser-based analysis (fallback)
│   ├── utils/                   # Helper utilities
│   ├── assets/                  # Static files (CSV mapping)
│   ├── types.ts
│   └── App.tsx
│
├── src-tauri/                   # Rust backend (Tauri)
│   ├── src/
│   │   ├── main.rs              # Application entry point
│   │   ├── lib.rs               # Tauri plugin registration
│   │   ├── commands.rs          # Tauri IPC command handlers
│   │   ├── azure_service.rs     # Azure REST API client (reqwest)
│   │   ├── analysis_service.rs  # RBAC analysis engine
│   │   ├── token_utils.rs       # JWT decoding
│   │   ├── export_utils.rs      # CSV/JSON/PowerShell generation
│   │   ├── constants.rs         # Configuration constants
│   │   └── types.rs             # Shared type definitions
│   ├── Cargo.toml
│   └── tauri.conf.json
```

## How It Works

1. **Data fetching** – The Rust backend retrieves subscriptions, vaults, role definitions, and access policies via Azure ARM APIs using `reqwest`.
2. **Mapping** – The `AcessPolicyRBACMapping.csv` is embedded at compile time and parsed to map legacy permissions to RBAC data actions.
3. **Analysis** – Three weighted greedy algorithms run in Rust to propose optimal role sets.
4. **Scoring** – Confidence scores are calculated based on coverage and excess permissions.
5. **Presentation** – The React frontend displays visual breakdowns with charts, tooltips, and export options.
6. **IPC** – All communication between frontend and backend uses Tauri's type-safe `invoke()` mechanism.

## Security

- Tokens are kept **in memory only**; never persisted to disk.
- All Azure API calls are made from the Rust backend, not from the webview.
- The app uses a strict Content Security Policy (CSP).
- No data is transmitted outside the app except to Azure APIs.

## Technologies

- **Tauri 2** – Desktop application framework
- **Rust** – Backend business logic
- **React 19** – Frontend UI
- **TypeScript** – Frontend type safety
- **Vite** – Frontend build tool
- **Tailwind CSS** – Styling
- **Recharts** – Data visualization

## License

MIT

## Contributing

Contributions are welcome! Open an issue or submit a pull request.
