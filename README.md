# MSBuild Guard

**MSBuild Guard** is a security analysis tool for .NET projects that detects risky or untrusted MSBuild configurations — including imported `.targets`, `.props`, NuGet package assets, wildcard imports, and more — before they can execute arbitrary code on your machine.

It integrates into your daily workflow through three complementary surfaces:

| Module | Description |
|---|---|
| **CLI** | Cross-platform command-line scanner for local use, CI/CD, and Git hooks |
| **Windows Explorer Extension** | Right-click context menu and icon overlay integration for shell-level scanning |
| **Visual Studio Extension (VSIX)** | Inline security review panel inside Visual Studio 2026+ |

---

## Why MSBuild Guard?

MSBuild project files (`.csproj`, `.targets`, `.props`, `.sln`, etc.) are XML documents that can execute arbitrary shell commands, download files, and run code during a simple `dotnet restore` or solution load. Supply-chain attacks increasingly abuse this attack surface.

MSBuild Guard scans these files before execution and:

- Identifies imported files from untrusted or unexpected sources
- Flags NuGet packages that introduce `.targets` or `.props` files
- Highlights wildcard imports that could be hijacked
- Compares the current state against a trusted baseline
- Evaluates findings against a configurable policy
- Reports risk levels (None / Low / Medium / High / Critical)

---

## Solution Structure

```
MSBuildGuard.sln
├── MSBuildGuard.Core               # Shared scanning engine and models
├── MSBuildGuard.CLI                # Command-line interface
├── MSBuildGuard.ShellExtension     # Windows Explorer shell extension (COM, x64)
├── MSBuildGuard.ShellBroker        # Out-of-process broker for the shell extension
├── MSBuildGuard.ShellInstaller     # WiX installer for the shell extension
├── MSBuildGuard.VisualStudio       # Visual Studio 2026 extension (VSIX)
├── MSBuildGuard.Core.Tests
├── MSBuildGuard.CLI.Tests
└── MSBuildGuard.ShellBroker.Tests
```

---

## Modules

### MSBuildGuard.Core

The shared scanning engine used by all other modules. It provides:

- **MsBuildScanner** — recursively parses solution and project files, resolves imports and NuGet assets
- **NuGetLockFileParser / NuGetConfigurationParser / PackageAssetsFileParser** — parse NuGet lock files, `NuGet.Config`, and `project.assets.json`
- **PackageProvenanceResolver** — determines the origin and trust status of each package
- **PolicyService / PolicyDecisionEvaluator** — evaluates findings against a YAML policy file
- **BaselineService / BaselineComparer** — compares the current scan to a previously saved trusted baseline
- **TrustStoreService** — manages per-project trusted versions

**Target framework:** .NET 10 (Windows)

---

### MSBuildGuard.VisualStudio

A Visual Studio 2026 extension (VSIX) that provides integrated security review, policy editing, and build enforcement workflows.

Features:
- Automatic scan on solution open, NuGet restore, and package-change triggers
- Status bar shield icon (green / orange / red) reflecting the current risk level
- **Project Security Review** and **Solution Security Review** tool windows
- Scope-correct solution review filtering (All / per project) with target/risk/action summary updates
- Bottom **Reasoning** panel for selected findings in review windows
- Per-finding double-click navigation to source file and line
- **Policy Editor** with machine, solution, and project policy scope selection
- Automatic rescan and UI refresh after policy changes
- Build-time enforcement with user prompt (shows step/rule/risk, supports Continue or Cancel build)
- Security menu commands for solution review, project review, policy editing, and baseline creation
- Background monitoring with non-blocking UI feedback

**Target:** Visual Studio 2026 (Community, Professional, Enterprise) — amd64
**Target framework:** .NET Framework 4.7.2

---

## Building

### Prerequisites

- [Visual Studio 2026](https://visualstudio.microsoft.com/) with the **Visual Studio extension development** workload
- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [WiX Toolset v4](https://wixtoolset.org/) (for the installer project only)

### Build only the VSIX

```powershell
msbuild MSBuildGuard.VisualStudio\MSBuildGuard.VisualStudio.csproj /p:Configuration=Release
```

The `.vsix` file is emitted to `MSBuildGuard.VisualStudio\bin\Release\`.

### Run the tests

```powershell
dotnet test MSBuildGuard.sln --configuration Release
```

---

## CI / CD

The repository includes a GitHub Actions workflow (`.github/workflows/build-vsix.yml`) that:

1. Restores NuGet packages
2. Builds the VSIX in Release configuration
3. Uploads the `.vsix` as a build artifact

See [.github/workflows/build-vsix.yml](.github/workflows/build-vsix.yml) for details.

---

## Contributing

Contributions are welcome for non-commercial use cases. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `master`.
2. Follow the existing code style (C# 14, block-scoped namespaces, XML doc comments on all public/internal members).
3. Add or update unit tests for every changed or new class. Tests use **NUnit**, **Moq**, and **Shouldly**.
4. Ensure `msbuild MSBuildGuard.sln /p:Configuration=Release` succeeds with no warnings before opening a pull request.
5. Open a pull request with a clear description of the change and its motivation.

> By contributing you agree that your contribution is licensed under the same [PolyForm Noncommercial License 1.0.0](LICENSE) as the rest of the project.

---

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.
Commercial use requires a separate written agreement with the author.

See [LICENSE](LICENSE) for the full license text.

---

## Author

**Hefaistos68** — <https://github.com/Hefaistos68>

---

## Module documentation

Module-specific documentation is split into dedicated files:

- [Visual Studio extension documentation](documentation/VisualStudioExtension.md)

---

## Detection rules

The first implementation tracks the following rule IDs:

| Id | Rule | Default severity | Default action |
|---|---|---:|---|
| MBG000 | No issues detected | None | Trusted |
| MBG001 | `UsingTask` contains inline `Code` | Medium | Require approval |
| MBG002 | `TaskFactory="RoslynCodeTaskFactory"` or `CodeTaskFactory` | Medium | Require approval |
| MBG003 | `InitialTargets` present or changed from baseline | High | Require approval |
| MBG004 | Early lifecycle hooks (`BeforeBuild`, `PrepareForBuild`, `BeforeTargets` on early targets) | Medium | Warn |
| MBG005 | `Exec` invokes shell, PowerShell, script host, or command interpreter | High | Block unless approved by policy |
| MBG006 | Inline code references process creation APIs | High | Block unless approved by policy |
| MBG007 | Inline code references reflection, dynamic loading, or native interop | High | Require approval or block |
| MBG008 | Inline code contains large base64/byte arrays/encoded blobs | High | Block unless approved by policy |
| MBG009 | Import path resolves to user-writable, temporary, remote, or traversal path | High | Require approval |
| MBG010 | New `.props` or `.targets` appears compared with baseline | Medium | Require approval |
| MBG011 | Project/build file has Mark-of-the-Web | Medium | Require approval |
| MBG012 | Parse errors or unsupported constructs prevent full analysis | Medium | Warn or block in strict mode |

---

## Results model and interpretation

Scan output includes:

- Per-file findings with location and evidence
- Severity and confidence
- Suggested policy action
- Risk score and recommended action
- Baseline comparison context (new/changed/drifted findings)

### Risk score baseline values

- Info: `0`
- Low: `5`
- Medium: `20`
- High: `50`
- Critical: `100`

### Score modifiers

- `+30` if file has Mark-of-the-Web
- `+20` if finding appears in a file imported by multiple projects
- `+25` if finding is new versus baseline
- `-30` if finding fingerprint is explicitly approved in trust store
- `-20` if repository remote+commit match a trusted baseline state

### Recommended action thresholds

- `0-19`: Allow
- `20-49`: Warn
- `50-99`: RequireApproval
- `100+`: Block

---

## Policies, trust, and baselines

MSBuild Guard uses a layered governance model to keep decisions deterministic and auditable.

### Recommended paths

- Repository policy: `.msbuildguard/policy.json`
- Repository baseline: `.msbuildguard/baseline.json`
- User trust store: `%LOCALAPPDATA%/MSBuildGuard/trust.json`
- Machine policy: `%PROGRAMDATA%/MSBuildGuard/policy.json`

### Policy precedence

Effective policy merge order (highest priority first):

1. Machine policy
2. Repository policy
3. User settings
4. Built-in defaults

Lower layers cannot weaken stricter machine policy requirements.

### Policy details

Policy controls how findings are interpreted and enforced:

- `minimumActionBySeverity`: baseline action floor by severity
- `rules`: per-rule action overrides
- `baselineRequired`: require baseline to proceed
- `include` / `exclude`: path filtering
- `mode`: warn/block behavior in automation workflows

Example policy skeleton:

```json
{
  "version": 1,
  "mode": "block",
  "baselineRequired": true,
  "minimumActionBySeverity": {
    "Critical": "Block",
    "High": "Block",
    "Medium": "RequireApproval",
    "Low": "Warn",
    "Info": "Allow"
  },
  "rules": {
    "MBG005": { "action": "Block" }
  },
  "include": ["**/*.csproj", "**/*.targets"],
  "exclude": ["bin/**", "obj/**", ".git/**"]
}
```

### Baseline details

Baselines store an approved snapshot of normalized findings and file states for drift detection.

Use baselines to:

- Detect newly introduced risky behavior
- Separate known-approved legacy risk from new risk
- Gate CI and hooks on unapproved changes

Typical baseline workflow:

1. `msbuildguard baseline create . --output .msbuildguard/baseline.json`
2. Review and store baseline under source control policy
3. Compare with `msbuildguard baseline compare . --baseline .msbuildguard/baseline.json`
4. Update baseline only after explicit review/approval

### Trust details

Trust decisions allow approved exceptions without disabling rules globally.

Common trust scopes:

- `finding`: one fingerprinted finding
- `file`: specific file content hash
- `repo`: repository state

Trust decisions should include explicit reason text and are intended to be auditable.

Typical trust workflow:

1. Review finding evidence and source
2. Add trust decision: `msbuildguard trust add <subject> --scope finding --reason "Reviewed and approved"`
3. Re-run scan with `--trust` store configured
4. Re-evaluate trust when file content or dependency provenance changes

### End-to-end governance flow

1. Initialize policy: `msbuildguard policy init .`
2. Create baseline: `msbuildguard baseline create . --output .msbuildguard/baseline.json`
3. Run gated scan with policy+baseline+trust
4. Fail automation on blocking result or required approval state
5. Record trust decisions only for reviewed, justified exceptions

---

## CI usage

Typical CI invocation:

```text
msbuildguard scan . --format sarif --output artifacts/msbuildguard.sarif --policy .msbuildguard/policy.json --baseline .msbuildguard/baseline.json
```

Use command exit code to fail/pass pipeline gates.

## Notes

- For detailed command syntax and examples, use [CLI documentation](documentation/CLI.md).
- Explorer and Visual Studio workflows are documented in their dedicated module files.
