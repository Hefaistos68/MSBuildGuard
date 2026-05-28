# MSBuild Guard

**MSBuild Guard** is a security analysis tool for .NET projects that detects risky or untrusted MSBuild configurations — including imported `.targets`, `.props`, NuGet package assets, wildcard imports, and more — before they can execute arbitrary code on your machine.

It integrates into your workflow through three complementary surfaces:

| Module | Description |
|---|---|
| **Scanning Library** | .NET Standard 2.1 library for MSBuild analysis and policy evaluation |
| **Visual Studio Extension (VSIX)** | Inline security review panel inside Visual Studio 2026+ |
| **VScode Extension (VSIX)** | Inline security review panel inside VScode |

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
├── MSBuildGuard.Core.Tests         # Unit tests for the scanning engine
└── MSBuildGuard.VisualStudio       # Visual Studio 2026 extension (VSIX)
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

### Build the entire solution

```powershell
dotnet build MSBuildGuard-public.slnx -c Release
```

### Build only the VSIX

```powershell
dotnet build MSBuildGuard.VisualStudio\MSBuildGuard.VisualStudio.csproj -c Release
```

The `.vsix` file is emitted to `MSBuildGuard.VisualStudio\bin\Release\`.

### Run the tests

```powershell
dotnet test MSBuildGuard-public.slnx -c Release
```

---

## CI / CD

The repository includes a GitHub Actions workflow (`.github/workflows/build-vsix.yml`) that:

1. Restores NuGet packages
2. Builds the solution in Release configuration
3. Runs all tests
4. Uploads the `.vsix` as a build artifact

See [.github/workflows/build-vsix.yml](.github/workflows/build-vsix.yml) for details.

---

## Contributing

Contributions are welcome for non-commercial use cases. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `master`.
2. Follow the existing code style (C# 14, block-scoped namespaces, XML doc comments on all public/internal members).
3. Add or update unit tests for every changed or new class. Tests use **NUnit**, **Moq**, and **Shouldly**.
4. Ensure `dotnet build MSBuildGuard-public.slnx -c Release` succeeds with no warnings before opening a pull request.
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

## Detection Rules

MSBuild Guard currently detects the following risky patterns in MSBuild files:

| ID | Rule | Default Severity | Description |
|---|---|---|---|
| MBG000 | No issues detected | None | Clean scan result |
| MBG001 | `UsingTask` contains inline `Code` | Medium | Task executes inline C# code directly |
| MBG002 | `TaskFactory` using `RoslynCodeTaskFactory` or `CodeTaskFactory` | Medium | Task factory can dynamically compile and execute code |
| MBG003 | `InitialTargets` present or changed from baseline | High | Targets run before normal build pipeline; high code execution risk |
| MBG004 | Early lifecycle hooks (`BeforeBuild`, `PrepareForBuild`, `BeforeTargets` on early targets) | Medium | Code executes in early phases before user awareness |
| MBG005 | `Exec` task invokes shell, PowerShell, script host, or command interpreter | High | Direct shell/process invocation for arbitrary commands |
| MBG006 | Inline code references process creation APIs | High | Code can spawn child processes for command execution |
| MBG007 | Inline code references reflection, dynamic loading, or native interop | High | Code can load external assemblies or invoke native code |
| MBG008 | Inline code contains large base64/byte arrays/encoded blobs | High | Suspicious encoded payloads that may hide malicious logic |
| MBG009 | Import path resolves to user-writable, temporary, remote, or traversal path | High | Import target may be hijackable or from untrusted source |
| MBG010 | New `.props` or `.targets` file appears compared with baseline | Medium | New build configuration not previously approved |
| MBG011 | Project/build file has Mark-of-the-Web | Medium | File downloaded from internet and may have origin restrictions |
| MBG012 | Parse errors or unsupported constructs prevent full analysis | Medium | Incomplete scan; hidden logic may not be detected |

---

## Results Model and Interpretation

### Risk Scoring

Each finding is assigned a base score indicating its severity level:

| Level | Score |
|---|---|
| Info | 0 |
| Low | 5 |
| Medium | 20 |
| High | 50 |
| Critical | 100 |

### Score Modifiers

Base scores are adjusted by:

- **+30** — File has Mark-of-the-Web (downloaded from internet)
- **+20** — Finding appears in a file imported by multiple projects (wider blast radius)
- **+25** — Finding is new versus the trusted baseline (unapproved change)
- **−30** — Finding fingerprint is explicitly approved in the trust store
- **−20** — Repository remote and commit match a trusted baseline state

### Recommended Action Thresholds

Policy evaluator uses final score to determine action:

| Score Range | Recommended Action |
|---|---|
| 0–19 | **Allow** — permit build to continue |
| 20–49 | **Warn** — log warning, continue build |
| 50–99 | **Require Approval** — block until explicitly approved |
| 100+ | **Block** — prevent build/load |

---

## Policies, Trust, and Baselines

MSBuild Guard uses a layered governance model to keep decisions deterministic and auditable:

### Policy

Policy files control how findings are interpreted and enforced. They define:

- **Minimum action by severity** — floor action for each severity level (cannot be weakened by lower-priority policies)
- **Per-rule overrides** — custom action for specific rules (e.g., treat MBG005 as `Block` instead of `Warn`)
- **Mode** — behavior in automation (`warn` vs. `block` on violations)
- **Baseline requirement** — whether a trusted baseline must exist to proceed
- **Path filters** — `include` / `exclude` patterns to scope analysis

Example policy:

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
    "MBG005": { "action": "Block" },
    "MBG009": { "action": "RequireApproval" }
  },
  "include": ["**/*.csproj", "**/*.targets", "**/*.props"],
  "exclude": ["bin/**", "obj/**", ".git/**"]
}
```

### Baseline

Baselines record an approved snapshot of normalized findings and file states for drift detection. Use baselines to:

- Detect newly introduced risky behavior (score modifier +25)
- Separate known-approved legacy risk from new risk
- Gate CI/CD and pre-commit hooks on unapproved changes

Typical baseline workflow:

1. Create baseline after security review: `MSBuildGuardScanner.CreateBaseline(solution, output)`
2. Store baseline under source control policy (e.g., `.msbuildguard/baseline.json`)
3. Compare future scans: `MSBuildGuardScanner.CompareAgainstBaseline(solution, baseline)`
4. Update baseline only after explicit security review and approval

### Trust Store

Trust decisions allow approved exceptions without disabling rules globally.

Trust storage supports three scopes in Visual Studio:

- **User**: `%LOCALAPPDATA%\MSBuildGuard\trust.json`
- **Solution**: `<solution-dir>/.msbuildguard/trust.json`
- **Project**: `<project-dir>/.msbuildguard/trust.json`

When evaluating findings, MSBuild Guard merges trust decisions across these scopes.

#### Trust types and evaluation criteria

| Trust type | How it works | What is evaluated |
|---|---|---|
| **Issue** (finding-level trust) | Approves one specific finding instance. | Matches the finding `Fingerprint` exactly (case-insensitive), plus trust-context filters when present (repository remote, branch, commit SHA, policy profile), and requires a non-expired approving decision. The fingerprint is derived from `Rule ID` (issue type), file path, line/column, and evidence/description payload. |
| **Assembly** | Approves findings tied to one exact package/assembly version. | Matches `assemblyName@assemblyVersion` (for package findings this is `PackageId@PackageVersion`), case-insensitive, and requires a non-expired approving decision. Signer/issuer/subject fields are stored as metadata for audit context. |
| **Signature** (signer-level trust) | Approves findings for assemblies signed by a trusted certificate identity. | Matches a canonical signer key: certificate thumbprint when available; otherwise normalized `Subject|Issuer|SerialNumber`. In the Visual Studio workflow this is applied when a valid assembly signature can be resolved for the package and the signer identity matches a non-expired approving decision. |

Other supported scopes include **File** (normalized file hash) and **Repository/Baseline** (remote + commit, optional branch/profile constraints).

Trust decisions must include explicit reason text and are auditable. Trust entries can also be time-limited with a **valid-until** date (`ExpiresAtUtc`); expired entries are ignored during trust evaluation.

For team repositories, decide whether solution/project trust files should be committed. If not, add `**/.msbuildguard/trust.json` and `**/.msbuildguard/trust.json.audit.jsonl` to `.gitignore`.

```json
{
  "trustedFindings": [
    {
      "fingerprint": "...",
      "reason": "Reviewed by security team on 2024-01-15",
      "expiresAt": "2025-01-15"
    }
  ]
}
```

### Policy Precedence

Effective policy merge order (highest priority first):

1. **Machine policy** — `%PROGRAMDATA%\MSBuildGuard\policy.json`
2. **Solution policy** — `.msbuildguard\policy.json` in repository root
3. **User settings** — Visual Studio options or user config
4. **Built-in defaults** — safe, permissive baseline

Lower-priority layers cannot weaken stricter machine policy requirements.

### End-to-End Governance Flow

1. **Initialize policy** — set organization minimum actions and rule overrides
2. **Create baseline** — capture current approved state
3. **Configure trust store** — pre-approve known-safe findings
4. **Run gated scan** — evaluate against policy + baseline + trust
5. **Act on results** — block/warn/allow based on final score
6. **Update trust** — record justified exceptions with audit trail
7. **Baseline refresh** — update baseline only after explicit review

---

## Module documentation

Module-specific documentation is split into dedicated files:

- [Visual Studio extension documentation](documentation/VisualStudioExtension.md)


## Visual Studio Unified Settings Migration Guide
A complete blueprint for transitioning from legacy `DialogPage` options to modern Unified Settings in Visual Studio extensions.

[Read the guide](documentation/unified_settings_migration_guide.md)
