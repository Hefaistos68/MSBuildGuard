# MSBuild Guard VS Code Extension

MSBuild Guard for VS Code provides cross-platform inline project risk visibility, trust workflows, and build protection inside Visual Studio Code.

## Target

- VS Code version `^1.75.0` or higher
- Cross-platform support: Windows, macOS, and Linux
- Backend dependency: `.NET 8.0` or higher runtime (for background worker execution)

## Main features

- **Automatic scan on workspace open** and solution/project load
- **Automatic scan after NuGet restore** and package changes (via asset file watchers)
- **Activity Bar Shield Icon** and dedicated **Security Review** side panel dashboard
- **Interactive Security Review Dashboard** featuring:
  - Full findings list with severity filter count buttons (Critical, High, Medium, Low, Info)
  - Project filter dropdown with solution-correct summary metrics
  - Detailed **Reasoning** panel for selected finding context
  - Double-click navigating directly to source file and location
- **Tabs-based Policy Editor** document panel supporting:
  - Solution Policy, Project Policy, and Machine Policy scopes
  - Custom toggles for baseline requirements and strict analysis mode
  - Build-time action settings for incomplete analysis and unapproved package feeds
  - Enforcement action overrides styled dynamically with impact-based colors (Green for Allow, Yellow for Review, Blue for Warn, Red for Block)
- **Interactive Trust Store Manager** supporting:
  - Scope selectors for User, Solution, and Project levels
  - Detailed grid layouts to view, add, and remove trusted assemblies or certificate signers
- **Build Blocker / Build Enforcement Integration** that intercepts task execution and halts builds on policy failures
- **Explorer Context Menu Integration** allowing quick scans on solutions, projects, and target files
- **Secure background JSON IPC channel** using UTF-8 encoding streams for worker communications

## Security review workflow

1. Open a workspace folder containing a C# project or `.sln`/`.slnx` solution.
2. An automatic scan will run and populate the **Security Review** panel inside the MSBuild Guard view container.
3. Review the findings list, project metrics, and the detailed reasoning panel.
4. Click on findings or double-click to navigate directly to the risky line in the source editor.
5. In the reasoning panel, click **🛡️ Trust Finding**, **📦 Trust NuGet Assembly**, or **✍️ Trust Signer Certificate** to add exception rules directly to your trust stores.
6. Open the **Policy Editor** via command or the dashboard action button, configure policies, and save.
7. The extension will automatically rescan the workspace and refresh the dashboard UI.

## Baseline workflow in VS Code

- **Dynamic Visibility & Safety**:
  - The **Create Baseline** button is dynamically visible on the Security Review dashboard **only when the current recommended action is Safe (Allow) or Warn**.
  - If the project status is **Block** or **Require Approval**, the baseline button is completely hidden from the panel. Attempting to trigger baseline creation via the Command Palette in these states will show an error message: *"Cannot create baseline while project is in blocked or require-approval state."* This prevents baseline-approving active security issues without prior review.
- **How to Create a Baseline**:
  - **Option 1 (Review Dashboard)**: Run a quick scan. If the status is safe/warn, click the **Create Baseline** button located underneath the Scan button. Specify or confirm the output path in the input box (defaults to `.msbuildguard/baseline.json` in your workspace root) and press Enter to save.
  - **Option 2 (Command Palette)**: Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`), run **`MSBuild Guard: Create Baseline`**, and confirm the baseline destination path.
- **Rescanning on Creation**: Upon successful creation, the extension will automatically rescan the workspace to apply the baseline, which immediately hides baseline-matching findings and establishes a trusted baseline state.
- **Confirmation Overwrites**: If a baseline already exists at the target location, the extension will prompt you to confirm before overwriting the existing baseline record.

## Trusted Baseline Onboarding

When you open a workspace containing a solution that has never been scanned by MSBuild Guard before (no `.msbuildguard/trust.json` and no `.msbuildguard/baseline.json` files present), MSBuild Guard will launch a beautiful **Trusted Baseline Onboarding** dashboard to guide you through establishing a clean security baseline:
- **Intelligent Trust Suggestions**: MSBuild Guard scans the solution and suggests pre-approving high-reputation NuGet packages (verified on NuGet.org or signed by Microsoft) and valid Authenticode-signed assemblies.
- **Opt-in Review for Unverified Code**: If packages do not have a verified publisher or a valid signature, they are displayed as **unselected** suggestions. This alerts you to review them manually instead of silently ignoring them or auto-trusting unverified dependencies.
- **Setup Actions**:
  - **Apply Setup**: Approves the selected packages/signers/assemblies in the solution's `trust.json` store.
  - **Create baseline for remaining findings**: Automatically saves any unchecked issues into a baseline file so that they don't block subsequent builds, keeping active development clean.
  - **Do not scan again**: Writes a `.msbuildguard/noscan` marker that completely bypasses scanning for this workspace on future loads.
  - **Skip**: Closes the wizard. If "Don't show again" is toggled, it creates an empty `trust.json` store to mark the solution as "seen" so you won't be prompted again.

## Integration model

The extension spawns `MSBuildGuard.Worker.dll` as a persistent background worker process and communicates with it using a JSON-RPC channel via standard input/output streams. The scanner parses and evaluates build assets, MSBuild logic, and certificate signatures directly to protect code *before* a full compilation or project evaluation is executed.

## How it works

1. The extension scans active workspace build configurations using the background worker.
2. The worker evaluates the target files, imported target libraries, NuGet asset paths, and certificate chains against the active policy.
3. Trust records are loaded from the user, solution, and project trust stores and matched against findings.
4. Validated assembly and signer-certificate exceptions automatically mark corresponding findings as trusted.
5. The webview parses the scan report and dynamically escapes HTML/XML payloads to render full, safe code snippets inside the Evidence panel.
6. The Build Enforcer intercepts VS Code task builds and blocks compilation if untrusted build failures violate the active enforcement policy.

## UX surfaces

- **MSBuild Guard Activity Bar View Container** (`resources/shield-icon.svg`)
- **Security Review Side Panel Webview** (Findings lists, filters, reasoning, and trust actions)
- **Policy Editor Document Tab** (Solution, Project, and Machine policy tabs with impact-colored selectors)
- **Trust Store Manager Webview** (User, Solution, and Project trust grid management)
- **Explorer Context Menus** (Context actions on `.sln`, `.slnx`, `.csproj`, `.targets`, etc.)
- **Interactive Blocker Alerts** (VS Code build notification warnings and modal dialog blocks)

## VS Code configuration settings

The extension contributes several workspace and global configurations accessible via `File` → `Preferences` → `Settings` (under the `MSBuild Guard` section):

- **Enable Baseline Onboarding** (`msbuildguard.enableBaselineOnboarding`):
  - *Default*: `true`
  - *Description*: Intelligently suggests baseline trust settings when loading a new workspace for the first time.
- **Auto-open Security Review** (`msbuildguard.autoOpenSecurityReview`):
  - *Default*: `true`
  - *Description*: Automatically opens the Security Review pane when a scan requires user attention.
- **Only Untrusted Issues** (`msbuildguard.onlyUntrustedIssues`):
  - *Default*: `false`
  - *Description*: Filters the Security Review dashboard to only show active, untrusted findings.
- **Scan NuGet Packages** (`msbuildguard.scanNuGetPackages`):
  - *Default*: `true`
  - *Description*: Enables NuGet package asset file watchers and restore-triggered workspace rescans.
- **File Types to Scan** (`msbuildguard.fileTypesToScan`):
  - *Default*: `.csproj;.vbproj;.fsproj;.proj;.props;.targets;.sln;.slnx`
  - *Description*: Semicolon-separated list of build and project file extensions to target in scans.
- **Process Creation Indicators** (`msbuildguard.processCreationIndicators`):
  - *Default*: `System.Diagnostics.Process;Process.Start(;CreateProcess(;cmd.exe;powershell;pwsh`
  - *Description*: Semicolon-separated list of risky process creation API indicators.
- **Reflection/Interop Indicators** (`msbuildguard.reflectionInteropIndicators`):
  - *Default*: `System.Reflection;Assembly.Load;Activator.CreateInstance;GetType(;dynamic ;DllImport;Marshal.GetDelegateForFunctionPointer;LoadLibrary`
  - *Description*: Semicolon-separated list of reflection, dynamic loading, and native interop indicators.
- **Additional Blocked Assemblies** (`msbuildguard.additionalBlockedAssemblies`):
  - *Default*: empty string
  - *Description*: Semicolon-separated list of NuGet package assembly names that should be explicitly blocked.

## Trust management and scope settings

The **Trust Store Manager** allows detailed configuration of trusted items at three scoped locations:

1. **User Store (Global)**:
   - Configured globally for the user's profile directory. Useful for developer-wide certificate signers and trusted core tooling.
2. **Solution Store (.msbuildguard/trust.json)**:
   - Saved at the root of the solution workspace. These trusts can be committed and shared with other developers on the team.
3. **Project Store (.msbuildguard/trust.json)**:
   - Nested inside specific projects. Restricts trust scopes strictly to the project context.

### Add & Remove Trusts
- Click **Manage Trusts** to review active trust scopes.
- Search, filter, or remove version-pinned assembly trust entries or trusted certificate subjects.
- Add new trust exceptions dynamically directly from findings details in the **Security Review** sidebar panel.

## Notes

VS Code build enforcement relies on task hook interception and background worker analysis.

## Screenshots

![VS Code Trust Store Manager](/documentation/images/vscode-manage-signer-trusts.jpg)

![VS Code Security Review Panel](/documentation/images/vscode-security-review.jpg)

![VS Code Policy Editor](/documentation/images/vscode-policy-editor.jpg)

## Packaging the VSIX

```shell
npx @vscode/vsce package --pre-release
```
