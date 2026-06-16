import * as path from 'path';
import * as fs from 'fs';
import * as vscode from 'vscode';
import { WorkerClient, ScanReport } from './services/workerClient';
import { DiagnosticPublisher } from './services/diagnosticPublisher';
import { BuildEnforcer } from './services/buildEnforcer';
import { SecurityReviewViewProvider } from './views/securityReviewView';
import { PolicyEditorPanel } from './views/policyEditorView';
import { TrustStorePanel } from './views/trustStoreView';
import { OnboardingPanel } from './views/onboardingView';

let workerClient: WorkerClient | null = null;
let diagnosticPublisher: DiagnosticPublisher | null = null;
let buildEnforcer: BuildEnforcer | null = null;
let statusBarItem: vscode.StatusBarItem | null = null;
let outputChannel: vscode.OutputChannel | null = null;

let latestReport: ScanReport | null = null;
let activeReviewProvider: any = null; // Will be set once review view provider is registered
let extensionContext: vscode.ExtensionContext | null = null;
const promptedSolutions = new Set<string>();

export function activate(context: vscode.ExtensionContext) {
    extensionContext = context;
    outputChannel = vscode.window.createOutputChannel('MSBuild Guard Log');
    outputChannel.appendLine('MSBuild Guard extension activating...');

    // Initialize Worker process client
    try {
        workerClient = new WorkerClient(context);
        outputChannel.appendLine('MSBuild Guard C# background worker spawned.');
    } catch (err: any) {
        outputChannel.appendLine(`Failed to launch background worker: ${err.message}`);
        void vscode.window.showErrorMessage(`MSBuild Guard failed to activate background worker: ${err.message}`);
        return;
    }

    // Initialize Service Layers
    diagnosticPublisher = new DiagnosticPublisher();
    buildEnforcer = new BuildEnforcer();

    context.subscriptions.push(workerClient);
    context.subscriptions.push(diagnosticPublisher);
    context.subscriptions.push(buildEnforcer);

    // Register Webview Dashboard Provider
    const reviewProvider = new SecurityReviewViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(SecurityReviewViewProvider.viewType, reviewProvider)
    );

    // Create dynamic Status Bar Shield
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'msbuildguard.showReview';
    statusBarItem.text = '$(shield) MSBuild Guard: Idle';
    statusBarItem.tooltip = 'MSBuild Guard: Click to open Security Review Dashboard';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.scan', async (uri?: vscode.Uri) => {
            await runScan(uri);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.showReview', () => {
            void vscode.commands.executeCommand('workbench.view.extension.msbuildguard-container');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.createBaseline', async () => {
            await createBaseline();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.editPolicy', async () => {
            await editPolicy();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.manageAssemblyTrusts', async () => {
            await manageTrusts('Solution');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.manageSignerTrusts', async () => {
            await manageTrusts('Solution');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.removeAllSolutionTrusts', async () => {
            await removeAllSolutionTrusts();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.removeAllProjectTrusts', async () => {
            await removeAllProjectTrusts();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('msbuildguard.removeAllUserTrusts', async () => {
            await removeAllUserTrusts();
        })
    );

    const config = vscode.workspace.getConfiguration('msbuildguard');
    const currentEnforce = config.get<boolean>('enforceAsymmetricSignatures', false);
    void context.globalState.update('lastEnforceAsymmetricSignatures', currentEnforce);

    const keyMode = config.get<string>('trustManagement.keyManagementMode', 'unconfigured');
    if (keyMode === 'unconfigured') {
        void showFirstRunQuickPick(config);
    }

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async (e) => {
            if (e.affectsConfiguration('msbuildguard.enforceAsymmetricSignatures')) {
                const conf = vscode.workspace.getConfiguration('msbuildguard');
                const newValue = conf.get<boolean>('enforceAsymmetricSignatures', false);
                const oldValue = context.globalState.get<boolean>('lastEnforceAsymmetricSignatures', false);
                
                if (oldValue === true && newValue === false) {
                    const confirm = await vscode.window.showWarningMessage(
                        "Downgrading security settings: Disabling strict asymmetric signatures will permanently delete all local user, solution, and project trust files. Do you want to proceed?",
                        { modal: true },
                        "Yes",
                        "No"
                    );

                    if (confirm === "Yes") {
                        await purgeAllTrusts(context);
                        restartWorkerClient();
                        void runScan();
                    } else {
                        await conf.update('enforceAsymmetricSignatures', true, vscode.ConfigurationTarget.Global);
                    }
                } else {
                    restartWorkerClient();
                    void runScan();
                }
                await context.globalState.update('lastEnforceAsymmetricSignatures', newValue);
            } else if (e.affectsConfiguration('msbuildguard.trustManagement.allowSharingTrustsInRepositories')) {
                const conf = vscode.workspace.getConfiguration('msbuildguard');
                const allowSharing = conf.get<boolean>('trustManagement.allowSharingTrustsInRepositories', false);
                const mode = conf.get<string>('trustManagement.keyManagementMode', 'unconfigured');
                if (allowSharing && mode === 'dpapi') {
                    void vscode.window.showWarningMessage("Cannot enable repository trust sharing while key management is set to Solo Developer (Local DPAPI).");
                    await conf.update('trustManagement.allowSharingTrustsInRepositories', false, vscode.ConfigurationTarget.Global);
                } else {
                    restartWorkerClient();
                    void runScan();
                }
            } else if (e.affectsConfiguration('msbuildguard.trustManagement.keyManagementMode')) {
                const conf = vscode.workspace.getConfiguration('msbuildguard');
                const mode = conf.get<string>('trustManagement.keyManagementMode', 'unconfigured');
                if (mode === 'dpapi') {
                    const allowSharing = conf.get<boolean>('trustManagement.allowSharingTrustsInRepositories', false);
                    if (allowSharing) {
                        void vscode.window.showWarningMessage("In Solo Developer (Local DPAPI) mode, sharing trusts in repositories is not supported. Disabling repository trust sharing.");
                        await conf.update('trustManagement.allowSharingTrustsInRepositories', false, vscode.ConfigurationTarget.Global);
                    }
                }
                restartWorkerClient();
                void runScan();
            }
        })
    );

    // Watchers for NuGet restores and Policy modifications
    setupFileSystemWatchers(context);

    // Trigger initial scan if a workspace is loaded
    void triggerAutoScan();

    outputChannel.appendLine('MSBuild Guard activated successfully.');
}

export function deactivate() {
    if (workerClient) {
        workerClient.dispose();
    }
    if (diagnosticPublisher) {
        diagnosticPublisher.dispose();
    }
    if (buildEnforcer) {
        buildEnforcer.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}

/**
 * Executes a security review scan.
 */
async function runScan(targetUri?: vscode.Uri): Promise<void> {
    if (!workerClient || !outputChannel) {
        return;
    }

    let targetPath = '';

    if (targetUri) {
        targetPath = targetUri.fsPath;
    } else {
        targetPath = await resolveActiveScanTarget();
    }

    if (!targetPath) {
        void vscode.window.showWarningMessage('No active .NET Solution or Project found in workspace to scan.');
        return;
    }

    outputChannel.appendLine(`Starting scan on: ${targetPath}`);
    updateStatusBarState('scanning');

    try {
        const config = vscode.workspace.getConfiguration('msbuildguard');
        const options = {
            fileTypesToScan: config.get<string>('fileTypesToScan', '').split(';').filter(Boolean),
            processCreationIndicators: config.get<string>('processCreationIndicators', '').split(';').filter(Boolean),
            reflectionInteropIndicators: config.get<string>('reflectionInteropIndicators', '').split(';').filter(Boolean),
            additionalBlockedAssemblies: config.get<string>('additionalBlockedAssemblies', '').split(';').filter(Boolean),
        };

        const report = await workerClient.scanAsync(targetPath, options);
        latestReport = report;

        const isSolution = report.target.targetKind.toLowerCase() === 'solution';
        const enableOnboarding = config.get<boolean>('enableBaselineOnboarding', true);

        if (isSolution && enableOnboarding && !promptedSolutions.has(targetPath) && extensionContext) {
            const solutionDir = path.dirname(targetPath);
            const trustPath = path.join(solutionDir, '.msbuildguard', 'trust.json');
            const baselinePath = path.join(solutionDir, '.msbuildguard', 'baseline.json');

            if (!fs.existsSync(trustPath) && !fs.existsSync(baselinePath)) {
                promptedSolutions.add(targetPath);
                outputChannel.appendLine(`Triggering Trusted Baseline Onboarding for: ${targetPath}`);
                OnboardingPanel.createOrShow(extensionContext.extensionUri, workerClient, targetPath, options, report);
                updateStatusBarState('idle');
                return;
            }
        }

        outputChannel.appendLine(`Scan completed: ${report.findings.length} findings identified.`);
        
        // Publish squiggles
        if (diagnosticPublisher) {
            diagnosticPublisher.publish(report);
        }

        // Feed to build enforcer
        if (buildEnforcer) {
            buildEnforcer.updateReport(report);
        }

        // Refresh Status Bar Shield
        updateStatusBarState('idle', report);

        // Refresh Webview View if open
        if (activeReviewProvider && activeReviewProvider.refresh) {
            activeReviewProvider.refresh(report);
        }

        // Auto-open Webview View on risk detection
        const hasRisks = report.recommendedAction.toLowerCase() === 'block' || report.recommendedAction.toLowerCase() === 'requireapproval';
        const autoOpen = config.get<boolean>('autoOpenSecurityReview', true);

        if (hasRisks && autoOpen) {
            void vscode.commands.executeCommand('msbuildguard.showReview');
        }

    } catch (err: any) {
        outputChannel.appendLine(`Scan failed: ${err.message}`);
        updateStatusBarState('error');
        void vscode.window.showErrorMessage(`MSBuild Guard scan failed: ${err.message}`);
    }
}

/**
 * Creates a trusted baseline.
 */
async function createBaseline(): Promise<void> {
    if (!workerClient || !outputChannel || !latestReport) {
        void vscode.window.showWarningMessage('Please run a Scan first before creating a baseline.');
        return;
    }

    const action = latestReport.recommendedAction.toLowerCase();
    if (action === 'block' || action === 'requireapproval') {
        void vscode.window.showErrorMessage('Cannot create baseline while project is in blocked or require-approval state.');
        return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return;
    }

    const defaultBaselineDir = path.join(workspaceFolders[0].uri.fsPath, '.msbuildguard');
    const defaultPath = path.join(defaultBaselineDir, 'baseline.json');

    const confirmed = await vscode.window.showInputBox({
        title: 'Create Baseline',
        prompt: 'Specify the path to save the baseline file',
        value: defaultPath
    });

    if (!confirmed) {
        return;
    }

    const targetPath = latestReport.target.targetPath;
    const reviewer = process.env.USERNAME || process.env.USER || 'VSCodeUser';

    outputChannel.appendLine(`Creating baseline for ${targetPath} to ${confirmed}`);

    try {
        const config = vscode.workspace.getConfiguration('msbuildguard');
        const options = {
            fileTypesToScan: config.get<string>('fileTypesToScan', '').split(';').filter(Boolean),
            processCreationIndicators: config.get<string>('processCreationIndicators', '').split(';').filter(Boolean),
            reflectionInteropIndicators: config.get<string>('reflectionInteropIndicators', '').split(';').filter(Boolean),
            additionalBlockedAssemblies: config.get<string>('additionalBlockedAssemblies', '').split(';').filter(Boolean),
        };

        await workerClient.createBaselineAsync(targetPath, reviewer, confirmed);
        void vscode.window.showInformationMessage(`Trusted baseline successfully saved to: ${confirmed}`);
        outputChannel.appendLine(`Baseline successfully created.`);

        // Rescan to apply the baseline
        await runScan();

    } catch (err: any) {
        outputChannel.appendLine(`Create baseline failed: ${err.message}`);
        void vscode.window.showErrorMessage(`Failed to create baseline: ${err.message}`);
    }
}

/**
 * Sets up filesystem watchers for nuget restore and policy modifications.
 */
function setupFileSystemWatchers(context: vscode.ExtensionContext): void {
    const config = vscode.workspace.getConfiguration('msbuildguard');
    if (!config.get<boolean>('scanNuGetPackages', true)) {
        return;
    }

    // Watch project.assets.json to trigger automatic scans after package restore
    const restoreWatcher = vscode.workspace.createFileSystemWatcher('**/obj/project.assets.json');
    restoreWatcher.onDidChange(() => triggerDelayedScan());
    restoreWatcher.onDidCreate(() => triggerDelayedScan());
    context.subscriptions.push(restoreWatcher);

    // Watch policy.json to trigger automatic scans after policy configurations change
    const policyWatcher = vscode.workspace.createFileSystemWatcher('**/.msbuildguard/policy.json');
    policyWatcher.onDidChange(() => triggerDelayedScan());
    policyWatcher.onDidCreate(() => triggerDelayedScan());
    policyWatcher.onDidDelete(() => triggerDelayedScan());
    context.subscriptions.push(policyWatcher);
}

let scanTimeout: NodeJS.Timeout | null = null;
function triggerDelayedScan(): void {
    if (scanTimeout) {
        clearTimeout(scanTimeout);
    }
    scanTimeout = setTimeout(() => {
        void runScan();
    }, 1500);
}

/**
 * Resolves the primary solution or project file inside active workspace folders.
 */
async function resolveActiveScanTarget(): Promise<string> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return '';
    }

    const rootPath = workspaceFolders[0].uri.fsPath;

    // Search for .slnx or .sln first
    const slnxFiles = await vscode.workspace.findFiles('*.slnx', undefined, 1);
    if (slnxFiles.length > 0) {
        return slnxFiles[0].fsPath;
    }

    const slnFiles = await vscode.workspace.findFiles('*.sln', undefined, 1);
    if (slnFiles.length > 0) {
        return slnFiles[0].fsPath;
    }

    // Fall back to first available csproj
    const csprojFiles = await vscode.workspace.findFiles('**/*.csproj', '**/node_modules/**', 1);
    if (csprojFiles.length > 0) {
        return csprojFiles[0].fsPath;
    }

    return '';
}

async function triggerAutoScan(): Promise<void> {
    const target = await resolveActiveScanTarget();
    if (target) {
        await runScan();
    }
}

/**
 * Updates the Status Bar Shield icon, color, and tooltip details.
 */
function updateStatusBarState(state: 'scanning' | 'error' | 'idle', report?: ScanReport): void {
    if (!statusBarItem) {
        return;
    }

    if (state === 'scanning') {
        statusBarItem.text = '$(sync~spin) MSBuild Guard: Scanning...';
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = 'MSBuild Guard: Actively scanning solution files...';
        return;
    }

    if (state === 'error') {
        statusBarItem.text = '$(shield) MSBuild Guard: Scan Error';
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        statusBarItem.tooltip = 'MSBuild Guard: Last analysis failed to complete.';
        return;
    }

    if (!report) {
        statusBarItem.text = '$(shield) MSBuild Guard: Idle';
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = 'MSBuild Guard: System idle. Ready to analyze build files.';
        return;
    }

    const action = report.recommendedAction.toLowerCase();
    const score = report.riskScore;

    if (action === 'block') {
        statusBarItem.text = `$(shield) MSBuild Guard: Blocked (${score})`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        statusBarItem.tooltip = `MSBuild Guard: Blocker! Security policy prevents building (Risk Score: ${score}).`;
    } else if (action === 'requireapproval') {
        statusBarItem.text = `$(shield) MSBuild Guard: Suspicious (${score})`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        statusBarItem.tooltip = `MSBuild Guard: Risky! Requires manual review/approval before building (Risk Score: ${score}).`;
    } else if (action === 'warn') {
        statusBarItem.text = `$(shield) MSBuild Guard: Warning (${score})`;
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = `MSBuild Guard: Low security warning. Proceed with caution (Risk Score: ${score}).`;
    } else {
        statusBarItem.text = `$(shield) MSBuild Guard: Safe (${score})`;
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = `MSBuild Guard: Active solution is clean and trusted (Risk Score: ${score}).`;
    }
}

/**
 * Attaches the Webview View Provider so extension commands can interact with it.
 */
export function setGlobalReviewProvider(provider: any): void {
    activeReviewProvider = provider;
    if (latestReport) {
        provider.refresh(latestReport);
    }
}

/**
 * Gets the active C# background worker client instance.
 */
export function getWorkerClient(): WorkerClient | null {
    return workerClient;
}

/**
 * Visual Policy Editor: Opens the workspace policy settings in a highly interactive visual panel.
 */
async function editPolicy(): Promise<void> {
    if (!workerClient) {
        return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        void vscode.window.showWarningMessage('No active workspace folders loaded.');
        return;
    }

    const solutionPath = await resolveActiveScanTarget();
    if (!solutionPath) {
        void vscode.window.showWarningMessage('No active solution or project found to configure policy.');
        return;
    }

    const projectFiles = await vscode.workspace.findFiles('**/*.{csproj,fsproj,vbproj}', '**/node_modules/**');
    const projectPaths = projectFiles.map(f => f.fsPath);

    PolicyEditorPanel.createOrShow(
        contextUriResolver(workspaceFolders[0]),
        workerClient,
        solutionPath,
        projectPaths
    );
}

/**
 * Helper to resolve the correct Uri context.
 */
function contextUriResolver(folder: vscode.WorkspaceFolder): vscode.Uri {
    return folder.uri;
}

/**
 * Visual Trust Store Manager: Opens the workspace trust settings in a highly interactive visual panel.
 */
async function manageTrusts(initialScope: 'User' | 'Solution' | 'Project' = 'User'): Promise<void> {
    if (!workerClient) {
        return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        void vscode.window.showWarningMessage('No active workspace folders loaded.');
        return;
    }

    const solutionPath = await resolveActiveScanTarget();
    if (!solutionPath) {
        void vscode.window.showWarningMessage('No active solution or project found to manage trusts.');
        return;
    }

    const projectFiles = await vscode.workspace.findFiles('**/*.{csproj,fsproj,vbproj}', '**/node_modules/**');
    const projectPaths = projectFiles.map(f => f.fsPath);

    TrustStorePanel.createOrShow(
        contextUriResolver(workspaceFolders[0]),
        workerClient,
        solutionPath,
        projectPaths,
        initialScope
    );
}

// Security Hardening Helper functions

function getUserTrustPath(): string {
    const localAppData = process.env.LOCALAPPDATA || 
        (process.platform === 'darwin' ? path.join(process.env.HOME || '', 'Library', 'Caches') : path.join(process.env.HOME || '', '.local', 'share'));
    return path.join(localAppData, 'MSBuildGuard', 'trust.json');
}

function getRecentWorkspaces(): string[] {
    const paths: string[] = [];
    try {
        const appData = process.env.APPDATA || 
            (process.platform === 'darwin' ? path.join(process.env.HOME || '', 'Library', 'Application Support') : path.join(process.env.HOME || '', '.config'));
        const channelDirs = ['Code', 'Code - Insiders', 'VSCodium'];
        for (const dir of channelDirs) {
            const storagePath = path.join(appData, dir, 'User', 'globalStorage', 'storage.json');
            if (fs.existsSync(storagePath)) {
                const content = fs.readFileSync(storagePath, 'utf8');
                const data = JSON.parse(content);
                if (data.openedPathsList && Array.isArray(data.openedPathsList.entries)) {
                    for (const entry of data.openedPathsList.entries) {
                        if (entry.folderUri) {
                            try {
                                const uriPath = vscode.Uri.parse(entry.folderUri).fsPath;
                                if (uriPath) {
                                    paths.push(uriPath);
                                }
                            } catch {}
                        } else if (entry.workspace && entry.workspace.configPath) {
                            try {
                                const uriPath = vscode.Uri.parse(entry.workspace.configPath).fsPath;
                                const folder = path.dirname(uriPath);
                                paths.push(folder);
                            } catch {}
                        }
                    }
                }
            }
        }
    } catch (e) {
    }
    return paths;
}

function purgeTrustFilesInDir(dir: string, depth: number = 0): void {
    if (depth > 5) {
        return;
    }
    try {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            if (file === '.msbuildguard') {
                const trustFile = path.join(fullPath, 'trust.json');
                if (fs.existsSync(trustFile)) {
                    try {
                        fs.unlinkSync(trustFile);
                        outputChannel?.appendLine(`Deleted trust store: ${trustFile}`);
                        const sigFile = trustFile + '.signature';
                        if (fs.existsSync(sigFile)) {
                            fs.unlinkSync(sigFile);
                            outputChannel?.appendLine(`Deleted signature companion: ${sigFile}`);
                        }
                    } catch (e: any) {
                        outputChannel?.appendLine(`Failed to delete ${trustFile}: ${e.message}`);
                    }
                }
            } else {
                try {
                    const stat = fs.statSync(fullPath);
                    if (stat.isDirectory()) {
                        if (file !== 'node_modules' && file !== '.git' && file !== 'bin' && file !== 'obj') {
                            purgeTrustFilesInDir(fullPath, depth + 1);
                        }
                    }
                } catch (e) {}
            }
        }
    } catch (e) {}
}

async function purgeAllTrusts(context: vscode.ExtensionContext): Promise<void> {
    outputChannel?.appendLine('Purging all trust stores due to enforceAsymmetricSignatures downgrade...');
    
    // 1. Delete user-level trust store
    const userPath = getUserTrustPath();
    if (fs.existsSync(userPath)) {
        try {
            fs.unlinkSync(userPath);
            outputChannel?.appendLine(`Deleted user trust store: ${userPath}`);
            const sigPath = userPath + '.signature';
            if (fs.existsSync(sigPath)) {
                fs.unlinkSync(sigPath);
                outputChannel?.appendLine(`Deleted user trust signature: ${sigPath}`);
            }
        } catch (e: any) {
            outputChannel?.appendLine(`Failed to delete user trust store: ${e.message}`);
        }
    }

    // 2. Scan recent and open workspace folders to delete .msbuildguard/trust.json
    const foldersToScan = new Set<string>();
    
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
        for (const folder of workspaceFolders) {
            foldersToScan.add(folder.uri.fsPath);
        }
    }

    const recent = getRecentWorkspaces();
    for (const folder of recent) {
        foldersToScan.add(folder);
    }

    for (const folder of foldersToScan) {
        if (fs.existsSync(folder)) {
            try {
                purgeTrustFilesInDir(folder);
            } catch (e: any) {
                outputChannel?.appendLine(`Failed to purge trusts in folder ${folder}: ${e.message}`);
            }
        }
    }
    
    void vscode.window.showInformationMessage("All local, solution, and project trust stores have been successfully purged.");
}

function restartWorkerClient(): void {
    if (workerClient) {
        workerClient.dispose();
    }
    if (extensionContext) {
        try {
            workerClient = new WorkerClient(extensionContext);
            outputChannel?.appendLine('MSBuild Guard C# background worker restarted.');
        } catch (err: any) {
            outputChannel?.appendLine(`Failed to launch background worker: ${err.message}`);
            void vscode.window.showErrorMessage(`MSBuild Guard failed to activate background worker: ${err.message}`);
        }
    }
}

async function showFirstRunQuickPick(config: vscode.WorkspaceConfiguration): Promise<void> {
    const selected = await vscode.window.showQuickPick([
        { label: "Solo Developer (Local DPAPI)", description: "Keys are unique to this machine, secured via DPAPI. Sharing trusts in repositories is disabled.", value: "dpapi" },
        { label: "Team Environment (Asymmetric Certificates)", description: "Enables sharing signed trusts. Requires public validation certificates.", value: "certificates" }
    ], {
        placeHolder: "MSBuild Guard: Choose Key Management Mode",
        ignoreFocusOut: true
    });

    if (selected) {
        await config.update('trustManagement.keyManagementMode', selected.value, vscode.ConfigurationTarget.Global);
        if (selected.value === 'dpapi') {
            await config.update('trustManagement.allowSharingTrustsInRepositories', false, vscode.ConfigurationTarget.Global);
        }
    }
}

async function removeAllSolutionTrusts(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        void vscode.window.showWarningMessage('No active workspace folders loaded.');
        return;
    }

    const confirm = await vscode.window.showWarningMessage(
        "Are you sure you want to permanently remove all solution-level trusts for this workspace?",
        { modal: true },
        "Yes",
        "No"
    );

    if (confirm !== "Yes") {
        return;
    }

    const solutionTrustPath = path.join(workspaceFolders[0].uri.fsPath, '.msbuildguard', 'trust.json');
    if (fs.existsSync(solutionTrustPath)) {
        try {
            fs.unlinkSync(solutionTrustPath);
            outputChannel?.appendLine(`Deleted solution trust file: ${solutionTrustPath}`);
            const sigPath = solutionTrustPath + '.signature';
            if (fs.existsSync(sigPath)) {
                fs.unlinkSync(sigPath);
                outputChannel?.appendLine(`Deleted solution trust signature: ${sigPath}`);
            }
            void vscode.window.showInformationMessage("Solution trusts successfully removed.");
            restartWorkerClient();
            void runScan();
        } catch (e: any) {
            void vscode.window.showErrorMessage(`Failed to remove solution trusts: ${e.message}`);
        }
    } else {
        void vscode.window.showInformationMessage("No solution trust file found to remove.");
    }
}

async function removeAllUserTrusts(): Promise<void> {
    const confirm = await vscode.window.showWarningMessage(
        "Are you sure you want to permanently remove all user-level trusts?",
        { modal: true },
        "Yes",
        "No"
    );

    if (confirm !== "Yes") {
        return;
    }

    const userPath = getUserTrustPath();
    if (fs.existsSync(userPath)) {
        try {
            fs.unlinkSync(userPath);
            outputChannel?.appendLine(`Deleted user trust store: ${userPath}`);
            const sigPath = userPath + '.signature';
            if (fs.existsSync(sigPath)) {
                fs.unlinkSync(sigPath);
                outputChannel?.appendLine(`Deleted user trust signature: ${sigPath}`);
            }
            void vscode.window.showInformationMessage("User-level trusts successfully removed.");
            restartWorkerClient();
            void runScan();
        } catch (e: any) {
            void vscode.window.showErrorMessage(`Failed to remove user trusts: ${e.message}`);
        }
    } else {
        void vscode.window.showInformationMessage("No user trust file found to remove.");
    }
}

async function removeAllProjectTrusts(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        void vscode.window.showWarningMessage('No active workspace folders loaded.');
        return;
    }

    const confirm = await vscode.window.showWarningMessage(
        "Are you sure you want to permanently remove all project-level trusts for this workspace?",
        { modal: true },
        "Yes",
        "No"
    );

    if (confirm !== "Yes") {
        return;
    }

    const rootDir = workspaceFolders[0].uri.fsPath;
    let deletedCount = 0;

    function purgeProjectTrusts(dir: string, depth: number = 0): void {
        if (depth > 5) {
            return;
        }
        try {
            const files = fs.readdirSync(dir);
            for (const file of files) {
                const fullPath = path.join(dir, file);
                if (file === '.msbuildguard') {
                    if (path.resolve(dir) === path.resolve(rootDir)) {
                        continue;
                    }
                    const trustFile = path.join(fullPath, 'trust.json');
                    if (fs.existsSync(trustFile)) {
                        try {
                            fs.unlinkSync(trustFile);
                            deletedCount++;
                            outputChannel?.appendLine(`Deleted project trust store: ${trustFile}`);
                            const sigFile = trustFile + '.signature';
                            if (fs.existsSync(sigFile)) {
                                fs.unlinkSync(sigFile);
                                outputChannel?.appendLine(`Deleted project trust signature: ${sigFile}`);
                            }
                        } catch (e: any) {
                            outputChannel?.appendLine(`Failed to delete ${trustFile}: ${e.message}`);
                        }
                    }
                } else {
                    try {
                        const stat = fs.statSync(fullPath);
                        if (stat.isDirectory()) {
                            if (file !== 'node_modules' && file !== '.git' && file !== 'bin' && file !== 'obj') {
                                purgeProjectTrusts(fullPath, depth + 1);
                            }
                        }
                    } catch (e) {}
                }
            }
        } catch (e) {}
    }

    purgeProjectTrusts(rootDir);
    if (deletedCount > 0) {
        void vscode.window.showInformationMessage(`Successfully removed project-level trusts from ${deletedCount} project(s).`);
        restartWorkerClient();
        void runScan();
    } else {
        void vscode.window.showInformationMessage("No project-level trust files found to remove.");
    }
}
