import * as path from 'path';
import * as fs from 'fs';
import * as vscode from 'vscode';
import { WorkerClient, ScanReport } from './services/workerClient';
import { DiagnosticPublisher } from './services/diagnosticPublisher';
import { BuildEnforcer } from './services/buildEnforcer';
import { SecurityReviewViewProvider } from './views/securityReviewView';
import { PolicyEditorPanel } from './views/policyEditorView';
import { TrustStorePanel } from './views/trustStoreView';

let workerClient: WorkerClient | null = null;
let diagnosticPublisher: DiagnosticPublisher | null = null;
let buildEnforcer: BuildEnforcer | null = null;
let statusBarItem: vscode.StatusBarItem | null = null;
let outputChannel: vscode.OutputChannel | null = null;

let latestReport: ScanReport | null = null;
let activeReviewProvider: any = null; // Will be set once review view provider is registered

export function activate(context: vscode.ExtensionContext) {
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
