import * as vscode from 'vscode';
import * as path from 'path';
import { WorkerClient } from '../services/workerClient';

export class PolicyEditorPanel {
    public static currentPanel: PolicyEditorPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private _workerClient: WorkerClient;
    private _solutionPath = '';
    private _projectPaths: string[] = [];
    private _activeScope = 'Solution'; // 'Machine', 'Solution', 'Project'
    private _selectedProject = '';
    private _currentPolicyPath = '';

    public static createOrShow(
        extensionUri: vscode.Uri,
        workerClient: WorkerClient,
        solutionPath: string,
        projectPaths: string[]
    ) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (PolicyEditorPanel.currentPanel) {
            PolicyEditorPanel.currentPanel._solutionPath = solutionPath;
            PolicyEditorPanel.currentPanel._projectPaths = projectPaths;
            PolicyEditorPanel.currentPanel._panel.reveal(column);
            void PolicyEditorPanel.currentPanel._loadPolicyData();
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'msbuildguard.policyEditor',
            '🛡️ MSBuild Guard: Policy Editor',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [extensionUri],
                retainContextWhenHidden: true
            }
        );

        PolicyEditorPanel.currentPanel = new PolicyEditorPanel(panel, extensionUri, workerClient, solutionPath, projectPaths);
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        workerClient: WorkerClient,
        solutionPath: string,
        projectPaths: string[]
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._workerClient = workerClient;
        this._solutionPath = solutionPath;
        this._projectPaths = projectPaths;

        this._panel.webview.html = this._getHtmlForWebview(this._panel.webview);

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'requestInitialData':
                        await this._loadPolicyData();
                        break;
                    case 'changeScope':
                        this._activeScope = message.scope;
                        this._selectedProject = message.selectedProject || '';
                        await this._loadPolicyData();
                        break;
                    case 'savePolicy':
                        await this._savePolicyData(message.policy);
                        break;
                    case 'showError':
                        void vscode.window.showErrorMessage(message.text);
                        break;
                    case 'showInfo':
                        void vscode.window.showInformationMessage(message.text);
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    private async _loadPolicyData() {
        // Resolve path
        let targetPath = '';
        if (this._activeScope === 'Machine') {
            // Machine policy is usually located in a global MSBuildGuard dir
            // Let's resolve it using the worker or a default fallback
            targetPath = process.platform === 'win32' 
                ? 'C:\\ProgramData\\MSBuildGuard\\policy.json'
                : '/etc/msbuildguard/policy.json';
        } else if (this._activeScope === 'Project') {
            targetPath = this._selectedProject || (this._projectPaths.length > 0 ? this._projectPaths[0] : '');
        } else {
            targetPath = this._solutionPath;
        }

        this._currentPolicyPath = targetPath;

        try {
            const policy = await this._workerClient.getPolicyAsync(targetPath);
            await this._panel.webview.postMessage({
                command: 'loadPolicy',
                scope: this._activeScope,
                policy: policy,
                projectPaths: this._projectPaths.map(p => ({ path: p, name: path.basename(p) })),
                selectedProject: this._selectedProject || (this._projectPaths.length > 0 ? this._projectPaths[0] : ''),
                policyPath: targetPath
            });
        } catch (err: any) {
            await this._panel.webview.postMessage({
                command: 'statusError',
                message: `Failed to load policy: ${err.message}`
            });
        }
    }

    private async _savePolicyData(policy: any) {
        if (!this._currentPolicyPath) {
            void vscode.window.showErrorMessage('No active policy path set to save.');
            return;
        }

        try {
            await this._workerClient.savePolicyAsync(this._currentPolicyPath, policy);
            void vscode.window.showInformationMessage(`Successfully saved and signed ${this._activeScope} policy config!`);
            
            // Rescan workspace to apply the changes
            void vscode.commands.executeCommand('msbuildguard.scan');

            await this._panel.webview.postMessage({
                command: 'saveStatus',
                success: true,
                message: `Saved policy: ${path.basename(this._currentPolicyPath)}`
            });

            await this._loadPolicyData();
        } catch (err: any) {
            void vscode.window.showErrorMessage(`Failed to save policy: ${err.message}`);
            await this._panel.webview.postMessage({
                command: 'saveStatus',
                success: false,
                message: `Save failed: ${err.message}`
            });
        }
    }

    public dispose() {
        PolicyEditorPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSBuild Guard Policy Editor</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');

        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-glow: rgba(59, 130, 246, 0.35);
            --accent-glow-green: rgba(16, 185, 129, 0.35);
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-primary: #3b82f6;
            --accent-success: #10b981;
            --accent-danger: #ef4444;
            --font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: var(--font-family);
            margin: 0;
            padding: 24px;
            box-sizing: border-box;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            overflow-y: auto;
        }

        .container {
            max-width: 900px;
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .header {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            gap: 12px;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-primary);
        }

        .header-title-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-size: 1.6rem;
            margin: 0;
            font-weight: 700;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .header p {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin: 0;
            line-height: 1.4;
        }

        .tabs {
            display: flex;
            gap: 8px;
            background: rgba(15, 23, 42, 0.6);
            padding: 4px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            align-self: flex-start;
        }

        .tab {
            padding: 8px 16px;
            border-radius: 8px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            font-family: var(--font-family);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.85rem;
        }

        .tab:hover {
            color: var(--text-primary);
            background: rgba(255, 255, 255, 0.03);
        }

        .tab.active {
            color: #fff;
            background: var(--accent-primary);
            box-shadow: 0 0 10px var(--accent-glow);
        }

        .project-select-container {
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-top: 10px;
        }

        .project-select-container label {
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        select, input[type="text"] {
            background-color: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            padding: 10px 14px;
            font-family: var(--font-family);
            font-size: 0.9rem;
            outline: none;
            transition: all 0.2s ease;
            width: 100%;
            box-sizing: border-box;
        }

        select:focus, input[type="text"]:focus {
            border-color: var(--accent-primary);
            box-shadow: 0 0 8px var(--accent-glow);
        }

        /* Impact Coloring Styles for Selects and Options */
        .impact-allow, select option[value="Allow"], select option[value="allow"] {
            color: #10b981 !important;
            font-weight: 600;
        }
        .impact-warn, select option[value="Warn"], select option[value="warn"] {
            color: #3b82f6 !important;
            font-weight: 600;
        }
        .impact-review, select option[value="RequireApproval"] {
            color: #eab308 !important;
            font-weight: 600;
        }
        .impact-block, select option[value="Block"], select option[value="block"] {
            color: #ef4444 !important;
            font-weight: 600;
        }

        .editor-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        @media (max-width: 768px) {
            .editor-grid {
                grid-template-columns: 1fr;
            }
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .card h2 {
            font-size: 1.1rem;
            margin: 0;
            font-weight: 600;
            color: #fff;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .form-row {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .form-row label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .checkbox-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 14px;
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            cursor: pointer;
            user-select: none;
            transition: all 0.2s ease;
        }

        .checkbox-row:hover {
            border-color: rgba(255, 255, 255, 0.15);
            background: rgba(15, 23, 42, 0.6);
        }

        .checkbox-row input[type="checkbox"] {
            width: 16px;
            height: 16px;
            cursor: pointer;
            accent-color: var(--accent-primary);
        }

        .checkbox-details {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        .checkbox-title {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .checkbox-desc {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .full-width-card {
            grid-column: 1 / -1;
        }

        .severity-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 12px;
        }

        .severity-badge-card {
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            align-items: center;
            position: relative;
            overflow: hidden;
        }

        .severity-badge-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
        }

        .severity-badge-card.critical::before { background: var(--accent-danger); }
        .severity-badge-card.high::before { background: #f97316; }
        .severity-badge-card.medium::before { background: #eab308; }
        .severity-badge-card.low::before { background: #3b82f6; }
        .severity-badge-card.info::before { background: #10b981; }

        .severity-label {
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge-card.critical .severity-label { color: var(--accent-danger); }
        .severity-badge-card.high .severity-label { color: #f97316; }
        .severity-badge-card.medium .severity-label { color: #eab308; }
        .severity-badge-card.low .severity-label { color: #3b82f6; }
        .severity-badge-card.info .severity-label { color: #10b981; }

        .severity-badge-card select {
            padding: 6px 10px;
            font-size: 0.75rem;
            border-radius: 6px;
            text-align: center;
        }

        .action-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 16px 24px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(12px);
        }

        .status-toast {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .status-toast.success {
            color: var(--accent-success);
        }

        .status-toast.error {
            color: var(--accent-danger);
        }

        .btn-save {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            border: none;
            padding: 12px 28px;
            font-family: var(--font-family);
            font-weight: 600;
            font-size: 0.95rem;
            border-radius: 10px;
            cursor: pointer;
            box-shadow: 0 4px 15px var(--accent-glow-green);
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-save:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.5);
        }

        .btn-save:active {
            transform: translateY(1px);
        }

        .pulse-loader {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--accent-primary);
            animation: pulse 1.5s infinite ease-in-out;
        }

        @keyframes pulse {
            0% { transform: scale(0.8); opacity: 0.5; }
            50% { transform: scale(1.3); opacity: 1; }
            100% { transform: scale(0.8); opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title-row">
                <h1>🛡️ MSBuild Guard: Policy Settings</h1>
                <div class="tabs" id="scopeTabs">
                    <button class="tab active" data-scope="Solution">Solution Policy</button>
                    <button class="tab" data-scope="Project">Project Policy</button>
                    <button class="tab" data-scope="Machine">Machine Policy</button>
                </div>
            </div>
            <p>Define rules and severity actions that regulate MSBuild project files before execution.</p>
            
            <div class="project-select-container" id="projectSelectWrapper" style="display: none;">
                <label for="projectSelector">Select Project File</label>
                <select id="projectSelector">
                    <!-- Loaded dynamically -->
                </select>
            </div>
        </div>

        <!-- Editor Form Layout -->
        <div class="editor-grid">
            <!-- Core Configurations Card -->
            <div class="card">
                <h2>⚙️ General Configurations</h2>
                
                <div class="form-row">
                    <label for="policyMode">Policy Enforcement Mode</label>
                    <select id="policyMode">
                        <option value="warn">Warn Only (Allow building with log warnings)</option>
                        <option value="block">Strict Enforcement (Block builds on policy failures)</option>
                    </select>
                </div>

                <div class="checkbox-row" onclick="toggleCheckbox('baselineRequired')">
                    <input type="checkbox" id="baselineRequired" />
                    <div class="checkbox-details">
                        <span class="checkbox-title">Require Trusted Baseline</span>
                        <span class="checkbox-desc">Block/warn on any new findings missing from baseline.json</span>
                    </div>
                </div>

                <div class="checkbox-row" onclick="toggleCheckbox('strictMode')">
                    <input type="checkbox" id="strictMode" />
                    <div class="checkbox-details">
                        <span class="checkbox-title">Enable strict analysis</span>
                        <span class="checkbox-desc">Escalate severity if validation signatures are missing</span>
                    </div>
                </div>
            </div>

            <!-- Action Behaviors Card -->
            <div class="card">
                <h2>🛠️ Build-Time Actions</h2>

                <div class="form-row">
                    <label for="incompleteAnalysisAction">Incomplete Analysis Behavior</label>
                    <select id="incompleteAnalysisAction">
                        <option value="Allow">Allow (Proceed despite skipped/incomplete scans)</option>
                        <option value="Warn">Warn (Notify on incomplete scan state)</option>
                        <option value="RequireApproval">Require Manual Review</option>
                        <option value="Block">Block Build immediately</option>
                    </select>
                </div>

                <div class="form-row">
                    <label for="unapprovedPackageSourceAction">Unapproved NuGet Sources Action</label>
                    <select id="unapprovedPackageSourceAction">
                        <option value="Allow">Allow package installation</option>
                        <option value="Warn">Warn if downloaded from unlisted source</option>
                        <option value="RequireApproval">Require review on unapproved feeds</option>
                        <option value="Block">Block unauthorized package references</option>
                    </select>
                </div>
            </div>

            <!-- Severity Action Overrides Card -->
            <div class="card full-width-card">
                <h2>📊 Minimum Enforcement Action by Severity</h2>
                
                <div class="severity-list">
                    <!-- Critical -->
                    <div class="severity-badge-card critical">
                        <span class="severity-label">Critical</span>
                        <select id="actionCritical">
                            <option value="Allow">Allow</option>
                            <option value="Warn">Warn</option>
                            <option value="RequireApproval">Review</option>
                            <option value="Block">Block</option>
                        </select>
                    </div>

                    <!-- High -->
                    <div class="severity-badge-card high">
                        <span class="severity-label">High</span>
                        <select id="actionHigh">
                            <option value="Allow">Allow</option>
                            <option value="Warn">Warn</option>
                            <option value="RequireApproval">Review</option>
                            <option value="Block">Block</option>
                        </select>
                    </div>

                    <!-- Medium -->
                    <div class="severity-badge-card medium">
                        <span class="severity-label">Medium</span>
                        <select id="actionMedium">
                            <option value="Allow">Allow</option>
                            <option value="Warn">Warn</option>
                            <option value="RequireApproval">Review</option>
                            <option value="Block">Block</option>
                        </select>
                    </div>

                    <!-- Low -->
                    <div class="severity-badge-card low">
                        <span class="severity-label">Low</span>
                        <select id="actionLow">
                            <option value="Allow">Allow</option>
                            <option value="Warn">Warn</option>
                            <option value="RequireApproval">Review</option>
                            <option value="Block">Block</option>
                        </select>
                    </div>

                    <!-- Info -->
                    <div class="severity-badge-card info">
                        <span class="severity-label">Info</span>
                        <select id="actionInfo">
                            <option value="Allow">Allow</option>
                            <option value="Warn">Warn</option>
                            <option value="RequireApproval">Review</option>
                            <option value="Block">Block</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer / Action bar -->
        <div class="action-bar">
            <div class="status-toast" id="statusToast">
                <span class="pulse-loader" id="statusPulse"></span>
                <span id="statusText">Loading active configuration...</span>
            </div>
            <button class="btn-save" id="btnSave">
                💾 Save & Sign Policy
            </button>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let currentPolicy = null;
        let isDirty = false;
        let selectedProject = "";
        const coloredSelects = [
            'policyMode', 'incompleteAnalysisAction', 'unapprovedPackageSourceAction',
            'actionCritical', 'actionHigh', 'actionMedium', 'actionLow', 'actionInfo'
        ];

        // Trigger request on DOM load
        window.addEventListener('DOMContentLoaded', () => {
            vscode.postMessage({ command: 'requestInitialData' });
        });

        // Toggle checkbox on row click
        function toggleCheckbox(id) {
            const checkbox = document.getElementById(id);
            checkbox.checked = !checkbox.checked;
            markDirty();
        }

        function markDirty() {
            isDirty = true;
            document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-primary)';
            document.getElementById('statusText').innerText = 'Unsaved modifications exist.';
            document.getElementById('statusToast').className = 'status-toast';
        }

        function updateSelectColor(selectEl) {
            if (!selectEl) return;
            selectEl.classList.remove('impact-allow', 'impact-warn', 'impact-review', 'impact-block');
            const val = selectEl.value;
            if (val === 'Allow' || val === 'allow') {
                selectEl.classList.add('impact-allow');
            } else if (val === 'Warn' || val === 'warn') {
                selectEl.classList.add('impact-warn');
            } else if (val === 'RequireApproval') {
                selectEl.classList.add('impact-review');
            } else if (val === 'Block' || val === 'block') {
                selectEl.classList.add('impact-block');
            }
        }

        // Add dirty listeners to standard selects
        const selects = document.querySelectorAll('select, input[type="checkbox"]');
        selects.forEach(sel => {
            sel.addEventListener('change', () => markDirty());
        });

        // Add color updating listeners to colored selects
        coloredSelects.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.addEventListener('change', () => updateSelectColor(el));
            }
        });

        // Tabs Scope Selection
        const tabButtons = document.querySelectorAll('.tab');
        tabButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                if (btn.classList.contains('active')) return;
                
                tabButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const scope = btn.getAttribute('data-scope');
                const projectSelector = document.getElementById('projectSelector');
                
                if (scope === 'Project') {
                    document.getElementById('projectSelectWrapper').style.display = 'flex';
                } else {
                    document.getElementById('projectSelectWrapper').style.display = 'none';
                }

                document.getElementById('statusText').innerText = 'Loading ' + scope + ' Policy...';
                document.getElementById('statusToast').className = 'status-toast';
                
                vscode.postMessage({
                    command: 'changeScope',
                    scope: scope,
                    selectedProject: projectSelector.value || ""
                });
            });
        });

        // Project selector change listener
        document.getElementById('projectSelector').addEventListener('change', (e) => {
            const scope = document.querySelector('.tab.active').getAttribute('data-scope');
            vscode.postMessage({
                command: 'changeScope',
                scope: scope,
                selectedProject: e.target.value
            });
        });

        // Webview message dispatch
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.command) {
                case 'loadPolicy':
                    currentPolicy = message.policy;
                    isDirty = false;
                    
                    // Render scope selector projects
                    const projSelect = document.getElementById('projectSelector');
                    projSelect.innerHTML = '';
                    
                    if (message.projectPaths && message.projectPaths.length > 0) {
                        message.projectPaths.forEach(proj => {
                            const opt = document.createElement('option');
                            opt.value = proj.path;
                            opt.innerText = proj.name;
                            if (proj.path === message.selectedProject) {
                                opt.selected = true;
                            }
                            projSelect.appendChild(opt);
                        });
                    }

                    // Populate fields
                    document.getElementById('policyMode').value = currentPolicy.mode || 'warn';
                    document.getElementById('baselineRequired').checked = !!currentPolicy.baselineRequired;
                    document.getElementById('strictMode').checked = !!currentPolicy.strictMode;
                    document.getElementById('incompleteAnalysisAction').value = currentPolicy.incompleteAnalysisAction || 'Warn';
                    document.getElementById('unapprovedPackageSourceAction').value = currentPolicy.unapprovedPackageSourceAction || 'RequireApproval';
                    
                    // Bind severity thresholds
                    const thresholds = currentPolicy.minimumActionBySeverity || {};
                    document.getElementById('actionCritical').value = thresholds.Critical || 'Block';
                    document.getElementById('actionHigh').value = thresholds.High || 'Block';
                    document.getElementById('actionMedium').value = thresholds.Medium || 'RequireApproval';
                    document.getElementById('actionLow').value = thresholds.Low || 'Warn';
                    document.getElementById('actionInfo').value = thresholds.Info || 'Allow';

                    coloredSelects.forEach(id => {
                        updateSelectColor(document.getElementById(id));
                    });

                    document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-success)';
                    document.getElementById('statusText').innerText = 'Active config: ' + message.policyPath.split(/[\/\\\\]/).pop();
                    document.getElementById('statusToast').className = 'status-toast success';
                    break;

                case 'saveStatus':
                    if (message.success) {
                        isDirty = false;
                        document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-success)';
                        document.getElementById('statusText').innerText = message.message;
                        document.getElementById('statusToast').className = 'status-toast success';
                    } else {
                        document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-danger)';
                        document.getElementById('statusText').innerText = message.message;
                        document.getElementById('statusToast').className = 'status-toast error';
                    }
                    break;
                case 'statusError':
                    document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-danger)';
                    document.getElementById('statusText').innerText = message.message;
                    document.getElementById('statusToast').className = 'status-toast error';
                    break;
            }
        });

        // Save Click action
        document.getElementById('btnSave').addEventListener('click', () => {
            if (!currentPolicy) return;

            document.getElementById('statusText').innerText = 'Saving & signing policy envelope...';
            document.getElementById('statusToast').className = 'status-toast';

            // Reconstruct document
            const policy = {
                version: currentPolicy.version || 1,
                mode: document.getElementById('policyMode').value,
                baselineRequired: document.getElementById('baselineRequired').checked,
                strictMode: document.getElementById('strictMode').checked,
                incompleteAnalysisAction: document.getElementById('incompleteAnalysisAction').value,
                unapprovedPackageSourceAction: document.getElementById('unapprovedPackageSourceAction').value,
                minimumActionBySeverity: {
                    Critical: document.getElementById('actionCritical').value,
                    High: document.getElementById('actionHigh').value,
                    Medium: document.getElementById('actionMedium').value,
                    Low: document.getElementById('actionLow').value,
                    Info: document.getElementById('actionInfo').value
                },
                rules: currentPolicy.rules || {},
                include: currentPolicy.include || [],
                exclude: currentPolicy.exclude || []
            };

            vscode.postMessage({
                command: 'savePolicy',
                policy: policy
            });
        });
    </script>
</body>
</html>
`;
    }
}
