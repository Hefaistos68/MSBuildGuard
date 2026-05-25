import * as vscode from 'vscode';
import * as path from 'path';
import { WorkerClient } from '../services/workerClient';

export class TrustStorePanel {
    public static currentPanel: TrustStorePanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private _workerClient: WorkerClient;
    private _solutionPath = '';
    private _projectPaths: string[] = [];
    private _activeScope = 'User'; // 'User', 'Solution', 'Project'
    private _selectedProject = '';

    public static createOrShow(
        extensionUri: vscode.Uri,
        workerClient: WorkerClient,
        solutionPath: string,
        projectPaths: string[],
        initialScope: 'User' | 'Solution' | 'Project' = 'User'
    ) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (TrustStorePanel.currentPanel) {
            TrustStorePanel.currentPanel._solutionPath = solutionPath;
            TrustStorePanel.currentPanel._projectPaths = projectPaths;
            TrustStorePanel.currentPanel._activeScope = initialScope;
            TrustStorePanel.currentPanel._panel.reveal(column);
            void TrustStorePanel.currentPanel._loadTrustStoreData();
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'msbuildguard.trustStore',
            '🛡️ MSBuild Guard: Trust Store Manager',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [extensionUri],
                retainContextWhenHidden: true
            }
        );

        TrustStorePanel.currentPanel = new TrustStorePanel(panel, extensionUri, workerClient, solutionPath, projectPaths, initialScope);
        void TrustStorePanel.currentPanel._loadTrustStoreData();
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        workerClient: WorkerClient,
        solutionPath: string,
        projectPaths: string[],
        initialScope: 'User' | 'Solution' | 'Project'
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._workerClient = workerClient;
        this._solutionPath = solutionPath;
        this._projectPaths = projectPaths;
        this._activeScope = initialScope;

        this._panel.webview.html = this._getHtmlForWebview(this._panel.webview);

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'requestInitialData':
                        await this._loadTrustStoreData();
                        break;
                    case 'changeScope':
                        this._activeScope = message.scope;
                        this._selectedProject = message.selectedProject || '';
                        await this._loadTrustStoreData();
                        break;
                    case 'revokeTrust':
                        await this._revokeTrustDecision(message.subjectHash, message.reason);
                        break;
                    case 'showError':
                        void vscode.window.showErrorMessage(message.text);
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    private async _loadTrustStoreData() {
        let targetPath = '';
        if (this._activeScope === 'Project') {
            targetPath = this._selectedProject || (this._projectPaths.length > 0 ? this._projectPaths[0] : '');
        } else if (this._activeScope === 'Solution') {
            targetPath = this._solutionPath;
        } else {
            targetPath = this._solutionPath;
        }

        try {
            const result = await this._workerClient.getTrustStoreAsync(targetPath, this._activeScope);
            
            await this._panel.webview.postMessage({
                command: 'loadTrustStore',
                scope: this._activeScope,
                decisions: result?.decisions || [],
                projectPaths: this._projectPaths.map(p => ({ path: p, name: path.basename(p) })),
                selectedProject: this._selectedProject || (this._projectPaths.length > 0 ? this._projectPaths[0] : ''),
                storePath: targetPath
            });
        } catch (err: any) {
            await this._panel.webview.postMessage({
                command: 'statusError',
                message: `Failed to load trust store: ${err.message}`
            });
        }
    }

    private async _revokeTrustDecision(subjectHash: string, reason: string) {
        let targetPath = '';
        if (this._activeScope === 'Project') {
            targetPath = this._selectedProject || (this._projectPaths.length > 0 ? this._projectPaths[0] : '');
        } else if (this._activeScope === 'Solution') {
            targetPath = this._solutionPath;
        } else {
            targetPath = this._solutionPath;
        }

        try {
            await this._workerClient.removeTrustAsync(targetPath, this._activeScope, subjectHash, reason);
            void vscode.window.showInformationMessage('Successfully revoked trust decision from active store.');

            void vscode.commands.executeCommand('msbuildguard.scan');

            await this._loadTrustStoreData();
        } catch (err: any) {
            void vscode.window.showErrorMessage(`Failed to revoke trust: ${err.message}`);
        }
    }

    public dispose() {
        TrustStorePanel.currentPanel = undefined;
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
    <title>MSBuild Guard Trust Store Manager</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');

        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-glow: rgba(59, 130, 246, 0.35);
            --accent-glow-red: rgba(239, 68, 68, 0.35);
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
            max-width: 1000px;
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
            background: var(--accent-danger);
        }

        .header-title-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
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
            background: var(--accent-danger);
            box-shadow: 0 0 10px var(--accent-glow-red);
        }

        .controls-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }

        .search-container {
            position: relative;
            flex: 1;
            min-width: 250px;
        }

        .search-input {
            width: 100%;
            background-color: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            color: var(--text-primary);
            padding: 12px 16px 12px 40px;
            font-family: var(--font-family);
            font-size: 0.9rem;
            outline: none;
            transition: all 0.2s ease;
            box-sizing: border-box;
        }

        .search-input:focus {
            border-color: var(--accent-danger);
            box-shadow: 0 0 8px var(--accent-glow-red);
        }

        .search-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.1rem;
            color: var(--text-secondary);
            pointer-events: none;
        }

        .project-select-container {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .project-select-container label {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
            white-space: nowrap;
        }

        select {
            background-color: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            padding: 10px 14px;
            font-family: var(--font-family);
            font-size: 0.9rem;
            outline: none;
            min-width: 200px;
        }

        .trust-list {
            display: flex;
            flex-direction: column;
            gap: 16px;
            width: 100%;
        }

        .trust-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            gap: 12px;
            position: relative;
            transition: all 0.25s ease;
            box-sizing: border-box;
        }

        .trust-card:hover {
            border-color: rgba(255, 255, 255, 0.15);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.25);
            transform: translateY(-2px);
        }

        .trust-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            border-top-left-radius: 16px;
            border-bottom-left-radius: 16px;
        }

        .trust-card.finding::before { background: var(--accent-primary); }
        .trust-card.assembly::before { background: var(--accent-success); }
        .trust-card.signer::before { background: #a855f7; }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }

        .card-header-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .card-date {
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .card-subject {
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1.4;
            word-break: break-all;
            margin-top: 4px;
        }

        .card-details-section {
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 12px 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            font-size: 0.85rem;
            line-height: 1.4;
        }

        .card-detail-item {
            display: flex;
            gap: 8px;
            word-break: break-all;
        }

        .card-detail-label {
            font-weight: 600;
            color: var(--text-primary);
            min-width: 120px;
            flex-shrink: 0;
        }

        .card-detail-value {
            color: var(--text-secondary);
        }

        .card-reason-section {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-style: italic;
            background: rgba(255, 255, 255, 0.02);
            padding: 8px 12px;
            border-radius: 8px;
            border-left: 2px solid var(--border-color);
        }

        .card-reason-icon {
            opacity: 0.7;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge.finding { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .badge.assembly { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge.signer { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }

        .btn-revoke {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            padding: 8px 14px;
            font-family: var(--font-family);
            font-weight: 600;
            font-size: 0.78rem;
            border-radius: 6px;
            cursor: pointer;
            box-shadow: 0 2px 8px var(--accent-glow-red);
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn-revoke:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.5);
        }

        .btn-revoke:active {
            transform: translateY(1px);
        }

        .empty-state {
            padding: 60px 40px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            gap: 16px;
            color: var(--text-secondary);
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            width: 100%;
            box-sizing: border-box;
        }

        .empty-state-icon {
            font-size: 3rem;
            opacity: 0.5;
        }

        .status-toast {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 16px 24px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(12px);
        }

        .status-toast.error {
            color: var(--accent-danger);
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
                <h1>🛡️ MSBuild Guard: Trust Store Manager</h1>
                <div class="tabs" id="scopeTabs">
                    <button class="tab active" data-scope="User">Global Store</button>
                    <button class="tab" data-scope="Solution">Solution Store</button>
                    <button class="tab" data-scope="Project">Project Store</button>
                </div>
            </div>
            <p>Manage and revoke cryptographically approved findings, NuGet packages, and certificate signers.</p>
        </div>

        <!-- Controls row -->
        <div class="controls-row">
            <div class="search-container">
                <span class="search-icon">🔍</span>
                <input type="text" class="search-input" id="searchInput" placeholder="Search by name, subject, hash, reason..." />
            </div>

            <div class="project-select-container" id="projectSelectWrapper" style="display: none;">
                <label for="projectSelector">Select Project</label>
                <select id="projectSelector">
                    <!-- Dynamic project options -->
                </select>
            </div>
        </div>

        <!-- Trust Decisions List Container -->
        <div class="trust-list" id="trustList">
            <!-- Loaded dynamically as cards -->
        </div>

        <!-- Empty State -->
        <div class="empty-state" id="emptyState" style="display: none;">
            <span class="empty-state-icon">🛡️</span>
            <h3>No active trust decisions identified</h3>
            <p>Add trusts directly from the Security Review findings details panel to populate this store.</p>
        </div>

        <!-- Status bar -->
        <div class="status-toast" id="statusToast">
            <span class="pulse-loader" id="statusPulse"></span>
            <span id="statusText">Loading trust store configurations...</span>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let allDecisions = [];
        let searchFilter = "";

        // Trigger request on DOM load
        window.addEventListener('DOMContentLoaded', () => {
            vscode.postMessage({ command: 'requestInitialData' });
        });

        // Search inputs
        document.getElementById('searchInput').addEventListener('input', (e) => {
            searchFilter = e.target.value.toLowerCase().trim();
            renderList();
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

                document.getElementById('statusText').innerText = 'Loading ' + scope + ' Trust Store...';
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

        // List renderer
        function renderList() {
            const list = document.getElementById('trustList');
            const empty = document.getElementById('emptyState');
            
            list.innerHTML = '';

            const filtered = allDecisions.filter(d => {
                if (!searchFilter) return true;
                
                const kind = (d.scope || "").toLowerCase();
                const subject = (d.subjectHash || "").toLowerCase();
                const reason = (d.reason || "").toLowerCase();
                const name = (d.assemblyName || "").toLowerCase();
                const signer = (d.assemblySigner || "").toLowerCase();
                const certSub = (d.assemblySubject || "").toLowerCase();
                
                return kind.includes(searchFilter) || 
                       subject.includes(searchFilter) || 
                       reason.includes(searchFilter) || 
                       name.includes(searchFilter) || 
                       signer.includes(searchFilter) || 
                       certSub.includes(searchFilter);
            });

            if (filtered.length === 0) {
                empty.style.display = 'flex';
                return;
            }

            empty.style.display = 'none';

            filtered.forEach(d => {
                const card = document.createElement('div');
                const kindClass = (d.scope || 'finding').toLowerCase();
                card.className = 'trust-card ' + kindClass;

                // 1. Header Row
                const header = document.createElement('div');
                header.className = 'card-header';
                
                const headerLeft = document.createElement('div');
                headerLeft.className = 'card-header-left';
                
                const badge = document.createElement('span');
                badge.className = 'badge ' + kindClass;
                badge.innerText = d.scope || 'Finding';
                headerLeft.appendChild(badge);

                const dateSpan = document.createElement('span');
                dateSpan.className = 'card-date';
                if (d.createdAtUtc) {
                    dateSpan.innerText = 'Trusted on ' + new Date(d.createdAtUtc).toLocaleDateString(undefined, {
                        year: 'numeric', month: 'short', day: 'numeric'
                    });
                } else {
                    dateSpan.innerText = 'Trusted';
                }
                headerLeft.appendChild(dateSpan);
                header.appendChild(headerLeft);

                const btn = document.createElement('button');
                btn.className = 'btn-revoke';
                btn.innerHTML = '❌ Revoke Trust';
                btn.addEventListener('click', () => {
                    if (confirm('Are you sure you want to revoke trust for this ' + d.scope.toLowerCase() + '? This will restore security review warnings/blockers immediately.')) {
                        vscode.postMessage({
                            command: 'revokeTrust',
                            subjectHash: d.subjectHash,
                            reason: 'Revoked via VS Code Trust Store Manager'
                        });
                    }
                });
                header.appendChild(btn);
                card.appendChild(header);

                // 2. Subject Title
                const subject = document.createElement('div');
                subject.className = 'card-subject';
                if (d.scope === 'Assembly') {
                    subject.innerText = '📦 NuGet: ' + (d.assemblyName || 'Unnamed Package');
                } else if (d.scope === 'Signer') {
                    subject.innerText = '🔑 Certificate Signer: ' + (d.assemblySubject || 'Unnamed Signer');
                } else {
                    subject.innerText = '🛡️ Finding Fingerprint: ' + (d.subjectHash || 'No Fingerprint');
                }
                card.appendChild(subject);

                // 3. Details block
                const detailsSec = document.createElement('div');
                detailsSec.className = 'card-details-section';

                if (d.scope === 'Assembly') {
                    detailsSec.innerHTML = 
                        '<div class="card-detail-item"><span class="card-detail-label">Version:</span><span class="card-detail-value">' + (d.assemblyVersion || 'Any') + '</span></div>' +
                        '<div class="card-detail-item"><span class="card-detail-label">Signer:</span><span class="card-detail-value">' + (d.assemblySigner || 'None') + '</span></div>' +
                        '<div class="card-detail-item"><span class="card-detail-label">Subject Hash:</span><span class="card-detail-value">' + (d.subjectHash || 'None') + '</span></div>';
                } else if (d.scope === 'Signer') {
                    detailsSec.innerHTML = 
                        '<div class="card-detail-item"><span class="card-detail-label">Issuer:</span><span class="card-detail-value">' + (d.assemblyIssuer || 'None') + '</span></div>' +
                        '<div class="card-detail-item"><span class="card-detail-label">Serial Number:</span><span class="card-detail-value">' + (d.assemblySerialNumber || 'None') + '</span></div>' +
                        '<div class="card-detail-item"><span class="card-detail-label">Thumbprint:</span><span class="card-detail-value">' + (d.subjectHash || 'None') + '</span></div>';
                } else {
                    detailsSec.innerHTML = 
                        '<div class="card-detail-item"><span class="card-detail-label">Fingerprint:</span><span class="card-detail-value">' + (d.subjectHash || 'None') + '</span></div>' +
                        '<div class="card-detail-item"><span class="card-detail-label">Repo Remote:</span><span class="card-detail-value">' + (d.repositoryRemote || 'None') + '</span></div>';
                }
                card.appendChild(detailsSec);

                // 4. Reason block
                const reasonSec = document.createElement('div');
                reasonSec.className = 'card-reason-section';
                reasonSec.innerHTML = '<span class="card-reason-icon">🛡️</span>' +
                                      '<span><strong>Reason:</strong> ' + (d.reason || 'Trusted by security audit.') + '</span>';
                card.appendChild(reasonSec);

                list.appendChild(card);
            });
        }

        // Webview message dispatch
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.command) {
                case 'loadTrustStore':
                    allDecisions = message.decisions || [];
                    
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

                    // Synchronize the active tab in UI with the loaded scope
                    const tabs = document.querySelectorAll('.tab');
                    tabs.forEach(tab => {
                        if (tab.getAttribute('data-scope') === message.scope) {
                            tab.classList.add('active');
                        } else {
                            tab.classList.remove('active');
                        }
                    });

                    // Show/hide project selector wrapper depending on scope
                    if (message.scope === 'Project') {
                        document.getElementById('projectSelectWrapper').style.display = 'flex';
                    } else {
                        document.getElementById('projectSelectWrapper').style.display = 'none';
                    }

                    renderList();

                    document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-success)';
                    document.getElementById('statusText').innerText = 'Active store: ' + message.scope + ' Trust Store (' + allDecisions.length + ' entries)';
                    document.getElementById('statusToast').className = 'status-toast success';
                    break;

                case 'statusError':
                    document.getElementById('statusPulse').style.backgroundColor = 'var(--accent-danger)';
                    document.getElementById('statusText').innerText = message.message;
                    document.getElementById('statusToast').className = 'status-toast error';
                    break;
            }
        });
    </script>
</body>
</html>
`;
    }
}
