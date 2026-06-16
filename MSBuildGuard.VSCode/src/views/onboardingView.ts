import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { WorkerClient } from '../services/workerClient';

export class OnboardingPanel {
    public static currentPanel: OnboardingPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private _workerClient: WorkerClient;
    private _solutionPath: string;
    private _scanOptions: any;
    private _report: any;

    public static createOrShow(
        extensionUri: vscode.Uri,
        workerClient: WorkerClient,
        solutionPath: string,
        scanOptions: any,
        report: any
    ) {
        if (OnboardingPanel.currentPanel) {
            OnboardingPanel.currentPanel._panel.reveal(vscode.ViewColumn.One);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'msbuildguard.onboarding',
            '🛡️ MSBuild Guard: Set Up Trusted Baseline',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [extensionUri],
                retainContextWhenHidden: true
            }
        );

        OnboardingPanel.currentPanel = new OnboardingPanel(panel, extensionUri, workerClient, solutionPath, scanOptions, report);
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        workerClient: WorkerClient,
        solutionPath: string,
        scanOptions: any,
        report: any
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._workerClient = workerClient;
        this._solutionPath = solutionPath;
        this._scanOptions = scanOptions;
        this._report = report;

        this._panel.webview.html = this._getHtmlForWebview(this._panel.webview);

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'requestInitialData':
                        await this._loadSuggestions();
                        break;
                    case 'applySetup':
                        await this._handleApplySetup(message.selectedIndices, message.trustScope, message.createBaseline, message.doNotScan);
                        break;
                    case 'skipSetup':
                        await this._handleSkipSetup(message.dontShowAgain, message.doNotScan);
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

    private async _loadSuggestions() {
        try {
            const suggestions = await this._workerClient.getOnboardingSuggestionsAsync(this._solutionPath, this._scanOptions);
            await this._panel.webview.postMessage({
                command: 'loadSuggestions',
                suggestions,
                solutionName: path.basename(this._solutionPath)
            });
        } catch (err: any) {
            await this._panel.webview.postMessage({
                command: 'statusError',
                message: `Failed to generate trust suggestions: ${err.message}`
            });
        }
    }

    private _resolveProjectPath(finding: any): string | null {
        if (finding.introducedViaProject) {
            if (path.isAbsolute(finding.introducedViaProject)) {
                return finding.introducedViaProject;
            }
            return path.resolve(path.dirname(this._solutionPath), finding.introducedViaProject);
        }
        if (finding.filePath && (finding.filePath.endsWith('.csproj') || finding.filePath.endsWith('.fsproj') || finding.filePath.endsWith('.vbproj'))) {
            return finding.filePath;
        }
        return null;
    }

    private async _handleApplySetup(selectedIndices: number[], trustScope: string, createBaseline: boolean, doNotScan: boolean) {
        try {
            const suggestions = await this._workerClient.getOnboardingSuggestionsAsync(this._solutionPath, this._scanOptions);
            const selectedSuggestions = suggestions.filter((item, idx) => selectedIndices.includes(idx) && !item.isAlreadyTrusted);

            // Apply selected trusts
            if (selectedSuggestions.length > 0) {
                for (const suggestion of selectedSuggestions) {
                    const scope = suggestion.scope;
                    const targetPaths: string[] = [];

                    if (trustScope === 'user') {
                        targetPaths.push(this._solutionPath);
                    } else if (trustScope === 'solution') {
                        targetPaths.push(this._solutionPath);
                    } else if (trustScope === 'project') {
                        // Resolve projects referencing this suggestion
                        const projectPaths = new Set<string>();

                        if (scope === 'Package') {
                            const packageId = suggestion.metadata['PackageId'];
                            if (this._report && this._report.findings) {
                                for (const finding of this._report.findings) {
                                    if (finding.packageId && finding.packageId.toLowerCase() === packageId.toLowerCase()) {
                                        const p = this._resolveProjectPath(finding);
                                        if (p) {
                                            projectPaths.add(p);
                                        }
                                    }
                                }
                            }
                        } else if (scope === 'Assembly') {
                            const assemblyName = suggestion.metadata['AssemblyName'];
                            if (this._report && this._report.findings) {
                                for (const finding of this._report.findings) {
                                    const match = (finding.owningAssembly && finding.owningAssembly.toLowerCase().includes(assemblyName.toLowerCase())) ||
                                                  (finding.filePath && finding.filePath.toLowerCase().includes(assemblyName.toLowerCase()));
                                    if (match) {
                                        const p = this._resolveProjectPath(finding);
                                        if (p) {
                                            projectPaths.add(p);
                                        }
                                    }
                                }
                            }
                        } else if (scope === 'Signer') {
                            const thumbprint = suggestion.metadata['SignerThumbprint'];
                            if (this._report && this._report.findings) {
                                for (const finding of this._report.findings) {
                                    if (finding.packageSignatureState && finding.packageSignatureState.toLowerCase() === thumbprint.toLowerCase()) {
                                        const p = this._resolveProjectPath(finding);
                                        if (p) {
                                            projectPaths.add(p);
                                        }
                                    }
                                }
                            }
                        }

                        if (projectPaths.size === 0 && this._report && this._report.filesScanned) {
                            for (const file of this._report.filesScanned) {
                                if (file.path.endsWith('.csproj') || file.path.endsWith('.fsproj') || file.path.endsWith('.vbproj')) {
                                    projectPaths.add(file.path);
                                }
                            }
                        }

                        targetPaths.push(...projectPaths);
                    } else {
                        targetPaths.push(this._solutionPath);
                    }

                    for (const targetPath of targetPaths) {
                        if (scope === 'Signer') {
                            await this._workerClient.addTrustAsync(targetPath, {
                                trustScope,
                                scope: 'Signer',
                                subjectHash: suggestion.metadata['SignerThumbprint'] || suggestion.subject,
                                assemblySubject: suggestion.metadata['SignerSubject'] || '',
                                assemblySigner: suggestion.displayName,
                                assemblyIssuer: suggestion.metadata['SignerIssuer'] || '',
                                assemblySerialNumber: suggestion.metadata['SignerSerialNumber'] || '',
                                reason: suggestion.recommendationReason
                            });
                        } else if (scope === 'Package') {
                            await this._workerClient.addTrustAsync(targetPath, {
                                trustScope,
                                scope: 'Package',
                                assemblyName: suggestion.metadata['PackageId'] || suggestion.displayName.split(' ')[0],
                                assemblyVersion: suggestion.metadata['PackageVersion'] || suggestion.displayName.split(' ')[1]?.substring(1) || '',
                                reason: suggestion.recommendationReason
                            });
                        } else if (scope === 'Assembly') {
                            await this._workerClient.addTrustAsync(targetPath, {
                                trustScope,
                                scope: 'Assembly',
                                assemblyName: suggestion.metadata['AssemblyName'] || '',
                                assemblyVersion: suggestion.metadata['AssemblyVersion'] || '',
                                reason: suggestion.recommendationReason,
                                assemblySigner: suggestion.metadata['AssemblySigner'] || '',
                                assemblyIssuer: suggestion.metadata['AssemblyIssuer'] || '',
                                assemblySubject: suggestion.metadata['AssemblySubject'] || ''
                            });
                        }
                    }
                }
            }

            // Create baseline for remaining findings
            if (createBaseline) {
                const solutionDir = path.dirname(this._solutionPath);
                const baselineDir = path.join(solutionDir, '.msbuildguard');
                if (!fs.existsSync(baselineDir)) {
                    fs.mkdirSync(baselineDir, { recursive: true });
                }
                const baselinePath = path.join(baselineDir, 'baseline.json');
                const reviewer = process.env.USERNAME || process.env.USER || 'VSCodeUser';
                await this._workerClient.createBaselineAsync(this._solutionPath, reviewer, baselinePath);
            }

            // Bypass scanning if doNotScan is true
            if (doNotScan) {
                this._writeNoscanMarker();
            }

            void vscode.window.showInformationMessage('Trusted baseline onboarding setup completed successfully!');
            
            // Trigger rescan immediately
            void vscode.commands.executeCommand('msbuildguard.scan');
            this.dispose();
        } catch (err: any) {
            void vscode.window.showErrorMessage(`Failed to apply onboarding setup: ${err.message}`);
        }
    }

    private async _handleSkipSetup(dontShowAgain: boolean, doNotScan: boolean) {
        try {
            if (dontShowAgain) {
                const solutionDir = path.dirname(this._solutionPath);
                const trustDir = path.join(solutionDir, '.msbuildguard');
                if (!fs.existsSync(trustDir)) {
                    fs.mkdirSync(trustDir, { recursive: true });
                }
                const trustPath = path.join(trustDir, 'trust.json');
                fs.writeFileSync(trustPath, JSON.stringify({
                    version: "1.0",
                    decisions: []
                }, null, 2));
            }

            if (doNotScan) {
                this._writeNoscanMarker();
            }

            void vscode.window.showInformationMessage('Onboarding skipped. Solution review scanning will continue normally.');
            this.dispose();
        } catch (err: any) {
            void vscode.window.showErrorMessage(`Failed to skip onboarding setup: ${err.message}`);
        }
    }

    private _writeNoscanMarker() {
        const solutionDir = path.dirname(this._solutionPath);
        const noscanDir = path.join(solutionDir, '.msbuildguard');
        if (!fs.existsSync(noscanDir)) {
            fs.mkdirSync(noscanDir, { recursive: true });
        }
        const noscanPath = path.join(noscanDir, 'noscan');
        fs.writeFileSync(noscanPath, 'Scanning disabled.');
    }

    public dispose() {
        OnboardingPanel.currentPanel = undefined;
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
    <title>MSBuild Guard Onboarding</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');

        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.75);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-glow: rgba(59, 130, 246, 0.35);
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-primary: #3b82f6;
            --accent-success: #10b981;
            --font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: var(--font-family);
            margin: 0;
            padding: 40px 24px;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            box-sizing: border-box;
            overflow-y: auto;
        }

        .container {
            max-width: 680px;
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            gap: 16px;
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-primary);
        }

        h1 {
            font-size: 1.8rem;
            margin: 0;
            font-weight: 700;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        p.desc {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin: 0;
            line-height: 1.5;
        }

        .suggestion-list-wrapper {
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.5);
            max-height: 280px;
            overflow-y: auto;
            margin: 8px 0;
        }

        .suggestion-item {
            display: flex;
            gap: 16px;
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            align-items: flex-start;
            transition: background 0.2s ease;
        }

        .suggestion-item:last-child {
            border-bottom: none;
        }

        .suggestion-item:hover {
            background: rgba(255, 255, 255, 0.02);
        }

        .checkbox-container {
            display: flex;
            align-items: center;
            justify-content: center;
            padding-top: 2px;
        }

        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--accent-primary);
            cursor: pointer;
        }

        .suggestion-details {
            display: flex;
            flex-direction: column;
            gap: 6px;
            flex: 1;
        }

        .suggestion-header {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .badge {
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 3px 8px;
            border-radius: 20px;
            letter-spacing: 0.5px;
        }

        .badge-signer {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.25);
        }

        .badge-package {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.25);
        }

        .badge-assembly {
            background: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.25);
        }

        .display-name {
            font-weight: 600;
            font-size: 0.95rem;
            color: #fff;
        }

        .reason {
            font-size: 0.85rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }

        .reputation {
            font-size: 0.75rem;
            color: var(--text-secondary);
            opacity: 0.6;
            font-style: italic;
        }

        .options-section {
            display: flex;
            flex-direction: column;
            gap: 12px;
            padding: 8px 0;
            border-top: 1px solid var(--border-color);
        }

        .option-item {
            display: flex;
            gap: 10px;
            align-items: center;
            font-size: 0.9rem;
            color: var(--text-secondary);
            cursor: pointer;
        }

        .option-item:hover {
            color: var(--text-primary);
        }

        .buttons-row {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            margin-top: 8px;
        }

        button {
            padding: 10px 24px;
            border-radius: 8px;
            font-family: var(--font-family);
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-apply {
            background: var(--accent-primary);
            color: #fff;
            border: none;
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.3);
        }

        .btn-apply:hover {
            background: #2563eb;
            box-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
        }

        .btn-skip {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }

        .btn-skip:hover {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
        }

        .loading-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
            gap: 16px;
        }

        .spinner {
            width: 36px;
            height: 36px;
            border: 3px solid rgba(59, 130, 246, 0.1);
            border-top-color: var(--accent-primary);
            border-radius: 50%;
            animation: spin 1s infinite linear;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .empty-suggestions {
            padding: 32px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        #content {
            display: flex;
            flex-direction: column;
            gap: 20px;
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card" id="mainCard">
            <div class="loading-container" id="loading">
                <div class="spinner"></div>
                <div style="font-weight: 500;">Analyzing solution dependencies...</div>
            </div>

            <div id="content" style="display: none;">
                <h1 id="titleHeader">🛡️ Trusted Baseline Setup</h1>
                <p class="desc" id="descText">
                    MSBuild Guard analyzed <strong><span id="solutionName">this solution</span></strong> and identified common, trusted NuGet packages or assemblies. We recommend trusting these publishers and files to initialize your baseline.
                </p>

                <div class="suggestion-list-wrapper">
                    <div id="suggestionsList"></div>
                </div>

                <div style="display: flex; align-items: center; gap: 12px; margin: 8px 0 16px 0; font-size: 0.95rem;">
                    <strong>Trust Scope Level:</strong>
                    <select id="trustScope" style="background: rgba(15, 23, 42, 0.8); color: #fff; border: 1px solid var(--border-color); border-radius: 6px; padding: 6px 12px; font-family: var(--font-family); cursor: pointer; outline: none;">
                        <option value="solution" selected>Solution Store</option>
                        <option value="user">User Store (Global)</option>
                        <option value="project">Project Store (Local)</option>
                    </select>
                </div>

                <div class="options-section">
                    <label class="option-item">
                        <input type="checkbox" id="createBaseline" checked>
                        Create baseline for remaining (unchecked) findings
                    </label>
                    <label class="option-item">
                        <input type="checkbox" id="dontShowAgain">
                        Don't show this onboarding prompt again for this solution
                    </label>
                    <label class="option-item">
                        <input type="checkbox" id="doNotScan">
                        Do not scan this solution again (completely bypass future scans)
                    </label>
                </div>

                <div class="buttons-row">
                    <button class="btn-skip" id="btnSkip">Skip</button>
                    <button class="btn-apply" id="btnApply">Apply Setup</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let currentSuggestions = [];

        // Request data on load
        vscode.postMessage({ command: 'requestInitialData' });

        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.command) {
                case 'loadSuggestions':
                    currentSuggestions = message.suggestions || [];
                    document.getElementById('solutionName').innerText = message.solutionName;
                    renderSuggestions(currentSuggestions);
                    document.getElementById('loading').style.display = 'none';
                    document.getElementById('content').style.display = 'flex';
                    break;
                case 'statusError':
                    document.getElementById('loading').innerHTML = '<div style="color: var(--accent-danger); font-weight: 600;">Error: ' + message.message + '</div>';
                    break;
            }
        });

        function renderSuggestions(suggestions) {
            const list = document.getElementById('suggestionsList');
            list.innerHTML = '';

            if (suggestions.length === 0) {
                list.innerHTML = '<div class="empty-suggestions">No high-trust signatures or NuGet packages suggested for trust.</div>';
                return;
            }

            suggestions.forEach((item, index) => {
                const badgeClass = 'badge-' + item.scope.toLowerCase();
                const container = document.createElement('div');
                container.className = 'suggestion-item';

                const isAlreadyTrusted = item.isAlreadyTrusted || false;
                const checkboxHtml = isAlreadyTrusted
                    ? '<input type="checkbox" id="sug-' + index + '" checked disabled>'
                    : '<input type="checkbox" id="sug-' + index + '" ' + (item.isSelected ? 'checked' : '') + '>';

                const detailsStyle = isAlreadyTrusted ? 'opacity: 0.65;' : '';
                const trustedIndicator = isAlreadyTrusted ? ' <span style="color: var(--accent-success); font-size: 0.8rem; font-weight: 600; margin-left: 8px;">✓ Already Trusted</span>' : '';

                container.innerHTML = 
                    '<div class="checkbox-container">' +
                        checkboxHtml +
                    '</div>' +
                    '<div class="suggestion-details" style="' + detailsStyle + '">' +
                        '<div class="suggestion-header">' +
                            '<span class="badge ' + badgeClass + '">' + item.scope + '</span>' +
                            '<span class="display-name">' + item.displayName + '</span>' +
                            trustedIndicator +
                        '</div>' +
                        '<div class="reason">' + item.recommendationReason + '</div>' +
                        '<div class="reputation">' + item.reputationSourceDescription + '</div>' +
                    '</div>';
                list.appendChild(container);
            });
        }

        document.getElementById('btnApply').addEventListener('click', () => {
            const selectedIndices = [];
            currentSuggestions.forEach((_, index) => {
                const chk = document.getElementById('sug-' + index);
                if (chk && chk.checked) {
                    selectedIndices.push(index);
                }
            });

            vscode.postMessage({
                command: 'applySetup',
                selectedIndices,
                trustScope: document.getElementById('trustScope').value,
                createBaseline: document.getElementById('createBaseline').checked,
                doNotScan: document.getElementById('doNotScan').checked
            });
        });

        document.getElementById('btnSkip').addEventListener('click', () => {
            vscode.postMessage({
                command: 'skipSetup',
                dontShowAgain: document.getElementById('dontShowAgain').checked,
                doNotScan: document.getElementById('doNotScan').checked
            });
        });
    </script>
</body>
</html>`;
    }
}
