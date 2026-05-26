import * as vscode from 'vscode';
import { ScanReport, Finding } from '../services/workerClient';
import { setGlobalReviewProvider, getWorkerClient } from '../extension';

export class SecurityReviewViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'msbuildguard.securityReview';
    private _view?: vscode.WebviewView;
    private _latestReport: ScanReport | null = null;

    public constructor(private readonly _extensionUri: vscode.Uri) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        webviewView.webview.onDidReceiveMessage((data) => {
            switch (data.command) {
                case 'openFile':
                    this._openFileLocation(data.filePath, data.startLine, data.startColumn);
                    break;
                case 'scanWorkspace':
                    void vscode.commands.executeCommand('msbuildguard.scan');
                    break;
                case 'createBaseline':
                    void vscode.commands.executeCommand('msbuildguard.createBaseline');
                    break;
                case 'editPolicy':
                    void vscode.commands.executeCommand('msbuildguard.editPolicy');
                    break;
                case 'manageTrusts':
                    void vscode.commands.executeCommand('msbuildguard.manageAssemblyTrusts');
                    break;
                case 'addTrust':
                    void this._handleAddTrust(data);
                    break;
                case 'saveOnlyUntrustedSetting':
                    const config = vscode.workspace.getConfiguration('msbuildguard');
                    void config.update('onlyUntrustedIssues', data.value, vscode.ConfigurationTarget.Workspace);
                    break;
            }
        });

        // Watch for settings changes to keep dashboard synced when modified in settings UI
        const settingsDisposable = vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('msbuildguard.onlyUntrustedIssues')) {
                const onlyUntrusted = vscode.workspace.getConfiguration('msbuildguard').get<boolean>('onlyUntrustedIssues', false);
                void webviewView.webview.postMessage({ command: 'updateOnlyUntrustedSetting', value: onlyUntrusted });
            }
        });

        webviewView.onDidDispose(() => {
            settingsDisposable.dispose();
        });

        // Register this provider to receive scans
        setGlobalReviewProvider(this);
    }

    /**
     * Refreshes the review dashboard with a new scan report.
     */
    public refresh(report: ScanReport): void {
        this._latestReport = report;
        if (this._view) {
            void this._view.webview.postMessage({ command: 'updateReport', report });
        }
    }

    private _openFileLocation(filePath: string, line: number, column: number): void {
        const uri = vscode.Uri.file(filePath);
        vscode.workspace.openTextDocument(uri).then((doc) => {
            const position = new vscode.Position(Math.max(0, line - 1), Math.max(0, column - 1));
            const range = new vscode.Range(position, position);
            vscode.window.showTextDocument(doc, {
                selection: range,
                preview: true
            });
        });
    }

    private async _handleAddTrust(data: any): Promise<void> {
        const workerClient = getWorkerClient();
        if (!workerClient) {
            void vscode.window.showErrorMessage('MSBuild Guard: Background worker is not available.');
            return;
        }

        const report = this._latestReport;
        if (!report) {
            void vscode.window.showErrorMessage('MSBuild Guard: No active scan report to trust findings from.');
            return;
        }

        try {
            const scope = data.scope; // "Finding", "Assembly", "Signer"
            const trustScope = data.trustScope; // "user", "solution", "project"
            const reason = data.reason || 'Approved via security review';
            const finding = data.finding as Finding;

            const targetPath = report.target.targetPath;

            if (scope === 'Finding') {
                await workerClient.addTrustAsync(targetPath, {
                    scope: 'Finding',
                    trustScope,
                    subjectHash: finding.fingerprint,
                    reason,
                    repositoryRemote: report.target.trustContext?.repositoryRemote || '',
                    branch: report.target.trustContext?.branch || '',
                    commitSha: report.target.trustContext?.commitSha || '',
                    policyProfile: report.policyProfile || ''
                });
            } else if (scope === 'Assembly') {
                const owning = finding.owningAssembly || `${finding.packageId}@${finding.packageVersion}`;
                if (!owning || owning === '@') {
                    void vscode.window.showErrorMessage('MSBuild Guard: Finding does not originate from a NuGet package asset.');
                    return;
                }
                const split = owning.split('@');
                const assemblyName = split[0];
                const assemblyVersion = split[1] || 'Unknown';

                await workerClient.addTrustAsync(targetPath, {
                    scope: 'Assembly',
                    trustScope,
                    assemblyName,
                    assemblyVersion,
                    reason,
                    assemblySigner: finding.packageSignatureState || '',
                    assemblyIssuer: '',
                    assemblySubject: ''
                });
            } else if (scope === 'Signer') {
                if (!finding.packageSignatureState) {
                    void vscode.window.showErrorMessage('MSBuild Guard: Finding signature state is empty.');
                    return;
                }
                await workerClient.addTrustAsync(targetPath, {
                    scope: 'Signer',
                    trustScope,
                    subjectHash: finding.packageSignatureState,
                    assemblySigner: finding.packageSignatureState,
                    reason
                });
            }

            void vscode.window.showInformationMessage(`Successfully added ${scope} trust to ${trustScope} store.`);
            // Automatically rescan solution to apply trust decisions instantly!
            void vscode.commands.executeCommand('msbuildguard.scan');
        } catch (err: any) {
            void vscode.window.showErrorMessage(`Failed to add trust: ${err.message}`);
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview): string {
        const onlyUntrusted = vscode.workspace.getConfiguration('msbuildguard').get<boolean>('onlyUntrustedIssues', false);
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSBuild Guard Review</title>
    <style>
        :root {
            --glass-bg: rgba(30, 41, 59, 0.45);
            --glass-border: rgba(255, 255, 255, 0.08);
            --glass-glow: rgba(0, 242, 254, 0.05);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --safe-color: #10b981;
            --warn-color: #f59e0b;
            --block-color: #ef4444;
            --accent-color: #00f2fe;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            background-color: var(--vscode-sideBar-background);
            color: var(--vscode-editor-foreground, var(--text-primary));
            font-family: var(--font-family);
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        #header-panel {
            padding: 12px 12px 6px 12px;
            flex: 0 0 auto;
        }

        #listPane {
            flex: 1 1 30%;
            overflow-y: auto;
            padding: 6px 12px 12px 12px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            min-height: 100px;
        }

        #divider {
            height: 1px;
            background: var(--vscode-panel-border, rgba(255, 255, 255, 0.08));
            flex: 0 0 auto;
            margin: 0 12px;
        }

        #detailPane {
            flex: 1 1 35%;
            overflow-y: auto;
            padding: 12px;
            background: rgba(15, 23, 42, 0.35);
            min-height: 120px;
            border-top: 1px solid var(--vscode-panel-border, rgba(255, 255, 255, 0.08));
        }

        /* Glassmorphism Panel card styling */
        .glass-panel {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 12px;
            padding: 14px;
            margin-bottom: 12px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }

        .header h2 {
            font-size: 1.1rem;
            margin: 0;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .header h2 span {
            color: var(--accent-color);
        }

        .risk-badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 20px;
            text-transform: uppercase;
        }

        .risk-safe { background: rgba(16, 185, 129, 0.15); color: var(--safe-color); border: 1px solid var(--safe-color); }
        .risk-warn { background: rgba(245, 158, 11, 0.15); color: var(--warn-color); border: 1px solid var(--warn-color); }
        .risk-block { background: rgba(239, 68, 68, 0.15); color: var(--block-color); border: 1px solid var(--block-color); }

        .status-badge {
            font-size: 0.6rem;
            font-weight: 700;
            padding: 1px 4px;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .status-trusted { background: rgba(16, 185, 129, 0.15); color: var(--safe-color); border: 1px solid var(--safe-color); }
        .status-block { background: rgba(239, 68, 68, 0.15); color: var(--block-color); border: 1px solid var(--block-color); }
        .status-requireapproval { background: rgba(245, 158, 11, 0.15); color: var(--warn-color); border: 1px solid var(--warn-color); }
        .status-warn { background: rgba(96, 165, 250, 0.15); color: #60a5fa; border: 1px solid #60a5fa; }
        .status-allow { background: rgba(16, 185, 129, 0.15); color: var(--safe-color); border: 1px solid var(--safe-color); }

        .widgets-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            margin-bottom: 12px;
        }

        .widget-card {
            background: rgba(15, 23, 42, 0.3);
            border: 1px solid var(--glass-border);
            border-radius: 8px;
            padding: 8px 10px;
            text-align: center;
        }

        .widget-value {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--accent-color);
            margin-bottom: 2px;
        }

        .widget-label {
            font-size: 0.65rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            letter-spacing: 0.5px;
        }

        .project-select {
            background: #1e293b;
            color: var(--text-primary);
            border: 1px solid var(--glass-border);
            border-radius: 6px;
            padding: 6px 8px;
            font-size: 0.8rem;
            outline: none;
        }

        .finding-item {
            background: rgba(15, 23, 42, 0.2);
            border-left: 4px solid var(--safe-color);
            padding: 10px;
            border-radius: 0 8px 8px 0;
            cursor: pointer;
            transition: all 0.2s ease;
            border-top: 1px solid var(--glass-border);
            border-right: 1px solid var(--glass-border);
            border-bottom: 1px solid var(--glass-border);
        }

        .finding-item:hover {
            background: rgba(255, 255, 255, 0.03);
            transform: translateX(2px);
        }

        .finding-item.selected {
            background: rgba(0, 242, 254, 0.08) !important;
            border-color: var(--accent-color) !important;
            border-left-width: 6px !important;
            box-shadow: 0 0 12px rgba(0, 242, 254, 0.06);
        }

        .finding-item.severity-critical { border-left-color: var(--block-color); }
        .finding-item.severity-high { border-left-color: var(--block-color); }
        .finding-item.severity-medium { border-left-color: var(--warn-color); }
        .finding-item.severity-low { border-left-color: #60a5fa; }

        .finding-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 4px;
        }

        .finding-id {
            font-size: 0.65rem;
            font-weight: 700;
            color: var(--text-secondary);
            background: rgba(255, 255, 255, 0.05);
            padding: 1px 4px;
            border-radius: 4px;
        }

        .finding-title {
            font-size: 0.82rem;
            font-weight: 600;
            margin: 0 0 4px 0;
            color: var(--text-primary);
        }

        .finding-path {
            font-size: 0.68rem;
            color: var(--text-secondary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .action-button {
            width: 100%;
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: #0f172a;
            border: none;
            border-radius: 6px;
            padding: 8px;
            font-weight: 700;
            font-size: 0.8rem;
            cursor: pointer;
            transition: opacity 0.2s;
        }

        .action-button:hover {
            opacity: 0.9;
        }

        .secondary-button {
            width: 100%;
            background: transparent;
            color: var(--text-primary);
            border: 1px solid var(--glass-border);
            border-radius: 6px;
            padding: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: background 0.2s;
        }

        .secondary-button:hover {
            background: rgba(255, 255, 255, 0.05);
            border-color: rgba(0, 242, 254, 0.3);
        }

        .empty-state {
            text-align: center;
            padding: 20px 10px;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }

        .empty-icon {
            font-size: 2rem;
            color: var(--safe-color);
            margin-bottom: 6px;
        }
    </style>
</head>
<body>
    <div id="header-panel">
        <div class="header">
            <h2>🛡️ MSBuild<span>Guard</span></h2>
            <span id="riskBadge" class="risk-badge risk-safe">Safe</span>
        </div>

        <div class="widgets-grid">
            <div class="widget-card">
                <div id="widgetScore" class="widget-value">0</div>
                <div class="widget-label">Risk Score</div>
            </div>
            <div class="widget-card">
                <div id="widgetVulns" class="widget-value">0</div>
                <div class="widget-label">Findings</div>
            </div>
        </div>

        <div style="margin-bottom: 10px; display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; gap: 6px;">
                <select id="projectFilter" class="project-select" style="flex: 1; width: 50%;">
                    <option value="all">All Solution Projects</option>
                </select>
                <select id="scopeFilter" class="project-select" style="flex: 1; width: 50%;">
                    <option value="all">All Scopes</option>
                    <option value="solution">Solution Level</option>
                    <option value="project">Project Level</option>
                </select>
            </div>
            <div style="display: flex; align-items: center; gap: 6px; padding: 2px 4px;">
                <input type="checkbox" id="untrustedFilter" style="cursor: pointer; width: 14px; height: 14px; margin: 0; accent-color: var(--accent-color);" />
                <label for="untrustedFilter" style="font-size: 0.72rem; color: var(--text-secondary); cursor: pointer; user-select: none;">Only untrusted issues</label>
            </div>
        </div>

        <button id="btnScan" class="action-button">⚡ Quick Scan Solution</button>
        <button id="btnBaseline" class="secondary-button" style="display:none; margin-top: 6px;">Create Baseline</button>

        <div style="border-top: 1px solid var(--glass-border); margin-top: 10px; padding-top: 8px;">
            <div style="display: flex; gap: 6px;">
                <button id="btnEditPolicy" class="secondary-button" style="margin: 0; flex: 1; font-size: 0.7rem; padding: 5px;">⚙️ Edit Policy</button>
                <button id="btnManageTrusts" class="secondary-button" style="margin: 0; flex: 1; font-size: 0.7rem; padding: 5px;">🔑 Trust Store</button>
            </div>
        </div>
    </div>

    <div id="divider"></div>

    <div id="listPane">
        <div class="empty-state">
            <div class="empty-icon">🛡️</div>
            <div>No scan results loaded. Click Scan above to begin project review.</div>
        </div>
    </div>

    <div id="detailPane">
        <div class="empty-state" style="padding-top: 40px;">
            <div class="empty-icon" style="color: var(--text-secondary); opacity: 0.6;">🔍</div>
            <div style="font-size: 0.78rem;">Select a finding from the list above to view details.</div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let currentFindings = [];
        let selectedIndex = null;
        let filterProject = 'all';
        let filterScope = 'all';
        let filterOnlyUntrusted = ${onlyUntrusted};

        function escapeHtml(unsafe) {
            if (!unsafe) return "";
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'updateReport') {
                renderReport(message.report);
            } else if (message.command === 'updateOnlyUntrustedSetting') {
                filterOnlyUntrusted = message.value;
                untrustedFilterEl.checked = filterOnlyUntrusted;
                applyFiltersAndRender();
            }
        });

        document.getElementById('btnScan').addEventListener('click', () => {
            vscode.postMessage({ command: 'scanWorkspace' });
        });

        document.getElementById('btnBaseline').addEventListener('click', () => {
            vscode.postMessage({ command: 'createBaseline' });
        });

        document.getElementById('btnEditPolicy').addEventListener('click', () => {
            vscode.postMessage({ command: 'editPolicy' });
        });

        document.getElementById('btnManageTrusts').addEventListener('click', () => {
            vscode.postMessage({ command: 'manageTrusts' });
        });

        const projectFilterEl = document.getElementById('projectFilter');
        const scopeFilterEl = document.getElementById('scopeFilter');
        const untrustedFilterEl = document.getElementById('untrustedFilter');

        projectFilterEl.addEventListener('change', (e) => {
            filterProject = e.target.value;
            applyFiltersAndRender();
        });

        scopeFilterEl.addEventListener('change', (e) => {
            filterScope = e.target.value;
            applyFiltersAndRender();
        });

        untrustedFilterEl.addEventListener('change', (e) => {
            filterOnlyUntrusted = e.target.checked;
            vscode.postMessage({ command: 'saveOnlyUntrustedSetting', value: filterOnlyUntrusted });
            applyFiltersAndRender();
        });

        function renderReport(report) {
            const score = report.riskScore;
            const action = report.recommendedAction.toLowerCase();

            document.getElementById('widgetScore').innerText = score;

            const badge = document.getElementById('riskBadge');
            badge.innerText = report.recommendedAction;
            badge.className = 'risk-badge';

            const btnBaseline = document.getElementById('btnBaseline');

            if (action === 'block' || action === 'requireapproval') {
                badge.className = 'risk-badge risk-block';
                btnBaseline.style.display = 'none';
            } else if (action === 'warn') {
                badge.className = 'risk-badge risk-warn';
                btnBaseline.style.display = 'block';
            } else {
                badge.className = 'risk-badge risk-safe';
                btnBaseline.style.display = 'block';
            }

            projectFilterEl.innerHTML = '<option value="all">All Solution Projects</option>';

            const projects = new Set();
            report.findings.forEach(f => {
                if (f.filePath) {
                    const parts = f.filePath.split(/[\\\\/]/);
                    const filename = parts[parts.length - 1];
                    if (filename.endsWith('.csproj') || filename.endsWith('.fsproj') || filename.endsWith('.vbproj')) {
                        projects.add(filename);
                    }
                }
            });

            projects.forEach(proj => {
                const opt = document.createElement('option');
                opt.value = proj;
                opt.innerText = proj;
                projectFilterEl.appendChild(opt);
            });

            currentFindings = report.findings;
            selectedIndex = null; 
            
            projectFilterEl.value = filterProject;
            scopeFilterEl.value = filterScope;
            untrustedFilterEl.checked = filterOnlyUntrusted;

            applyFiltersAndRender();
        }

        function applyFiltersAndRender() {
            const listPane = document.getElementById('listPane');
            listPane.innerHTML = '';

            let filtered = currentFindings;

            if (filterProject !== 'all') {
                filtered = filtered.filter(f => f.filePath && f.filePath.endsWith(filterProject));
            }

            if (filterScope === 'solution') {
                filtered = filtered.filter(f => f.filePath && (f.filePath.endsWith('.sln') || f.filePath.endsWith('.slnx')));
            } else if (filterScope === 'project') {
                filtered = filtered.filter(f => f.filePath && !(f.filePath.endsWith('.sln') || f.filePath.endsWith('.slnx')));
            }

            if (filterOnlyUntrusted) {
                filtered = filtered.filter(f => !f.isTrusted && f.policyAction.toLowerCase() !== 'allow');
            }

            document.getElementById('widgetVulns').innerText = filtered.length;

            if (filtered.length === 0) {
                listPane.innerHTML = \`
                    <div class="empty-state" style="padding-top: 30px;">
                        <div class="empty-icon" style="color: var(--safe-color);">🛡️</div>
                        <div style="font-size: 0.78rem;">No findings match active filters.</div>
                    </div>
                \`;
                renderDetails(null);
                return;
            }

            filtered.forEach((finding) => {
                const item = document.createElement('div');
                const isSelected = selectedIndex !== null && currentFindings[selectedIndex] && currentFindings[selectedIndex].fingerprint === finding.fingerprint;
                
                item.className = 'finding-item severity-' + finding.severity.toLowerCase() + (isSelected ? ' selected' : '');

                const parts = finding.filePath.split(/[\\\\/]/);
                const basename = parts[parts.length - 1];
                const isTrusted = finding.isTrusted || finding.policyAction.toLowerCase() === 'allow';
                
                let statusBadge = '';
                if (isTrusted) {
                    statusBadge = '<span class="status-badge status-trusted">🛡️ Trusted</span>';
                } else {
                    const actionClass = 'status-' + finding.policyAction.toLowerCase();
                    statusBadge = \`<span class="status-badge \${actionClass}">\${finding.policyAction}</span>\`;
                }

                item.innerHTML = \`
                    <div class="finding-header">
                        <span class="finding-id">\${finding.id}</span>
                        \${statusBadge}
                    </div>
                    <div class="finding-title">\${finding.title}</div>
                    <div class="finding-path">📍 \${basename}:L\${finding.startLine}</div>
                \`;

                item.addEventListener('click', () => {
                    const originalIdx = currentFindings.findIndex(f => f.fingerprint === finding.fingerprint);
                    selectedIndex = originalIdx;
                    applyFiltersAndRender();
                });

                item.addEventListener('dblclick', () => {
                    vscode.postMessage({
                        command: 'openFile',
                        filePath: finding.filePath,
                        startLine: finding.startLine,
                        startColumn: finding.startColumn
                    });
                });

                listPane.appendChild(item);
            });

            if (selectedIndex !== null && currentFindings[selectedIndex]) {
                const isFilteredOut = !filtered.some(f => f.fingerprint === currentFindings[selectedIndex].fingerprint);
                if (isFilteredOut) {
                    renderDetails(null);
                } else {
                    renderDetails(currentFindings[selectedIndex]);
                }
            } else {
                renderDetails(null);
            }
        }

        function renderDetails(finding) {
            const pane = document.getElementById('detailPane');
            
            if (!finding) {
                pane.innerHTML = \`
                    <div class="empty-state" style="padding-top: 40px;">
                        <div class="empty-icon" style="color: var(--text-secondary); opacity: 0.6;">🔍</div>
                        <div style="font-size: 0.78rem;">Select a finding from the list above to view details.</div>
                    </div>
                \`;
                return;
            }

            const parts = finding.filePath.split(/[\\\\/]/);
            const basename = parts[parts.length - 1];
            const isTrusted = finding.isTrusted || finding.policyAction.toLowerCase() === 'allow';

            let trustManagementSection = '';
            if (isTrusted) {
                trustManagementSection = \`
                    <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 12px; text-align: center; margin-top: 10px;">
                        <div style="color: var(--safe-color); font-weight: 700; font-size: 0.8rem; display: flex; align-items: center; justify-content: center; gap: 6px; margin-bottom: 4px;">
                            🛡️ Already Trusted
                        </div>
                        <div style="font-size: 0.72rem; color: var(--text-primary); line-height: 1.4;">
                            This finding is approved under the active policy.<br/>
                            <span style="font-style: italic; color: var(--text-secondary);">Reason: \${finding.policyActionReason || 'No reason specified'}</span>
                        </div>
                    </div>
                \`;
            } else {
                trustManagementSection = \`
                    <div style="border-top: 1px solid var(--glass-border); padding-top: 8px; font-size: 0.72rem;">
                        <div style="font-weight: 700; text-transform: uppercase; margin-bottom: 6px; color: var(--accent-color);">🛡️ Trust Management</div>
                        
                        <div style="margin-bottom: 6px;">
                            <label style="display: block; font-weight: 600; color: var(--text-secondary); margin-bottom: 2px;">Trust Reason:</label>
                            <input id="trust-reason" type="text" value="Approved via security review" style="width: calc(100% - 12px); background: #0f172a; color: var(--text-primary); border: 1px solid var(--glass-border); border-radius: 4px; padding: 4px 6px; font-size: 0.72rem; outline: none;"/>
                        </div>

                        <div style="margin-bottom: 8px;">
                            <label style="display: block; font-weight: 600; color: var(--text-secondary); margin-bottom: 2px;">Trust Scope:</label>
                            <select id="trust-scope" style="width: 100%; background: #0f172a; color: var(--text-primary); border: 1px solid var(--glass-border); border-radius: 4px; padding: 4px; font-size: 0.72rem; outline: none;">
                                <option value="user">User Store (Global)</option>
                                <option value="solution">Solution Store (.msbuildguard/trust.json)</option>
                                <option value="project">Project Store (.msbuildguard/trust.json)</option>
                            </select>
                        </div>

                        <div style="display: flex; flex-direction: column; gap: 4px;">
                            <button onclick="submitTrust('Finding')" class="secondary-button" style="text-align: left; padding: 6px; margin: 0; font-size: 0.7rem; font-weight: 600; display: flex; align-items: center; gap: 4px; background: rgba(0, 242, 254, 0.08); border-color: rgba(0, 242, 254, 0.25);">
                                🛡️ Trust Finding Issue
                            </button>
                            
                            \${finding.packageId ? \`
                            <button onclick="submitTrust('Assembly')" class="secondary-button" style="text-align: left; padding: 6px; margin: 0; font-size: 0.7rem; font-weight: 600; display: flex; align-items: center; gap: 4px; background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.25);">
                                📦 Trust NuGet Assembly
                            </button>
                            \` : ''}

                            \${finding.packageSignatureState ? \`
                            <button onclick="submitTrust('Signer')" class="secondary-button" style="text-align: left; padding: 6px; margin: 0; font-size: 0.7rem; font-weight: 600; display: flex; align-items: center; gap: 4px; background: rgba(245, 158, 11, 0.08); border-color: rgba(245, 158, 11, 0.25);">
                                ✍️ Trust Signer Certificate
                            </button>
                            \` : ''}
                        </div>
                    </div>
                \`;
            }

            pane.innerHTML = \`
                <div style="text-align: left; padding: 2px;">
                    <div style="font-weight: 700; font-size: 0.85rem; color: var(--accent-color); margin-bottom: 6px;">
                        Rule \${finding.id} — \${finding.title}
                    </div>
                    
                    <div id="fileLink" style="font-size: 0.7rem; color: var(--text-secondary); cursor: pointer; text-decoration: underline; margin-bottom: 8px; display: inline-block;">
                        📍 \${basename}:L\${finding.startLine}
                    </div>

                    <div style="margin-bottom: 10px; line-height: 1.4; color: var(--text-primary); font-size: 0.75rem;">
                        \${finding.description}
                    </div>

                    \${finding.recommendation ? \`
                    <div style="font-weight: 700; font-size: 0.68rem; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 2px;">Recommendation</div>
                    <div style="margin-bottom: 10px; color: var(--text-primary); font-size: 0.73rem;">\${finding.recommendation}</div>
                    \` : ''}

                    \${finding.evidence ? \`
                    <div style="font-weight: 700; font-size: 0.68rem; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 2px;">Evidence</div>
                    <div style="margin-bottom: 10px; font-family: monospace; background: rgba(0,0,0,0.25); padding: 4px 6px; border-radius: 4px; color: #f43f5e; font-size: 0.68rem; word-break: break-all;">\${escapeHtml(finding.evidence)}</div>
                    \` : ''}

                    \${finding.packageId ? \`
                    <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--glass-border); padding: 8px; border-radius: 6px; margin-bottom: 10px; font-size: 0.7rem;">
                        <div style="font-weight: 700; color: var(--accent-color); margin-bottom: 4px;">NuGet Package Context</div>
                        <div style="color: var(--text-primary); margin-bottom: 2px;">📦 <strong>\${finding.packageId} \${finding.packageVersion}</strong></div>
                        \${finding.packageSource ? \`<div style="color: var(--text-secondary); margin-bottom: 2px;">Source: \${finding.packageSource} \${finding.isPackageSourceInferred ? '(inferred)' : ''}</div>\` : ''}
                        \${finding.packageSignatureState ? \`<div style="color: var(--text-secondary); margin-bottom: 2px;">Signature: \${finding.packageSignatureState}</div>\` : ''}
                        \${finding.introducedViaProject ? \`<div style="color: var(--text-secondary);">Via Project: \${finding.introducedViaProject}</div>\` : ''}
                    </div>
                    \` : ''}

                    <div style="border-top: 1px solid var(--glass-border); padding-top: 8px; margin-bottom: 12px; font-size: 0.68rem; color: var(--text-secondary);">
                        <div style="font-weight: 700; text-transform: uppercase; margin-bottom: 4px; color: var(--text-secondary);">Policy Evaluation</div>
                        <div>Default scanner action: <span style="color: var(--text-primary);">\${finding.scannerPolicyAction || 'Allow'}</span></div>
                        <div>Effective policy action: <span style="color: var(--accent-color); font-weight: 600;">\${finding.policyAction}</span></div>
                        \${finding.policyActionReason ? \`<div style="margin-top: 2px; font-style: italic;">Reason: \${finding.policyActionReason}</div>\` : ''}
                    </div>

                    \${trustManagementSection}
                </div>
            \`;

            document.getElementById('fileLink').addEventListener('click', () => {
                vscode.postMessage({
                    command: 'openFile',
                    filePath: finding.filePath,
                    startLine: finding.startLine,
                    startColumn: finding.startColumn
                });
            });
        }

        window.submitTrust = function(scope) {
            const reason = document.getElementById('trust-reason').value;
            const trustScope = document.getElementById('trust-scope').value;
            const finding = currentFindings[selectedIndex];

            vscode.postMessage({
                command: 'addTrust',
                scope,
                trustScope,
                reason,
                finding
            });
        };
    </script>
</body>
</html>
`;
    }
}
