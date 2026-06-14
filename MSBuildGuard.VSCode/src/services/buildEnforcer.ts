import * as path from 'path';
import * as vscode from 'vscode';
import { ScanReport, Finding } from './workerClient';

export class BuildEnforcer implements vscode.Disposable {
    private readonly disposables: vscode.Disposable[] = [];
    private latestReport: ScanReport | null = null;
    private bypassActive = false;

    public constructor() {
        this.disposables.push(
            vscode.tasks.onDidStartTask(async (event) => {
                await this.onTaskStarted(event);
            })
        );
    }

    /**
     * Updates the latest scan report used to evaluate builds.
     */
    public updateReport(report: ScanReport | null): void {
        this.latestReport = report;
    }

    public dispose(): void {
        for (const d of this.disposables) {
            d.dispose();
        }
    }

    private async onTaskStarted(event: vscode.TaskStartEvent): Promise<void> {
        const taskName = event.execution.task.name.toLowerCase();
        const taskSource = event.execution.task.source.toLowerCase();

        // Detect .NET compile or build tasks
        const isBuildTask = 
            taskName.includes('build') || 
            taskName.includes('restore') || 
            taskName.includes('publish') ||
            taskSource.includes('dotnet') ||
            taskSource.includes('msbuild');

        if (!isBuildTask || this.bypassActive) {
            return;
        }

        if (!this.latestReport) {
            // No scan has run yet; we allow standard execution but trigger a background scan
            return;
        }

        // Resolve target project/solution paths from the VS Code task
        const projectPaths = this.getProjectPathsFromTask(event.execution.task);
        let filteredFindings = this.latestReport.findings;

        if (projectPaths.length > 0) {
            const solutionPath = this.latestReport.target.targetPath;
            filteredFindings = this.latestReport.findings.filter(finding => 
                projectPaths.some(projPath => this.isFindingForProject(finding, projPath, solutionPath))
            );
        }

        // Filter active findings (not trusted and policy requires action)
        const activeFindings = filteredFindings.filter(finding => {
            const isTrusted = finding.isTrusted || false;
            return !isTrusted && finding.policyEvaluatedAction?.toLowerCase() !== 'allow';
        });

        if (activeFindings.length === 0) {
            return;
        }

        // Calculate risk score and action for filtered findings
        let riskScore = 0;
        for (const finding of activeFindings) {
            riskScore += this.getSeverityRisk(finding.severity);
        }

        let action = 'allow';
        if (riskScore >= 100) {
            action = 'block';
        } else if (riskScore >= 50) {
            action = 'requireapproval';
        } else if (riskScore >= 20) {
            action = 'warn';
        }

        const requiresEnforcement = action === 'block' || action === 'requireapproval';

        if (!requiresEnforcement) {
            return;
        }

        const isBlockMode = action === 'block';

        // High-value interactive freezing prompt
        const promptMessage = isBlockMode
            ? `[MSBuild Guard] CRITICAL: Build blocked by security policy. Risk Score: ${riskScore}. Risky configuration identified.`
            : `[MSBuild Guard] ALERT: Risky MSBuild configurations detected. Risk Score: ${riskScore}. Do you want to allow this build to run?`;

        if (isBlockMode) {
            // Strict Block Mode: Terminate instantly and notify
            event.execution.terminate();
            await vscode.window.showErrorMessage(
                `${promptMessage}\n\nPlease review findings in the Security Review dashboard.`,
                { modal: true },
                'Open Security Review'
            ).then((choice) => {
                if (choice === 'Open Security Review') {
                    void vscode.commands.executeCommand('msbuildguard.showReview');
                }
            });
        } else {
            // Conditional Approval Mode: Freeze task (keep it running but prompt, terminate if cancelled)
            const choice = await vscode.window.showWarningMessage(
                promptMessage,
                { modal: true },
                'Allow & Continue Build',
                'Block & Cancel Build'
            );

            if (choice !== 'Allow & Continue Build') {
                event.execution.terminate();
                void vscode.window.showInformationMessage('Build cancelled and terminated by MSBuild Guard.');
            } else {
                // Allow task to continue
                this.bypassActive = true;
                setTimeout(() => {
                    this.bypassActive = false; // Reset bypass window
                }, 5000);
            }
        }
    }

    private getProjectPathsFromTask(task: vscode.Task): string[] {
        const paths: string[] = [];

        if (task.definition) {
            if (typeof task.definition.project === 'string') {
                paths.push(task.definition.project);
            } else if (typeof task.definition.file === 'string') {
                paths.push(task.definition.file);
            }
        }

        const execution = task.execution;
        if (execution) {
            let args: string[] = [];
            if ('args' in execution && Array.isArray(execution.args)) {
                args = execution.args.map(arg => typeof arg === 'string' ? arg : (arg.value || ''));
            } else if ('commandLine' in execution && typeof execution.commandLine === 'string') {
                const commandLine = execution.commandLine;
                const regex = /"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s]+/g;
                const matches = commandLine.match(regex);
                if (matches) {
                    args = matches.map(arg => {
                        if ((arg.startsWith('"') && arg.endsWith('"')) || (arg.startsWith("'") && arg.endsWith("'"))) {
                            return arg.slice(1, -1);
                        }
                        return arg;
                    });
                }
            }

            for (const arg of args) {
                if (
                    arg.endsWith('.csproj') || 
                    arg.endsWith('.vbproj') || 
                    arg.endsWith('.fsproj') || 
                    arg.endsWith('.proj') || 
                    arg.endsWith('.sln') || 
                    arg.endsWith('.slnx')
                ) {
                    paths.push(arg);
                }
            }
        }

        const resolvedPaths: string[] = [];
        const workspaceFolders = vscode.workspace.workspaceFolders;
        const rootPath = workspaceFolders && workspaceFolders.length > 0 ? workspaceFolders[0].uri.fsPath : '';

        for (const p of paths) {
            if (path.isAbsolute(p)) {
                resolvedPaths.push(path.normalize(p));
            } else if (rootPath) {
                resolvedPaths.push(path.normalize(path.join(rootPath, p)));
            }
        }

        return resolvedPaths;
    }

    private isFindingForProject(finding: Finding, projectPath: string, solutionPath: string | null): boolean {
        if (!projectPath) {
            return false;
        }

        const normalizedProject = path.normalize(projectPath).toLowerCase();

        // 1. Check IntroducedViaProject
        if (finding.introducedViaProject) {
            let absoluteFindingProjectPath = finding.introducedViaProject;
            if (!path.isAbsolute(absoluteFindingProjectPath) && solutionPath) {
                absoluteFindingProjectPath = path.join(path.dirname(solutionPath), absoluteFindingProjectPath);
            }
            if (path.normalize(absoluteFindingProjectPath).toLowerCase() === normalizedProject) {
                return true;
            }
        }

        // 2. Check FilePath
        if (finding.filePath) {
            const absoluteFilePath = path.isAbsolute(finding.filePath)
                ? path.normalize(finding.filePath).toLowerCase()
                : path.normalize(path.join(path.dirname(solutionPath || ''), finding.filePath)).toLowerCase();

            if (absoluteFilePath === normalizedProject) {
                return true;
            }

            const projectDir = path.dirname(normalizedProject);
            if (projectDir) {
                const projectDirNormalized = projectDir.endsWith(path.sep) ? projectDir : projectDir + path.sep;
                if (absoluteFilePath.startsWith(projectDirNormalized)) {
                    return true;
                }
            }
        }

        return false;
    }

    private getSeverityRisk(severity: string): number {
        switch (severity?.toLowerCase()) {
            case 'critical': return 100;
            case 'high': return 50;
            case 'medium': return 20;
            case 'low': return 5;
            default: return 0;
        }
    }
}
