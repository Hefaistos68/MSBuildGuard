import * as path from 'path';
import * as vscode from 'vscode';
import { ScanReport, Finding } from './workerClient';

export class BuildEnforcer implements vscode.Disposable {
    private readonly disposables: vscode.Disposable[] = [];
    private latestReport: ScanReport | null = null;
    private approvedTaskKey: string | null = null;

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
        const task = event.execution.task;
        const taskKey = `${task.source}:${task.name}`;

        if (!this.isBuildOrDotnetTask(task)) {
            return;
        }

        if (this.approvedTaskKey === taskKey) {
            this.approvedTaskKey = null;
            return;
        }

        if (!this.latestReport) {
            // No scan has run yet; trigger a scan in the background
            void vscode.commands.executeCommand('msbuildguard.scan');
            return;
        }

        // Resolve target project/solution paths from the VS Code task
        const projectPaths = this.getProjectPathsFromTask(task);
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
            const evaluatedAction = (finding.policyEvaluatedAction || finding.policyAction || '').toLowerCase();
            return !isTrusted && evaluatedAction !== 'allow';
        });

        if (activeFindings.length === 0) {
            return;
        }

        // Calculate risk score and effective policy action for filtered findings
        let riskScore = 0;
        let highestPolicyRank = 0;

        for (const finding of activeFindings) {
            riskScore += this.getSeverityRisk(finding.severity);
            const evaluatedAction = (finding.policyEvaluatedAction || finding.policyAction || '').toLowerCase();
            const rank = this.getActionRank(evaluatedAction);
            if (rank > highestPolicyRank) {
                highestPolicyRank = rank;
            }
        }

        let riskRank = 0;
        if (riskScore >= 100) {
            riskRank = 3;
        } else if (riskScore >= 50) {
            riskRank = 2;
        } else if (riskScore >= 20) {
            riskRank = 1;
        }

        const effectiveRank = Math.max(riskRank, highestPolicyRank);
        const requiresEnforcement = effectiveRank >= 2;

        if (!requiresEnforcement) {
            return;
        }

        const isBlockMode = effectiveRank >= 3;

        // Always terminate immediately so MSBuild cannot execute before user approval
        event.execution.terminate();

        const promptMessage = isBlockMode
            ? `[MSBuild Guard] CRITICAL: Build blocked by security policy. Risk Score: ${riskScore}. Risky configuration identified.`
            : `[MSBuild Guard] ALERT: Risky MSBuild configurations detected. Risk Score: ${riskScore}. Do you want to allow this build to run?`;

        if (isBlockMode) {
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
            const choice = await vscode.window.showWarningMessage(
                promptMessage,
                { modal: true },
                'Allow & Continue Build',
                'Block & Cancel Build'
            );

            if (choice !== 'Allow & Continue Build') {
                void vscode.window.showInformationMessage('Build cancelled and terminated by MSBuild Guard.');
            } else {
                this.approvedTaskKey = taskKey;
                void vscode.tasks.executeTask(task);
            }
        }
    }

    private isBuildOrDotnetTask(task: vscode.Task): boolean {
        const taskName = task.name.toLowerCase();
        const taskSource = task.source.toLowerCase();

        if (
            taskName.includes('build') ||
            taskName.includes('restore') ||
            taskName.includes('publish') ||
            taskName.includes('test') ||
            taskName.includes('run') ||
            taskName.includes('pack') ||
            taskName.includes('clean') ||
            taskSource.includes('dotnet') ||
            taskSource.includes('msbuild')
        ) {
            return true;
        }

        const execution = task.execution;
        if (execution) {
            if ('process' in execution && typeof execution.process === 'string') {
                const proc = execution.process.toLowerCase();
                if (proc.includes('dotnet') || proc.includes('msbuild')) {
                    return true;
                }
            }
            if ('commandLine' in execution && typeof execution.commandLine === 'string') {
                const cmd = execution.commandLine.toLowerCase();
                if (cmd.includes('dotnet') || cmd.includes('msbuild')) {
                    return true;
                }
            }
            if ('command' in execution) {
                const cmdVal = typeof execution.command === 'string' ? execution.command : (execution.command?.value || '');
                const cmdLower = cmdVal.toLowerCase();
                if (cmdLower.includes('dotnet') || cmdLower.includes('msbuild')) {
                    return true;
                }
            }
        }

        return false;
    }

    private getActionRank(action: string): number {
        switch (action) {
            case 'block': return 3;
            case 'requireapproval': return 2;
            case 'warn': return 1;
            default: return 0;
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
