import * as vscode from 'vscode';
import { ScanReport } from './workerClient';

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

        const action = this.latestReport.recommendedAction.toLowerCase();
        const requiresEnforcement = action === 'block' || action === 'requireapproval';

        if (!requiresEnforcement) {
            return;
        }

        const isBlockMode = action === 'block';

        // High-value interactive freezing prompt
        const score = this.latestReport.riskScore;
        const promptMessage = isBlockMode
            ? `[MSBuild Guard] CRITICAL: Build blocked by security policy. Risk Score: ${score}. Risky configuration identified.`
            : `[MSBuild Guard] ALERT: Risky MSBuild configurations detected. Risk Score: ${score}. Do you want to allow this build to run?`;

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
}
