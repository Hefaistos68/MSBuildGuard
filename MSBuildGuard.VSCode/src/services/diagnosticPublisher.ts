import * as vscode from 'vscode';
import { ScanReport, Finding } from './workerClient';

export class DiagnosticPublisher implements vscode.Disposable {
    private readonly collection: vscode.DiagnosticCollection;

    public constructor() {
        this.collection = vscode.languages.createDiagnosticCollection('msbuildguard');
    }

    /**
     * Publishes inline diagnostics for the given scan report findings.
     * Clears previous diagnostics before publishing.
     */
    public publish(report: ScanReport): void {
        this.collection.clear();

        const fileDiagnostics = new Map<string, vscode.Diagnostic[]>();

        for (const finding of report.findings) {
            if (!finding.filePath) {
                continue;
            }

            const diagnostics = fileDiagnostics.get(finding.filePath) || [];

            // Convert 1-based editor coordinates to 0-based VS Code Range coordinates
            const startLine = Math.max(0, finding.startLine - 1);
            const startCol = Math.max(0, finding.startColumn - 1);
            const endLine = Math.max(0, finding.endLine - 1);
            const endCol = Math.max(startCol, finding.endColumn - 1);

            const range = new vscode.Range(
                new vscode.Position(startLine, startCol),
                new vscode.Position(endLine, endCol === startCol ? 120 : endCol) // Default to standard line length if empty column
            );

            const severity = this.mapSeverity(finding.severity);

            const message = `[MSBuild Guard: ${finding.id}] ${finding.title}\n\nSeverity: ${finding.severity}\nAction: ${finding.policyAction}\n\nDescription: ${finding.description}\n\nReasoning: ${finding.policyActionReason}`;

            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.code = finding.id;
            diagnostic.source = 'MSBuild Guard';

            diagnostics.push(diagnostic);
            fileDiagnostics.set(finding.filePath, diagnostics);
        }

        // Set diagnostics grouped by absolute file paths
        for (const [filePath, diagnostics] of fileDiagnostics.entries()) {
            const uri = vscode.Uri.file(filePath);
            this.collection.set(uri, diagnostics);
        }
    }

    /**
     * Clears all published diagnostics.
     */
    public clear(): void {
        this.collection.clear();
    }

    public dispose(): void {
        this.collection.dispose();
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }
}
