import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

export interface Finding {
    id: string;
    title: string;
    description: string;
    filePath: string;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
    severity: string;
    policyAction: string;
    policyActionReason: string;
    fingerprint: string;
    fileHasMarkOfTheWeb: boolean;
    isInFileImportedByMultipleProjects: boolean;
    isNewComparedWithBaseline: boolean;
    packageId?: string;
    packageVersion?: string;
    packageSource?: string;
    packageSignatureState?: string;
    isTransitivePackage?: boolean;
    nuGetAssetPath?: string;
    introducedViaProject?: string;
    scannerPolicyAction?: string;
    policyEvaluatedAction?: string;
    confidence?: string;
    recommendation?: string;
    evidence?: string;
    owningAssembly?: string;
    isTrusted?: boolean;
}

export interface ScanReport {
    scannerVersion: string;
    completedAtUtc: string;
    target: {
        targetPath: string;
        targetKind: string;
        trustContext?: {
            isRepositoryTrusted: boolean;
            isMarkOfTheWebTrusted: boolean;
            isBaselineTrusted: boolean;
            policyProfile: string;
            repositoryRemote: string;
            branch: string;
            commitSha: string;
        };
    };
    riskScore: number;
    recommendedAction: string;
    findings: Finding[];
    filesScanned: {
        path: string;
        normalizedSha256: string;
    }[];
    policyProfile?: string;
    baselineComparison?: {
        driftDetected: boolean;
        hasBaseline: boolean;
        summary: string;
    };
}

interface WorkerRequest {
    version: string;
    id: string;
    method: string;
    payload: {
        targetPath: string;
        fileTypesToScan?: string[];
        processCreationIndicators?: string[];
        reflectionInteropIndicators?: string[];
        additionalBlockedAssemblies?: string[];
        reviewerIdentity?: string;
        outputPath?: string;
        policy?: any;
        trustScope?: string;
        scope?: string;
        subjectHash?: string;
        reason?: string;
    };
}

interface WorkerResponse {
    version: string;
    id: string;
    success: boolean;
    result?: any;
    error?: {
        code: string;
        message: string;
        details?: string;
    };
}

export class WorkerClient implements vscode.Disposable {
    private readonly process: cp.ChildProcessWithoutNullStreams;
    private readonly pending = new Map<string, {
        resolve: (value: WorkerResponse) => void;
        reject: (reason: Error) => void;
        timer: NodeJS.Timeout;
    }>();
    private readonly outputBuffer: string[] = [];
    private sequence = 0;
    private disposed = false;

    public constructor(context: vscode.ExtensionContext) {
        const packagedWorkerDll = path.resolve(context.extensionPath, 'dist', 'worker', 'MSBuildGuard.Worker.dll');
        const workerProject = path.resolve(context.extensionPath, '..', 'MSBuildGuard.Worker', 'MSBuildGuard.Worker.csproj');
        const workerArgs = this.getWorkerLaunchArguments(packagedWorkerDll, workerProject);
        const config = vscode.workspace.getConfiguration('msbuildguard');
        const enforceAsymmetric = config.get<boolean>('enforceAsymmetricSignatures', false);
        const allowSharing = config.get<boolean>('trustManagement.allowSharingTrustsInRepositories', false);
        const spawnEnv = {
            ...process.env,
            MSBUILDGUARD_ENFORCE_ASYMMETRIC_SIGNATURES: String(enforceAsymmetric),
            MSBUILDGUARD_ALLOW_SHARING_TRUSTS: String(allowSharing)
        };

        this.process = cp.spawn('dotnet', workerArgs, {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: spawnEnv
        });

        this.process.stdout.on('data', (data: Buffer) => {
            this.onStdOutData(data.toString());
        });

        this.process.stderr.on('data', (data: Buffer) => {
            // Log background diagnostics from stderr
            console.warn(`MSBuildGuard worker: ${data.toString().trim()}`);
        });

        this.process.on('exit', (code: number | null, signal: NodeJS.Signals | null) => {
            this.failAllPending(`MSBuildGuard worker exited (code=${code}, signal=${signal}).`);
        });
    }

    public async scanAsync(targetPath: string, options: {
        fileTypesToScan?: string[];
        processCreationIndicators?: string[];
        reflectionInteropIndicators?: string[];
        additionalBlockedAssemblies?: string[];
    }, timeoutMs = 30000): Promise<ScanReport> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'scan',
            payload: {
                targetPath,
                fileTypesToScan: options.fileTypesToScan,
                processCreationIndicators: options.processCreationIndicators,
                reflectionInteropIndicators: options.reflectionInteropIndicators,
                additionalBlockedAssemblies: options.additionalBlockedAssemblies
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success || !response.result) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Scan failed: ${message}`);
        }

        return response.result as ScanReport;
    }

    public async getOnboardingSuggestionsAsync(targetPath: string, options: {
        fileTypesToScan?: string[];
        processCreationIndicators?: string[];
        reflectionInteropIndicators?: string[];
        additionalBlockedAssemblies?: string[];
    }, timeoutMs = 30000): Promise<any[]> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'getOnboardingSuggestions',
            payload: {
                targetPath,
                fileTypesToScan: options.fileTypesToScan,
                processCreationIndicators: options.processCreationIndicators,
                reflectionInteropIndicators: options.reflectionInteropIndicators,
                additionalBlockedAssemblies: options.additionalBlockedAssemblies
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success || !response.result) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Failed to retrieve onboarding suggestions: ${message}`);
        }

        return response.result as any[];
    }

    public async createBaselineAsync(targetPath: string, reviewerIdentity: string, outputPath: string, timeoutMs = 30000): Promise<void> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'createBaseline',
            payload: {
                targetPath,
                reviewerIdentity,
                outputPath
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Create baseline failed: ${message}`);
        }
    }

    public async addTrustAsync(targetPath: string, options: {
        trustScope: string;
        scope: string;
        subjectHash?: string;
        reason?: string;
        assemblyName?: string;
        assemblyVersion?: string;
        assemblySigner?: string;
        assemblyIssuer?: string;
        assemblySubject?: string;
        assemblyThumbprint?: string;
        assemblySerialNumber?: string;
        repositoryRemote?: string;
        branch?: string;
        commitSha?: string;
        policyProfile?: string;
        expiresAtUtc?: string;
    }, timeoutMs = 30000): Promise<any> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'addTrust',
            payload: {
                targetPath,
                ...options
            } as any
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Add trust failed: ${message}`);
        }

        return response.result;
    }

    public async getPolicyAsync(targetPath: string, timeoutMs = 30000): Promise<any> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'getPolicy',
            payload: {
                targetPath
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success || !response.result) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Get policy failed: ${message}`);
        }

        return response.result;
    }

    public async savePolicyAsync(targetPath: string, policy: any, timeoutMs = 30000): Promise<any> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'savePolicy',
            payload: {
                targetPath,
                policy
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Save policy failed: ${message}`);
        }

        return response.result;
    }

    public async getTrustStoreAsync(targetPath: string, trustScope: string, timeoutMs = 30000): Promise<any> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'getTrustStore',
            payload: {
                targetPath,
                trustScope
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success || !response.result) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Get trust store failed: ${message}`);
        }

        return response.result;
    }

    public async removeTrustAsync(targetPath: string, trustScope: string, subjectHash: string, reason?: string, timeoutMs = 30000): Promise<any> {
        if (this.disposed) {
            throw new Error('MSBuildGuard worker client is disposed.');
        }

        const id = `req-${++this.sequence}`;
        const request: WorkerRequest = {
            version: '1.0',
            id,
            method: 'removeTrust',
            payload: {
                targetPath,
                trustScope,
                subjectHash,
                reason
            }
        };

        const response = await this.sendAsync(request, timeoutMs);
        if (!response.success) {
            const message = response.error?.details
                ? `${response.error.message} (${response.error.details})`
                : (response.error?.message ?? 'Worker returned an unknown failure.');
            throw new Error(`Remove trust failed: ${message}`);
        }

        return response.result;
    }

    public dispose(): void {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        this.failAllPending('MSBuildGuard worker client disposed.');
        this.process.kill();
    }

    private async sendAsync(request: WorkerRequest, timeoutMs: number): Promise<WorkerResponse> {
        const responseTask = new Promise<WorkerResponse>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(request.id);
                reject(new Error(`MSBuildGuard worker request timed out after ${timeoutMs} ms.`));
            }, timeoutMs);

            this.pending.set(request.id, { resolve, reject, timer });
        });

        this.process.stdin.write(`${JSON.stringify(request)}\n`);

        return responseTask;
    }

    private getWorkerLaunchArguments(packagedWorkerDll: string, workerProject: string): string[] {
        if (this.fileExists(packagedWorkerDll)) {
            return [packagedWorkerDll];
        }

        return ['run', '--project', workerProject];
    }

    private fileExists(filePath: string): boolean {
        try {
            return fs.existsSync(filePath);
        } catch {
            return false;
        }
    }

    private onStdOutData(chunk: string): void {
        this.outputBuffer.push(chunk);
        const combined = this.outputBuffer.join('');
        const lines = combined.split(/\r?\n/);

        this.outputBuffer.length = 0;
        if (!combined.endsWith('\n')) {
            this.outputBuffer.push(lines.pop() ?? '');
        }

        for (const line of lines) {
            if (!line.trim()) {
                continue;
            }

            let response: WorkerResponse;
            try {
                response = JSON.parse(line) as WorkerResponse;
            } catch {
                continue;
            }

            const pending = this.pending.get(response.id);
            if (!pending) {
                continue;
            }

            clearTimeout(pending.timer);
            this.pending.delete(response.id);
            pending.resolve(response);
        }
    }

    private failAllPending(message: string): void {
        for (const entry of this.pending.values()) {
            clearTimeout(entry.timer);
            entry.reject(new Error(message));
        }

        this.pending.clear();
    }
}
