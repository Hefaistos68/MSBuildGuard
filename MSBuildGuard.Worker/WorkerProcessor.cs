using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Baseline;
using MSBuildGuard.Core.Policy;
using MSBuildGuard.Core.Scanning;
using MSBuildGuard.Core.Trust;

namespace MSBuildGuard.Worker
{
	/// <summary>
	/// Processes JSON-RPC requests by calling the MSBuildGuard.Core scanning and evaluation services.
	/// </summary>
	public sealed class WorkerProcessor
	{
		private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
		{
			PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
			WriteIndented        = false,
			Converters           = { new JsonStringEnumConverter() }
		};

		/// <summary>
		/// Parses a JSON request line, routes it to the corresponding handler, and returns a JSON response object.
		/// </summary>
		/// <param name="line">The raw JSON-RPC request line.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A structured response envelope.</returns>
		public async Task<WorkerResponse> ProcessAsync(string line, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(line))
			{
				return CreateErrorResponse(string.Empty, WorkerErrorCodes.InvalidEnvelope, "Request payload is empty.");
			}

			WorkerRequest? request;

			try
			{
				request = JsonSerializer.Deserialize<WorkerRequest>(line, JsonOptions);
			}
			catch (JsonException ex)
			{
				return CreateErrorResponse(string.Empty, WorkerErrorCodes.InvalidEnvelope, "Request payload is not valid JSON.", ex.Message);
			}

			if (request == null)
			{
				return CreateErrorResponse(string.Empty, WorkerErrorCodes.InvalidEnvelope, "Request payload is invalid.");
			}

			var requestId = request.Id ?? string.Empty;
			var validationError = request.Validate();

			if (validationError != null)
			{
				return WorkerResponse.FailedResponse(requestId, validationError);
			}

			try
			{
				switch (request.Method)
				{
					case WorkerProtocol.MethodScan:
						return await HandleScanAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodGetOnboardingSuggestions:

						return await HandleGetOnboardingSuggestionsAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodCreateBaseline:
						return await HandleCreateBaselineAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodAddTrust:
						return await HandleAddTrustAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodGetPolicy:
						return await HandleGetPolicyAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodSavePolicy:
						return await HandleSavePolicyAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodGetTrustStore:
						return await HandleGetTrustStoreAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					case WorkerProtocol.MethodRemoveTrust:
						return await HandleRemoveTrustAsync(requestId, request.Payload!, cancellationToken).ConfigureAwait(false);

					default:
						return CreateErrorResponse(requestId, WorkerErrorCodes.InvalidArgument, $"Unsupported method '{request.Method}'.");
				}
			}
			catch (OperationCanceledException)
			{
				return CreateErrorResponse(requestId, WorkerErrorCodes.Canceled, "Operation was canceled.");
			}
			catch (Exception ex)
			{
				return CreateErrorResponse(requestId, WorkerErrorCodes.AnalysisFailed, "Internal process analysis failed.", ex.Message);
			}
		}

		/// <summary>
		/// Serializes a worker response object to a line-delimited JSON string.
		/// </summary>
		/// <param name="response">The response to serialize.</param>
		/// <returns>A single line of JSON.</returns>
		public static string Serialize(WorkerResponse response)
		{
			var json = JsonSerializer.Serialize(response, JsonOptions);

			return json;
		}

		/// <summary>
		/// Handles solution/project scan requests, resolves baseline comparisons, loads merged trust stores, and applies policy rules.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The scan parameters payload.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the scan response envelope.</returns>
		private static async Task<WorkerResponse> HandleScanAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			var targetPath = Path.GetFullPath(payload.TargetPath);

			if (!File.Exists(targetPath) && !Directory.Exists(targetPath))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, $"Target path '{payload.TargetPath}' does not exist.");
			}

			var repositoryRoot = Directory.Exists(targetPath) ? targetPath : (Path.GetDirectoryName(targetPath) ?? string.Empty);
			var noscanPath = Path.Combine(repositoryRoot, ".msbuildguard", "noscan");

			if (File.Exists(noscanPath))
			{
				var emptyReport = new ScanReport();

				emptyReport.Target.TargetPath = targetPath;
				emptyReport.Target.TargetKind = targetPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase) ? TargetKind.Solution : TargetKind.File;

				return WorkerResponse.SuccessResponse(id, emptyReport);
			}

			var scanner = new MsBuildScanner(
				fileSystem: null,
				activityLogger: null,
				msBuildExtensions: payload.FileTypesToScan,
				processCreationIndicators: payload.ProcessCreationIndicators,
				reflectionInteropIndicators: payload.ReflectionInteropIndicators,
				additionalBlockedAssemblies: payload.AdditionalBlockedAssemblies);

			var report = await Task.Run(() => scanner.Scan(targetPath, cancellationToken), cancellationToken).ConfigureAwait(false);

			var baselineService = new BaselineService();

			var baselinePath = Path.Combine(repositoryRoot, ".msbuildguard", "baseline.json");

			BaselineDocument? baseline = null;

			if (File.Exists(baselinePath))
			{
				try
				{
					baseline = baselineService.Load(baselinePath);

					var comparer = new BaselineComparer();

					comparer.Compare(report, baseline);
				}
				catch
				{
					// Ignore baseline load failures during scan to ensure scan results are still returned
				}
			}

			var policy = new PolicyStatusService().GetEffectivePolicy(repositoryRoot, targetPath);
			var trustService = new TrustStoreService();
			var userTrustPath = trustService.GetDefaultUserTrustPath();
			var solutionPath = targetPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase) ? targetPath : null;
			var projectPath = targetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase) ? targetPath : null;
			var trustStore = trustService.LoadMergedTrustStore(userTrustPath, solutionPath, projectPath);
			var evaluator = new PolicyDecisionEvaluator();

			evaluator.Apply(report, policy, baseline, trustStore);

			var userTrustStore     = trustService.Load(userTrustPath);
			var solutionTrustStore = !string.IsNullOrWhiteSpace(solutionPath) ? trustService.Load(trustService.GetSolutionTrustPath(solutionPath)) : new TrustStoreDocument();
			var projectTrustStores = new Dictionary<string, TrustStoreDocument>(StringComparer.OrdinalIgnoreCase);

			foreach (var file in report.FilesScanned)
			{
				if (file.Path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
					file.Path.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
					file.Path.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
				{
					projectTrustStores[file.Path] = trustService.Load(trustService.GetProjectTrustPath(file.Path));
				}
			}

			EvaluateFindingsTrust(report, trustStore, userTrustStore, solutionTrustStore, projectTrustStores);

			return WorkerResponse.SuccessResponse(id, report);
		}

		/// <summary>
		/// Handles generating onboarding suggestions for a solution or project.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The request payload containing targetPath.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the onboarding suggestions.</returns>
		private static async Task<WorkerResponse> HandleGetOnboardingSuggestionsAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			var targetPath = Path.GetFullPath(payload.TargetPath);

			if (!File.Exists(targetPath) && !Directory.Exists(targetPath))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, $"Target path '{payload.TargetPath}' does not exist.");
			}

			var scanner = new MsBuildScanner(
				fileSystem: null,
				activityLogger: null,
				msBuildExtensions: payload.FileTypesToScan,
				processCreationIndicators: payload.ProcessCreationIndicators,
				reflectionInteropIndicators: payload.ReflectionInteropIndicators,
				additionalBlockedAssemblies: payload.AdditionalBlockedAssemblies);

			var report = await Task.Run(() => scanner.Scan(targetPath, cancellationToken), cancellationToken).ConfigureAwait(false);

			var onboardingService = new BaselineOnboardingService();

			var suggestions = await onboardingService.GenerateSuggestionsAsync(report, cancellationToken).ConfigureAwait(false);

			return WorkerResponse.SuccessResponse(id, suggestions);
		}

		/// <summary>
		/// Handles trusted baseline creation, runs project scan, constructs a baseline model, and saves it to the output destination.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The baseline parameters payload.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the baseline creation response envelope.</returns>
		private static async Task<WorkerResponse> HandleCreateBaselineAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			var targetPath = Path.GetFullPath(payload.TargetPath);

			if (string.IsNullOrWhiteSpace(payload.ReviewerIdentity))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "ReviewerIdentity is required to create a baseline.");
			}

			if (string.IsNullOrWhiteSpace(payload.OutputPath))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "OutputPath is required to save the baseline.");
			}

			var outputPath = Path.GetFullPath(payload.OutputPath);

			var repositoryRoot = Directory.Exists(targetPath) ? targetPath : (Path.GetDirectoryName(targetPath) ?? string.Empty);

			var scanner = new MsBuildScanner(
				fileSystem: null,
				activityLogger: null,
				msBuildExtensions: payload.FileTypesToScan,
				processCreationIndicators: payload.ProcessCreationIndicators,
				reflectionInteropIndicators: payload.ReflectionInteropIndicators,
				additionalBlockedAssemblies: payload.AdditionalBlockedAssemblies);

			var report = await Task.Run(() => scanner.Scan(targetPath, cancellationToken), cancellationToken).ConfigureAwait(false);

			var policy = new PolicyStatusService().GetEffectivePolicy(repositoryRoot, targetPath);

			var trustService = new TrustStoreService();

			var userTrustPath = trustService.GetDefaultUserTrustPath();

			var solutionPath = targetPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase) ? targetPath : null;

			var projectPath = targetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase) ? targetPath : null;

			var trustStore = trustService.LoadMergedTrustStore(userTrustPath, solutionPath, projectPath);

			var userTrustStore = trustService.Load(userTrustPath);

			var solutionTrustStore = !string.IsNullOrWhiteSpace(solutionPath) ? trustService.Load(trustService.GetSolutionTrustPath(solutionPath)) : new TrustStoreDocument();

			var projectTrustStores = new Dictionary<string, TrustStoreDocument>(StringComparer.OrdinalIgnoreCase);

			foreach (var file in report.FilesScanned)
			{
				if (file.Path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
					file.Path.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
					file.Path.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
				{
					projectTrustStores[file.Path] = trustService.Load(trustService.GetProjectTrustPath(file.Path));
				}
			}

			EvaluateFindingsTrust(report, trustStore, userTrustStore, solutionTrustStore, projectTrustStores);

			var filteredReport = new ScanReport
			{
				ScannerVersion = report.ScannerVersion,
				ReportVersion = report.ReportVersion,
				Target = report.Target,
				PolicyProfile = report.PolicyProfile
			};

			foreach (var file in report.FilesScanned)
			{
				filteredReport.FilesScanned.Add(file);
			}

			foreach (var finding in report.Findings)
			{
				if (!finding.IsTrusted)
				{
					filteredReport.Findings.Add(finding);
				}
			}

			var baselineService = new BaselineService();

			var reviewer = payload.ReviewerIdentity ?? Environment.UserName;

			var baseline = baselineService.CreateFromReport(filteredReport, policy.Version.ToString(), reviewer);

			baselineService.Save(outputPath, baseline);

			return WorkerResponse.SuccessResponse(id, new { Message = "Baseline created successfully.", Path = outputPath });
		}

		/// <summary>
		/// Handles add trust requests, resolves the correct trust store scope path, and saves the new trust decision.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The request payload containing trust parameters.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the worker response envelope.</returns>
		private static async Task<WorkerResponse> HandleAddTrustAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			var trustStoreService = new TrustStoreService();
			
			string trustStorePath;

			var trustScope = payload.TrustScope?.ToLowerInvariant() ?? "user";
			var targetPath = Path.GetFullPath(payload.TargetPath);

			if (trustScope == "project" && (targetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase)))
			{
				trustStorePath = trustStoreService.GetProjectTrustPath(targetPath);
			}
			else if (trustScope == "solution" && (targetPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase)))
			{
				trustStorePath = trustStoreService.GetSolutionTrustPath(targetPath);
			}
			else if (trustScope == "solution" || trustScope == "project")
			{
				var searchRoot = Directory.Exists(targetPath) ? targetPath : (Path.GetDirectoryName(targetPath) ?? string.Empty);
				var solutionFile = !string.IsNullOrWhiteSpace(searchRoot) && Directory.Exists(searchRoot)
					? (Directory.EnumerateFiles(searchRoot, "*.sln").FirstOrDefault() ?? Directory.EnumerateFiles(searchRoot, "*.slnx").FirstOrDefault())
					: null;

				if (solutionFile != null)
				{
					trustStorePath = trustStoreService.GetSolutionTrustPath(solutionFile);
				}
				else
				{
					var projectFile = !string.IsNullOrWhiteSpace(searchRoot) && Directory.Exists(searchRoot)
						? Directory.EnumerateFiles(searchRoot, "*.csproj").FirstOrDefault()
						: null;

					if (projectFile != null)
					{
						trustStorePath = trustStoreService.GetProjectTrustPath(projectFile);
					}
					else
					{
						trustStorePath = trustStoreService.GetDefaultUserTrustPath();
					}
				}
			}
			else
			{
				trustStorePath = trustStoreService.GetDefaultUserTrustPath();
			}

			var scope   = payload.Scope ?? "Finding";
			var userSid = Environment.UserName;

			if (string.Equals(scope, "Finding", StringComparison.OrdinalIgnoreCase))
			{
				var entry = new TrustDecisionEntry
				{
					DecisionId       = Guid.NewGuid().ToString("D"),
					Scope            = "Finding",
					SubjectHash      = payload.SubjectHash ?? string.Empty,
					Decision         = "TrustUntilChanged",
					Reason           = payload.Reason ?? "Trusted via VS Code Security Review",
					UserSid          = userSid,
					CreatedAtUtc     = DateTimeOffset.UtcNow,
					RepositoryRemote = payload.RepositoryRemote ?? string.Empty,
					Branch           = payload.Branch ?? string.Empty,
					CommitSha        = payload.CommitSha ?? string.Empty,
					PolicyProfile    = payload.PolicyProfile ?? string.Empty
				};

				trustStoreService.AddDecision(trustStorePath, entry);
			}
			else if (string.Equals(scope, "Assembly", StringComparison.OrdinalIgnoreCase))
			{
				trustStoreService.AddAssemblyTrust(
					trustStorePath,
					payload.AssemblyName ?? string.Empty,
					payload.AssemblyVersion ?? string.Empty,
					payload.Reason ?? "Trusted via VS Code Security Review",
					userSid,
					payload.AssemblySigner ?? string.Empty,
					payload.AssemblyIssuer ?? string.Empty,
					payload.AssemblySubject ?? string.Empty,
					payload.ExpiresAtUtc);
			}
			else if (string.Equals(scope, "Signer", StringComparison.OrdinalIgnoreCase))
			{
				trustStoreService.AddSignerTrust(
					trustStorePath,
					payload.SubjectHash ?? string.Empty,
					payload.AssemblySubject ?? string.Empty,
					payload.AssemblySigner ?? string.Empty,
					payload.AssemblyIssuer ?? string.Empty,
					payload.AssemblySerialNumber ?? string.Empty,
					payload.Reason ?? "Trusted via VS Code Security Review",
					userSid,
					payload.ExpiresAtUtc);
			}
			else if (string.Equals(scope, "Package", StringComparison.OrdinalIgnoreCase))
			{
				var packageId = payload.AssemblyName ?? string.Empty;
				var packageVersion = payload.AssemblyVersion ?? string.Empty;
				var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
				var packageDir = Path.Combine(userHome, ".nuget", "packages", packageId.ToLowerInvariant(), packageVersion.ToLowerInvariant());

				if (!Directory.Exists(packageDir))
				{
					return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, $"NuGet package folder does not exist at '{packageDir}'.");
				}

				var packageHash = TrustStoreService.CalculatePackageDirectoryHash(packageDir);

				if (string.IsNullOrWhiteSpace(packageHash))
				{
					return CreateErrorResponse(id, WorkerErrorCodes.AnalysisFailed, "Failed to compute package directory hash.");
				}

				trustStoreService.AddPackageTrust(
					trustStorePath,
					packageId,
					packageVersion,
					packageHash,
					payload.Reason ?? "Trusted via VS Code Security Review",
					userSid,
					payload.ExpiresAtUtc);
			}
			else
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, $"Unsupported trust scope kind '{scope}'.");
			}

			return WorkerResponse.SuccessResponse(id, new { Message = "Trust added successfully.", Path = trustStorePath });
		}

		/// <summary>
		/// Creates a standardized error response envelope with protocol codes and descriptions.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="code">The protocol error code.</param>
		/// <param name="message">The description of the error.</param>
		/// <param name="details">Optional detailed technical information or stack trace.</param>
		/// <returns>A formatted error response envelope.</returns>
		private static WorkerResponse CreateErrorResponse(string id, string code, string message, string? details = null)
		{
			var response = WorkerResponse.ErrorResponse(id, code, message, details);

			return response;
		}

		/// <summary>
		/// Resolves the actual policy JSON file path from the given solution, project, or policy target path.
		/// </summary>
		/// <param name="targetPath">The target path supplied by the client.</param>
		/// <returns>The resolved policy file path.</returns>
		private static string ResolvePolicyPath(string targetPath)
		{
			if (string.IsNullOrWhiteSpace(targetPath))
			{
				return string.Empty;
			}

			if (targetPath.EndsWith("policy.json", StringComparison.OrdinalIgnoreCase))
			{
				return targetPath;
			}

			var service = new PolicyService();

			if (targetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
				targetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase) ||
				targetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase))
			{
				return service.GetProjectPolicyPath(targetPath);
			}

			var solutionDir = Directory.Exists(targetPath) ? targetPath : Path.GetDirectoryName(targetPath);

			if (string.IsNullOrWhiteSpace(solutionDir))
			{
				return service.GetMachinePolicyPath();
			}

			return service.GetRepositoryPolicyPath(solutionDir);
		}

		/// <summary>
		/// Handles loading a policy file from the specified path without validating signatures.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The request payload containing targetPath.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the policy document response envelope.</returns>
		private static async Task<WorkerResponse> HandleGetPolicyAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(payload.TargetPath))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "TargetPath is required to retrieve the policy.");
			}

			var policyPath = ResolvePolicyPath(payload.TargetPath);

			if (!File.Exists(policyPath))
			{
				var defaults = new PolicyService().CreateDefault();

				return WorkerResponse.SuccessResponse(id, defaults);
			}

			try
			{
				var service = new PolicyService();
				
				var policy = await Task.Run(() => service.LoadUnsigned(policyPath), cancellationToken).ConfigureAwait(false);

				return WorkerResponse.SuccessResponse(id, policy);
			}
			catch (Exception ex)
			{
				return CreateErrorResponse(id, WorkerErrorCodes.AnalysisFailed, "Failed to load policy.", ex.Message);
			}
		}

		/// <summary>
		/// Handles saving a policy file to the specified path with full signature verification envelope wrapping.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The request payload containing targetPath and policy.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the save success response envelope.</returns>
		private static async Task<WorkerResponse> HandleSavePolicyAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(payload.TargetPath))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "TargetPath is required to save the policy.");
			}

			if (payload.Policy == null)
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "Policy payload is required to save the policy.");
			}

			var policyPath = ResolvePolicyPath(payload.TargetPath);
			
			var policy = payload.Policy;

			try
			{
				var service = new PolicyService();

				await Task.Run(() => service.Save(policyPath, policy), cancellationToken).ConfigureAwait(false);

				return WorkerResponse.SuccessResponse(id, new { Message = "Policy saved successfully.", Path = policyPath });
			}
			catch (Exception ex)
			{
				return CreateErrorResponse(id, WorkerErrorCodes.AnalysisFailed, "Failed to save policy.", ex.Message);
			}
		}

		/// <summary>
		/// Handles retrieving a trust store's entries from the specified path.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The request payload containing targetPath.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the trust store document response envelope.</returns>
		private static async Task<WorkerResponse> HandleGetTrustStoreAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			var trustStoreService = new TrustStoreService();
			
			string trustStorePath;

			var trustScope = payload.TrustScope?.ToLowerInvariant() ?? "user";
			
			var targetPath = Path.GetFullPath(payload.TargetPath);

			if (trustScope == "project" && (targetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase)))
			{
				trustStorePath = trustStoreService.GetProjectTrustPath(targetPath);
			}
			else if (trustScope == "solution" && (targetPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase)))
			{
				trustStorePath = trustStoreService.GetSolutionTrustPath(targetPath);
			}
			else if (trustScope == "solution" || trustScope == "project")
			{
				var searchRoot = Directory.Exists(targetPath) ? targetPath : (Path.GetDirectoryName(targetPath) ?? string.Empty);
				var solutionFile = !string.IsNullOrWhiteSpace(searchRoot) && Directory.Exists(searchRoot)
					? (Directory.EnumerateFiles(searchRoot, "*.sln").FirstOrDefault() ?? Directory.EnumerateFiles(searchRoot, "*.slnx").FirstOrDefault())
					: null;

				if (solutionFile != null)
				{
					trustStorePath = trustStoreService.GetSolutionTrustPath(solutionFile);
				}
				else
				{
					var projectFile = !string.IsNullOrWhiteSpace(searchRoot) && Directory.Exists(searchRoot)
						? Directory.EnumerateFiles(searchRoot, "*.csproj").FirstOrDefault()
						: null;

					if (projectFile != null)
					{
						trustStorePath = trustStoreService.GetProjectTrustPath(projectFile);
					}
					else
					{
						trustStorePath = trustStoreService.GetDefaultUserTrustPath();
					}
				}
			}
			else
			{
				trustStorePath = trustStoreService.GetDefaultUserTrustPath();
			}

			if (!File.Exists(trustStorePath))
			{
				return WorkerResponse.SuccessResponse(id, new TrustStoreDocument());
			}

			try
			{
				var trustStore = await Task.Run(() => trustStoreService.Load(trustStorePath), cancellationToken).ConfigureAwait(false);

				return WorkerResponse.SuccessResponse(id, trustStore);
			}
			catch (Exception ex)
			{
				return CreateErrorResponse(id, WorkerErrorCodes.AnalysisFailed, "Failed to load trust store.", ex.Message);
			}
		}

		/// <summary>
		/// Handles revoking a trust decision by subject hash from a specified trust store.
		/// </summary>
		/// <param name="id">The correlation request identifier.</param>
		/// <param name="payload">The request payload containing targetPath, trustScope, and subjectHash.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A task returning the revocation success response envelope.</returns>
		private static async Task<WorkerResponse> HandleRemoveTrustAsync(string id, RequestPayload payload, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(payload.SubjectHash))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "SubjectHash is required to remove trust.");
			}

			var trustStoreService = new TrustStoreService();
			
			string trustStorePath;

			var trustScope = payload.TrustScope?.ToLowerInvariant() ?? "user";
			
			var targetPath = Path.GetFullPath(payload.TargetPath);

			if (trustScope == "project" && (targetPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase)))
			{
				trustStorePath = trustStoreService.GetProjectTrustPath(targetPath);
			}
			else if (trustScope == "solution" && (targetPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || targetPath.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase)))
			{
				trustStorePath = trustStoreService.GetSolutionTrustPath(targetPath);
			}
			else if (trustScope == "solution" || trustScope == "project")
			{
				var searchRoot = Directory.Exists(targetPath) ? targetPath : (Path.GetDirectoryName(targetPath) ?? string.Empty);
				var solutionFile = !string.IsNullOrWhiteSpace(searchRoot) && Directory.Exists(searchRoot)
					? (Directory.EnumerateFiles(searchRoot, "*.sln").FirstOrDefault() ?? Directory.EnumerateFiles(searchRoot, "*.slnx").FirstOrDefault())
					: null;

				if (solutionFile != null)
				{
					trustStorePath = trustStoreService.GetSolutionTrustPath(solutionFile);
				}
				else
				{
					var projectFile = !string.IsNullOrWhiteSpace(searchRoot) && Directory.Exists(searchRoot)
						? Directory.EnumerateFiles(searchRoot, "*.csproj").FirstOrDefault()
						: null;

					if (projectFile != null)
					{
						trustStorePath = trustStoreService.GetProjectTrustPath(projectFile);
					}
					else
					{
						trustStorePath = trustStoreService.GetDefaultUserTrustPath();
					}
				}
			}
			else
			{
				trustStorePath = trustStoreService.GetDefaultUserTrustPath();
			}

			if (!File.Exists(trustStorePath))
			{
				return CreateErrorResponse(id, WorkerErrorCodes.InvalidArgument, "Trust store does not exist at path: " + trustStorePath);
			}

			var subjectHash = payload.SubjectHash;
			
			var reason = payload.Reason ?? "Revoked via VS Code Trust Manager";
			
			var userSid = Environment.UserName;

			try
			{
				var removedCount = await Task.Run(() => trustStoreService.RemoveDecisionsBySubject(trustStorePath, subjectHash, reason, userSid), cancellationToken).ConfigureAwait(false);

				return WorkerResponse.SuccessResponse(id, new { Message = "Trust decisions revoked successfully.", RevokedCount = removedCount });
			}
			catch (Exception ex)
			{
				return CreateErrorResponse(id, WorkerErrorCodes.AnalysisFailed, "Failed to revoke trust decisions.", ex.Message);
			}
		}

		/// <summary>
		/// Evaluates trust status for all findings in the report and updates the risk score and recommended action.
		/// </summary>
		/// <param name="report">The scan report to evaluate trust for.</param>
		/// <param name="trustStore">The merged trust store document.</param>
		/// <param name="userTrustStore">The user-level trust store document.</param>
		/// <param name="solutionTrustStore">The solution-level trust store document.</param>
		/// <param name="projectTrustStores">Dictionary of project-level trust store documents.</param>
		private static void EvaluateFindingsTrust(
			ScanReport report,
			TrustStoreDocument trustStore,
			TrustStoreDocument userTrustStore,
			TrustStoreDocument solutionTrustStore,
			Dictionary<string, TrustStoreDocument> projectTrustStores)
		{
			var trustStoreService = new TrustStoreService();
			var signatureService  = new AssemblySignatureService();
			var signatureCache    = new Dictionary<string, AssemblySignatureInfo>(StringComparer.OrdinalIgnoreCase);
			var activeRiskScore   = 0;

			foreach (var finding in report.Findings)
			{
				var fileRecord = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));
				var isFingerprintTrusted = !string.IsNullOrWhiteSpace(finding.Fingerprint) &&
					fileRecord != null &&
					trustStoreService.IsFindingApproved(trustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile);

				var isApprovedByAssembly = false;

				if (!string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					if (trustStoreService.IsFindingApprovedByAssembly(userTrustStore, finding.PackageId, finding.PackageVersion) ||
						trustStoreService.IsFindingApprovedByAssembly(solutionTrustStore, finding.PackageId, finding.PackageVersion))
					{
						isApprovedByAssembly = true;
					}
					else
					{
						foreach (var projStore in projectTrustStores.Values)
						{
							if (trustStoreService.IsFindingApprovedByAssembly(projStore, finding.PackageId, finding.PackageVersion))
							{
								isApprovedByAssembly = true;
								break;
							}
						}
					}
				}

				var isApprovedBySigner = false;

				if (!string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					var dllPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);

					if (!string.IsNullOrWhiteSpace(dllPath) && File.Exists(dllPath))
					{
						if (!signatureCache.TryGetValue(dllPath, out var signature))
						{
							signature = signatureService.ReadSignature(dllPath);
							signatureCache[dllPath] = signature;
						}

						if (signature.IsSignatureValid && (!string.IsNullOrWhiteSpace(signature.Thumbprint) || !string.IsNullOrWhiteSpace(signature.Subject)))
						{
							if (trustStoreService.IsSignerTrusted(userTrustStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber) ||
								trustStoreService.IsSignerTrusted(solutionTrustStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber))
							{
								isApprovedBySigner = true;
							}
							else
							{
								foreach (var projStore in projectTrustStores.Values)
								{
									if (trustStoreService.IsSignerTrusted(projStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber))
									{
										isApprovedBySigner = true;
										break;
									}
								}
							}
						}
					}
				}

				var isApprovedByPackage = false;

				if (!string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					if (trustStoreService.IsFindingApprovedByPackage(userTrustStore, finding.PackageId, finding.PackageVersion) ||
						trustStoreService.IsFindingApprovedByPackage(solutionTrustStore, finding.PackageId, finding.PackageVersion))
					{
						isApprovedByPackage = true;
					}
					else
					{
						foreach (var projStore in projectTrustStores.Values)
						{
							if (trustStoreService.IsFindingApprovedByPackage(projStore, finding.PackageId, finding.PackageVersion))
							{
								isApprovedByPackage = true;

								break;
							}
						}
					}
				}

				var isEffectivelyTrusted = isFingerprintTrusted || isApprovedByAssembly || isApprovedBySigner || isApprovedByPackage;
				finding.IsTrusted        = isEffectivelyTrusted;

				if (!isEffectivelyTrusted)
				{
					activeRiskScore += GetSeverityRisk(finding.Severity);
				}
			}

			report.RiskScore = Math.Max(0, activeRiskScore);
			report.RecommendedAction = MapRecommendedAction(activeRiskScore);
		}

		private static int GetSeverityRisk(FindingSeverity severity)
		{
			switch (severity)
			{
				case FindingSeverity.None:
				case FindingSeverity.Info:
					return 0;
				case FindingSeverity.Low:
					return 5;
				case FindingSeverity.Medium:
					return 20;
				case FindingSeverity.High:
					return 50;
				case FindingSeverity.Critical:
					return 100;
				default:
					return 0;
			}
		}

		private static RecommendedAction MapRecommendedAction(int riskScore)
		{
			if (riskScore >= 100)
			{
				return RecommendedAction.Block;
			}

			if (riskScore >= 50)
			{
				return RecommendedAction.RequireApproval;
			}

			if (riskScore >= 20)
			{
				return RecommendedAction.Warn;
			}

			return RecommendedAction.Allow;
		}
	}
}
