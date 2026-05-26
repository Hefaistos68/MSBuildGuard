using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using MSBuildGuard.Core;

namespace MSBuildGuard.Worker
{
	/// <summary>
	/// Represents the standard request wrapper sent from the VS Code extension.
	/// </summary>
	public sealed class WorkerRequest
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="WorkerRequest"/> class with the default protocol version.
		/// </summary>
		public WorkerRequest()
		{
			this.Version = WorkerProtocol.Version;
		}

		/// <summary>
		/// Gets or sets the protocol version.
		/// </summary>
		[JsonPropertyName("version")]
		public string Version { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the unique request identifier.
		/// </summary>
		[JsonPropertyName("id")]
		public string Id { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the RPC method to invoke.
		/// </summary>
		[JsonPropertyName("method")]
		public string Method { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the request payload containing method-specific parameters.
		/// </summary>
		[JsonPropertyName("payload")]
		public RequestPayload? Payload { get; set; }

		/// <summary>
		/// Validates the request envelope, protocol version, and payload parameter parameters.
		/// </summary>
		/// <returns>A <see cref="WorkerError"/> if validation fails; otherwise, <c>null</c>.</returns>
		public WorkerError? Validate()
		{
			if (!string.Equals(this.Version, WorkerProtocol.Version, StringComparison.Ordinal))
			{
				var error = new WorkerError
				{
					Code    = WorkerErrorCodes.UnsupportedVersion,
					Message = $"Unsupported protocol version '{this.Version}'."
				};

				return error;
			}

			if (this.Payload == null)
			{
				var error = new WorkerError
				{
					Code    = WorkerErrorCodes.InvalidArgument,
					Message = "Request payload is missing."
				};

				return error;
			}

			if (string.IsNullOrWhiteSpace(this.Payload.TargetPath))
			{
				var error = new WorkerError
				{
					Code    = WorkerErrorCodes.InvalidArgument,
					Message = "The targetPath parameter is required."
				};

				return error;
			}

			return null;
		}
	}

	/// <summary>
	/// Holds the parameters for worker requests.
	/// </summary>
	public sealed class RequestPayload
	{
		/// <summary>
		/// Gets or sets the target solution or project path to scan.
		/// </summary>
		[JsonPropertyName("targetPath")]
		public string TargetPath { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the file extensions to include in the scan.
		/// </summary>
		[JsonPropertyName("fileTypesToScan")]
		public List<string>? FileTypesToScan { get; set; }

		/// <summary>
		/// Gets or sets custom process creation indicators.
		/// </summary>
		[JsonPropertyName("processCreationIndicators")]
		public List<string>? ProcessCreationIndicators { get; set; }

		/// <summary>
		/// Gets or sets custom reflection and interop indicators.
		/// </summary>
		[JsonPropertyName("reflectionInteropIndicators")]
		public List<string>? ReflectionInteropIndicators { get; set; }

		/// <summary>
		/// Gets or sets additional blocked NuGet assemblies.
		/// </summary>
		[JsonPropertyName("additionalBlockedAssemblies")]
		public List<string>? AdditionalBlockedAssemblies { get; set; }

		/// <summary>
		/// Gets or sets the identity of the baseline reviewer.
		/// </summary>
		[JsonPropertyName("reviewerIdentity")]
		public string? ReviewerIdentity { get; set; }

		/// <summary>
		/// Gets or sets the output path where the baseline should be saved.
		/// </summary>
		[JsonPropertyName("outputPath")]
		public string? OutputPath { get; set; }

		/// <summary>
		/// Gets or sets the trust scope: "user", "solution", or "project".
		/// </summary>
		[JsonPropertyName("trustScope")]
		public string? TrustScope { get; set; }

		/// <summary>
		/// Gets or sets the type of trust: "Finding", "Assembly", "Signer".
		/// </summary>
		[JsonPropertyName("scope")]
		public string? Scope { get; set; }

		/// <summary>
		/// Gets or sets the subject hash (fingerprint, thumbprint, or key).
		/// </summary>
		[JsonPropertyName("subjectHash")]
		public string? SubjectHash { get; set; }

		/// <summary>
		/// Gets or sets the reason for trusting.
		/// </summary>
		[JsonPropertyName("reason")]
		public string? Reason { get; set; }

		/// <summary>
		/// Gets or sets the assembly name.
		/// </summary>
		[JsonPropertyName("assemblyName")]
		public string? AssemblyName { get; set; }

		/// <summary>
		/// Gets or sets the assembly version.
		/// </summary>
		[JsonPropertyName("assemblyVersion")]
		public string? AssemblyVersion { get; set; }

		/// <summary>
		/// Gets or sets the assembly signer.
		/// </summary>
		[JsonPropertyName("assemblySigner")]
		public string? AssemblySigner { get; set; }

		/// <summary>
		/// Gets or sets the assembly issuer.
		/// </summary>
		[JsonPropertyName("assemblyIssuer")]
		public string? AssemblyIssuer { get; set; }

		/// <summary>
		/// Gets or sets the assembly subject.
		/// </summary>
		[JsonPropertyName("assemblySubject")]
		public string? AssemblySubject { get; set; }

		/// <summary>
		/// Gets or sets the assembly thumbprint.
		/// </summary>
		[JsonPropertyName("assemblyThumbprint")]
		public string? AssemblyThumbprint { get; set; }

		/// <summary>
		/// Gets or sets the assembly serial number.
		/// </summary>
		[JsonPropertyName("assemblySerialNumber")]
		public string? AssemblySerialNumber { get; set; }

		/// <summary>
		/// Gets or sets the repository remote.
		/// </summary>
		[JsonPropertyName("repositoryRemote")]
		public string? RepositoryRemote { get; set; }

		/// <summary>
		/// Gets or sets the branch.
		/// </summary>
		[JsonPropertyName("branch")]
		public string? Branch { get; set; }

		/// <summary>
		/// Gets or sets the commit SHA.
		/// </summary>
		[JsonPropertyName("commitSha")]
		public string? CommitSha { get; set; }

		/// <summary>
		/// Gets or sets the policy profile.
		/// </summary>
		[JsonPropertyName("policyProfile")]
		public string? PolicyProfile { get; set; }

		/// <summary>
		/// Gets or sets the expiration timestamp.
		/// </summary>
		[JsonPropertyName("expiresAtUtc")]
		public DateTimeOffset? ExpiresAtUtc { get; set; }

		/// <summary>
		/// Gets or sets the policy document to get/save.
		/// </summary>
		[JsonPropertyName("policy")]
		public MSBuildGuard.Core.Policy.PolicyDocument? Policy { get; set; }
	}

	/// <summary>
	/// Represents the standard response envelope returned from the worker.
	/// </summary>
	public sealed class WorkerResponse
	{
		/// <summary>
		/// Gets or sets the protocol version.
		/// </summary>
		[JsonPropertyName("version")]
		public string Version { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the correlation request identifier.
		/// </summary>
		[JsonPropertyName("id")]
		public string Id { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets whether the operation succeeded.
		/// </summary>
		[JsonPropertyName("success")]
		public bool Success { get; set; }

		/// <summary>
		/// Gets or sets the success payload object returned.
		/// </summary>
		[JsonPropertyName("result")]
		public object? Result { get; set; }

		/// <summary>
		/// Gets or sets error details if the operation failed.
		/// </summary>
		[JsonPropertyName("error")]
		public WorkerError? Error { get; set; }

		/// <summary>
		/// Creates a success response.
		/// </summary>
		/// <param name="id">Correlation ID.</param>
		/// <param name="result">Result payload.</param>
		/// <returns>A successful response.</returns>
		public static WorkerResponse SuccessResponse(string id, object? result)
		{
			return new WorkerResponse
			{
				Version = WorkerProtocol.Version,
				Id      = id,
				Success = true,
				Result  = result
			};
		}

		/// <summary>
		/// Creates a generic failure response.
		/// </summary>
		/// <param name="id">Correlation ID.</param>
		/// <param name="error">Error object.</param>
		/// <returns>A failed response.</returns>
		public static WorkerResponse FailedResponse(string id, WorkerError error)
		{
			return new WorkerResponse
			{
				Version = WorkerProtocol.Version,
				Id      = id,
				Success = false,
				Error   = error
			};
		}

		/// <summary>
		/// Creates a detailed failure response.
		/// </summary>
		/// <param name="id">Correlation ID.</param>
		/// <param name="code">Error code.</param>
		/// <param name="message">Error message.</param>
		/// <param name="details">Extra error details.</param>
		/// <returns>A failed response.</returns>
		public static WorkerResponse ErrorResponse(string id, string code, string message, string? details = null)
		{
			return new WorkerResponse
			{
				Version = WorkerProtocol.Version,
				Id      = id,
				Success = false,
				Error   = new WorkerError
				{
					Code    = code,
					Message = message,
					Details = details
				}
			};
		}
	}

	/// <summary>
	/// Represents persisted error details for a request.
	/// </summary>
	public sealed class WorkerError
	{
		/// <summary>
		/// Gets or sets the standard error code.
		/// </summary>
		[JsonPropertyName("code")]
		public string Code { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a descriptive error message.
		/// </summary>
		[JsonPropertyName("message")]
		public string Message { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets any extra technical details or exception stack information.
		/// </summary>
		[JsonPropertyName("details")]
		public string? Details { get; set; }
	}

	/// <summary>
	/// Defines the standard constants used by the worker protocol.
	/// </summary>
	public static class WorkerProtocol
	{
		/// <summary>
		/// The current version of the MSBuild Guard worker protocol.
		/// </summary>
		public const string Version = "1.0";

		/// <summary>
		/// The method name to execute solution or project scans.
		/// </summary>
		public const string MethodScan = "scan";

		/// <summary>
		/// The method name to create a trusted baseline snapshot.
		/// </summary>
		public const string MethodCreateBaseline = "createBaseline";

		/// <summary>
		/// The method name to add trust decisions to a trust store.
		/// </summary>
		public const string MethodAddTrust = "addTrust";

		/// <summary>
		/// The method name to retrieve the active policy.
		/// </summary>
		public const string MethodGetPolicy = "getPolicy";

		/// <summary>
		/// The method name to save the active policy.
		/// </summary>
		public const string MethodSavePolicy = "savePolicy";

		/// <summary>
		/// The method name to retrieve active trust decisions.
		/// </summary>
		public const string MethodGetTrustStore = "getTrustStore";

		/// <summary>
		/// The method name to remove a trust decision.
		/// </summary>
		public const string MethodRemoveTrust = "removeTrust";
	}

	/// <summary>
	/// Defines standard protocol error codes returned by the worker.
	/// </summary>
	public static class WorkerErrorCodes
	{
		/// <summary>
		/// The request was empty or could not be decoded.
		/// </summary>
		public const string InvalidEnvelope = "INVALID_ENVELOPE";

		/// <summary>
		/// The protocol version specified is not supported.
		/// </summary>
		public const string UnsupportedVersion = "UNSUPPORTED_VERSION";

		/// <summary>
		/// One or more arguments supplied are invalid or missing.
		/// </summary>
		public const string InvalidArgument = "INVALID_ARGUMENT";

		/// <summary>
		/// An internal error occurred during the analysis phase.
		/// </summary>
		public const string AnalysisFailed = "ANALYSIS_FAILED";

		/// <summary>
		/// The requested operation was cancelled.
		/// </summary>
		public const string Canceled = "CANCELED";
	}
}
