using System;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Provides baseline serialization and creation operations.
	/// </summary>
	public sealed class BaselineService
	{
		private const string BaselineSigningKey = "1f831744-a728-4fa8-9b8d-dc98f543e6cc";

		private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
		{
			WriteIndented = true
		};

		/// <summary>
		/// Creates a baseline document from a scan report.
		/// </summary>
		/// <param name="report">The source scan report.</param>
		/// <param name="policyVersion">The effective policy version identifier.</param>
		/// <param name="reviewerIdentity">Optional reviewer identity.</param>
		/// <returns>The created baseline document.</returns>
		public BaselineDocument CreateFromReport(ScanReport report, string policyVersion, string reviewerIdentity)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (policyVersion == null)
			{
				throw new ArgumentNullException(nameof(policyVersion));
			}

			if (reviewerIdentity == null)
			{
				throw new ArgumentNullException(nameof(reviewerIdentity));
			}

			var baseline = new BaselineDocument
			{
				CreatedAtUtc      = DateTimeOffset.UtcNow,
				PolicyVersion     = policyVersion,
				ReviewerIdentity  = reviewerIdentity,
				ScannerVersion    = report.ScannerVersion,
				Version           = 1
			};

			foreach (var file in report.FilesScanned)
			{
				baseline.Files.Add(new BaselineFileEntry
				{
					NormalizedSha256 = file.NormalizedSha256,
					Path             = file.Path
				});
			}

			foreach (var finding in report.Findings.Where(current => !string.IsNullOrWhiteSpace(current.Fingerprint)))
			{
				baseline.ApprovedFindings.Add(new BaselineFindingEntry
				{
					Fingerprint = finding.Fingerprint,
					RuleId      = finding.Id,
					Severity    = finding.Severity
				});
			}

			return baseline;
		}

		/// <summary>
		/// Saves a baseline document to disk.
		/// </summary>
		/// <param name="path">The baseline file path.</param>
		/// <param name="baseline">The baseline document to persist.</param>
		public void Save(string path, BaselineDocument baseline)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (baseline == null)
			{
				throw new ArgumentNullException(nameof(baseline));
			}

			var directory = Path.GetDirectoryName(path);

			if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
			{
				Directory.CreateDirectory(directory);
			}

			var payload = JsonSerializer.Serialize(baseline, SerializerOptions);
			var signedPayload = new JsonSignatureService().CreateSignedEnvelopeJson(payload, BaselineSigningKey);

			File.WriteAllText(path, signedPayload);
		}

		/// <summary>
		/// Loads a baseline document from disk.
		/// </summary>
		/// <param name="path">The baseline file path.</param>
		/// <returns>The loaded baseline document.</returns>
		public BaselineDocument Load(string path)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			var payload = File.ReadAllText(path);
			var signatureService = new JsonSignatureService();

			if (!signatureService.TryVerifyAndExtract<string>(payload, BaselineSigningKey, out var baselinePayload) || string.IsNullOrWhiteSpace(baselinePayload))
			{
				throw new InvalidDataException("Baseline signature validation failed.");
			}

			var baseline = JsonSerializer.Deserialize<BaselineDocument>(baselinePayload, SerializerOptions);

			if (baseline == null)
			{
				throw new InvalidDataException("Unable to deserialize baseline file.");
			}

			return baseline;
		}
	}
}
