using System;
using System.IO;
using System.Text;
using System.Text.Json;
using MSBuildGuard.Core;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Exports scan reports to persisted files.
	/// </summary>
	internal sealed class ReportExportService
	{
		private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
		{
			WriteIndented = true
		};

		/// <summary>
		/// Exports a report as JSON.
		/// </summary>
		/// <param name="report">Report to export.</param>
		/// <param name="path">Destination path.</param>
		public static void ExportJson(ScanReport report, string path)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (string.IsNullOrWhiteSpace(path))
			{
				throw new ArgumentException("A destination path is required.", nameof(path));
			}

			EnsureDirectory(path);

			var json = JsonSerializer.Serialize(report, JsonOptions);

			File.WriteAllText(path, json);
		}

		/// <summary>
		/// Exports a report as markdown.
		/// </summary>
		/// <param name="report">Report to export.</param>
		/// <param name="path">Destination path.</param>
		public static void ExportMarkdown(ScanReport report, string path)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (string.IsNullOrWhiteSpace(path))
			{
				throw new ArgumentException("A destination path is required.", nameof(path));
			}

			EnsureDirectory(path);

			var builder = new StringBuilder();
			builder.AppendLine("# MSBuild Guard Report");
			builder.AppendLine();
			builder.AppendLine($"- Risk score: {report.RiskScore}");
			builder.AppendLine($"- Recommended action: {report.RecommendedAction}");
			builder.AppendLine($"- Files scanned: {report.FilesScanned.Count}");
			builder.AppendLine($"- Findings: {report.Findings.Count}");
			builder.AppendLine();

			foreach (var finding in report.Findings)
			{
				builder.AppendLine($"- [{finding.Severity}] {finding.Id} {finding.Title} ({finding.FilePath}:{finding.StartLine})");
			}

			File.WriteAllText(path, builder.ToString());
		}

		/// <summary>
		/// Exports a report as SARIF.
		/// </summary>
		/// <param name="report">Report to export.</param>
		/// <param name="path">Destination path.</param>
		public static void ExportSarif(ScanReport report, string path)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (string.IsNullOrWhiteSpace(path))
			{
				throw new ArgumentException("A destination path is required.", nameof(path));
			}

			EnsureDirectory(path);

			var sarif = new
			{
				version = "2.1.0",
				runs = new[]
				{
					new
					{
						tool = new
						{
							driver = new
							{
								name = "MSBuild Guard"
							}
						},
						results = report.Findings
					}
				}
			};

			var json = JsonSerializer.Serialize(sarif, JsonOptions);

			File.WriteAllText(path, json);
		}

		/// <summary>
		/// Gets the default report storage path for Visual Studio scans.
		/// </summary>
		/// <returns>Report directory path.</returns>
		public static string GetDefaultReportDirectory()
		{
			var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

			return Path.Combine(basePath, "MSBuildGuard", "Reports");
		}

		/// <summary>
		/// Ensures destination directory exists.
		/// </summary>
		/// <param name="path">Target file path.</param>
		private static void EnsureDirectory(string path)
		{
			var directory = Path.GetDirectoryName(path);

			if (string.IsNullOrWhiteSpace(directory))
			{
				return;
			}

			Directory.CreateDirectory(directory);
		}
	}
}
