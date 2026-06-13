using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Represents reputation details fetched from NuGet.org.
	/// </summary>
	public sealed class NugetReputationInfo
	{
		/// <summary>
		/// Gets or sets the package identifier.
		/// </summary>
		public string PackageId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether the package is verified.
		/// </summary>
		public bool IsVerified { get; set; }

		/// <summary>
		/// Gets or sets the total download count.
		/// </summary>
		public long TotalDownloads { get; set; }

		/// <summary>
		/// Gets the list of package owners.
		/// </summary>
		public List<string> Owners { get; } = new List<string>();
	}

	/// <summary>
	/// Provides reputation lookup for NuGet packages from official sources.
	/// </summary>
	public sealed class NugetReputationService
	{
		private static readonly HttpClient HttpClientInstance = new HttpClient
		{
			Timeout = TimeSpan.FromSeconds(3)
		};

		/// <summary>
		/// Fetches package reputation information from the NuGet search API.
		/// </summary>
		/// <param name="packageId">NuGet package ID.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>A task returning the reputation info, or null if retrieval fails.</returns>
		public async Task<NugetReputationInfo?> GetReputationAsync(string packageId, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(packageId))
			{
				return null;
			}

			try
			{
				var url = $"https://api-v2v3search-0.nuget.org/query?q=packageid:{Uri.EscapeDataString(packageId)}";

				using var response = await HttpClientInstance.GetAsync(url, cancellationToken).ConfigureAwait(false);

				if (!response.IsSuccessStatusCode)
				{
					return null;
				}

				var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

				using var doc = JsonDocument.Parse(json);

				if (!doc.RootElement.TryGetProperty("data", out var dataProp) || dataProp.ValueKind != JsonValueKind.Array || dataProp.GetArrayLength() == 0)
				{
					return null;
				}

				JsonElement bestMatch = default;
				var foundMatch = false;

				foreach (var item in dataProp.EnumerateArray())
				{
					if (item.TryGetProperty("id", out var idProp) &&
						string.Equals(idProp.GetString(), packageId, StringComparison.OrdinalIgnoreCase))
					{
						bestMatch = item;
						foundMatch = true;

						break;
					}
				}

				if (!foundMatch)
				{
					bestMatch = dataProp[0];
				}

				var info = new NugetReputationInfo
				{
					PackageId = packageId,
					IsVerified = bestMatch.TryGetProperty("verified", out var verifiedProp) && verifiedProp.GetBoolean(),
					TotalDownloads = bestMatch.TryGetProperty("totalDownloads", out var downloadsProp) ? downloadsProp.GetInt64() : 0
				};

				if (bestMatch.TryGetProperty("owners", out var ownersProp) && ownersProp.ValueKind == JsonValueKind.Array)
				{
					foreach (var ownerItem in ownersProp.EnumerateArray())
					{
						var ownerStr = ownerItem.GetString();

						if (!string.IsNullOrWhiteSpace(ownerStr))
						{
							info.Owners.Add(ownerStr!);
						}
					}
				}

				return info;
			}
			catch
			{
				return null;
			}
		}
	}
}
