using System;
using System.Collections.Generic;
using System.Text.Json;
using MSBuildGuard.Core.Policy;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Policy
{
	/// <summary>
	/// Tests for <see cref="CaseInsensitiveEnumDictionaryConverter{TEnum, TValue}"/>.
	/// </summary>
	[TestFixture]
	public sealed class CaseInsensitiveEnumDictionaryConverterTests
	{
		private sealed class DummyContainer
		{
			[System.Text.Json.Serialization.JsonConverter(typeof(CaseInsensitiveEnumDictionaryConverter<FindingSeverity, PolicyAction>))]
			public IDictionary<FindingSeverity, PolicyAction> MinimumActionBySeverity { get; set; } = new Dictionary<FindingSeverity, PolicyAction>();
		}

		/// <summary>
		/// Verifies that various key casings can be successfully deserialized.
		/// </summary>
		[Test]
		public void Read_ShouldDeserializeVariousEnumKeyCasings()
		{
			var json = "{\"MinimumActionBySeverity\": {\"critical\": \"Block\", \"HIGH\": \"Warn\", \"mEdIuM\": \"RequireApproval\"}}";
			var options = new JsonSerializerOptions
			{
				PropertyNameCaseInsensitive = true,
				Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
			};

			var container = JsonSerializer.Deserialize<DummyContainer>(json, options);

			container.ShouldNotBeNull();
			container.MinimumActionBySeverity[FindingSeverity.Critical].ShouldBe(PolicyAction.Block);
			container.MinimumActionBySeverity[FindingSeverity.High].ShouldBe(PolicyAction.Warn);
			container.MinimumActionBySeverity[FindingSeverity.Medium].ShouldBe(PolicyAction.RequireApproval);
		}

		/// <summary>
		/// Verifies that serialization correctly writes keys.
		/// </summary>
		[Test]
		public void Write_ShouldSerializeEnumKeysToStrings()
		{
			var container = new DummyContainer();

			container.MinimumActionBySeverity[FindingSeverity.Critical] = PolicyAction.Block;
			container.MinimumActionBySeverity[FindingSeverity.High] = PolicyAction.Warn;

			var options = new JsonSerializerOptions
			{
				PropertyNameCaseInsensitive = true,
				Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
			};

			var json = JsonSerializer.Serialize(container, options);

			json.ShouldContain("\"Critical\":\"Block\"");
			json.ShouldContain("\"High\":\"Warn\"");
		}
	}
}
