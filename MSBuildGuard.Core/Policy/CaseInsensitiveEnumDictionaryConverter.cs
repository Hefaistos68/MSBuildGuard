using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MSBuildGuard.Core.Policy
{
	/// <summary>
	/// Provides case-insensitive enum key deserialization for dictionaries.
	/// </summary>
	/// <typeparam name="TEnum">The enum key type.</typeparam>
	/// <typeparam name="TValue">The value type.</typeparam>
	public sealed class CaseInsensitiveEnumDictionaryConverter<TEnum, TValue> : JsonConverter<IDictionary<TEnum, TValue>>
		where TEnum : struct, Enum
	{
		/// <inheritdoc />
		public override IDictionary<TEnum, TValue>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
		{
			var stringDict = JsonSerializer.Deserialize<Dictionary<string, TValue>>(ref reader, options);

			if (stringDict == null)
			{
				return null;
			}

			var result = new Dictionary<TEnum, TValue>();

			foreach (var kvp in stringDict)
			{
				if (Enum.TryParse<TEnum>(kvp.Key, ignoreCase: true, out var enumKey))
				{
					result[enumKey] = kvp.Value;
				}
			}

			return result;
		}

		/// <inheritdoc />
		public override void Write(Utf8JsonWriter writer, IDictionary<TEnum, TValue> value, JsonSerializerOptions options)
		{
			var stringDict = new Dictionary<string, TValue>();

			foreach (var kvp in value)
			{
				stringDict[kvp.Key.ToString()] = kvp.Value;
			}

			JsonSerializer.Serialize(writer, stringDict, options);
		}
	}
}
