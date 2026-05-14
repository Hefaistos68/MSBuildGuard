using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Provides signing and verification for JSON payload envelopes.
	/// </summary>
	public sealed class JsonSignatureService
	{
		/// <summary>
		/// Represents a signed JSON payload envelope.
		/// </summary>
		/// <typeparam name="T">The wrapped JSON payload type.</typeparam>
		public sealed class SignedJsonEnvelope<T>
		{
			/// <summary>
			/// Gets or sets the base64-encoded signature.
			/// </summary>
			public string SignatureV1 { get; set; } = string.Empty;

			/// <summary>
			/// Gets the warning note. Ignore this property when deserializing, and do not modify the contents of this file manually.
			/// </summary>
			[JsonIgnore(Condition = JsonIgnoreCondition.WhenReading)]
			public string Note => "Do not modify the contents of this file manually, or it will fail to load.";

			/// <summary>
			/// Gets or sets the wrapped JSON payload.
			/// </summary>
			public T JSON { get; set; } = default!;
		}

		private static readonly JsonSerializerOptions EnvelopeSerializerOptions = new JsonSerializerOptions
		{
			WriteIndented = true
		};

		/// <summary>
		/// Creates and serializes a signed JSON envelope.
		/// </summary>
		/// <typeparam name="T">The payload type.</typeparam>
		/// <param name="payload">The payload to wrap and sign.</param>
		/// <param name="signingKey">The symmetric signing key.</param>
		/// <returns>The serialized signed envelope JSON.</returns>
		public string CreateSignedEnvelopeJson<T>(T payload, string signingKey)
		{
			if (payload == null)
			{
				throw new ArgumentNullException(nameof(payload));
			}

			if (signingKey == null)
			{
				throw new ArgumentNullException(nameof(signingKey));
			}

			var normalizedPayloadJson = NormalizeJson(JsonSerializer.Serialize(payload));
			var signature = ComputeSignature(normalizedPayloadJson, signingKey);
			var envelope = new SignedJsonEnvelope<JsonElement>
			{
				SignatureV1 = signature,
				JSON        = JsonDocument.Parse(normalizedPayloadJson).RootElement.Clone()
			};

			return JsonSerializer.Serialize(envelope, EnvelopeSerializerOptions);
		}

		/// <summary>
		/// Verifies a signed envelope and extracts the payload.
		/// </summary>
		/// <typeparam name="T">The expected payload type.</typeparam>
		/// <param name="signedEnvelopeJson">The signed envelope JSON content.</param>
		/// <param name="signingKey">The symmetric signing key.</param>
		/// <param name="payload">The extracted payload when verification succeeds.</param>
		/// <returns><see langword="true"/> when signature is valid; otherwise <see langword="false"/>.</returns>
		public bool TryVerifyAndExtract<T>(string signedEnvelopeJson, string signingKey, out T? payload)
		{
			if (signedEnvelopeJson == null)
			{
				throw new ArgumentNullException(nameof(signedEnvelopeJson));
			}

			if (signingKey == null)
			{
				throw new ArgumentNullException(nameof(signingKey));
			}

			payload = default;

			SignedJsonEnvelope<JsonElement>? envelope;

			try
			{
				envelope = JsonSerializer.Deserialize<SignedJsonEnvelope<JsonElement>>(signedEnvelopeJson);
			}
			catch (JsonException)
			{
				return false;
			}

			if (envelope == null || string.IsNullOrWhiteSpace(envelope.SignatureV1))
			{
				return false;
			}

			var normalizedPayloadJson = NormalizeJson(envelope.JSON.GetRawText());
			var computedSignature = ComputeSignature(normalizedPayloadJson, signingKey);

			if (!ConstantTimeEquals(envelope.SignatureV1, computedSignature))
			{
				return false;
			}

			payload = JsonSerializer.Deserialize<T>(normalizedPayloadJson);
			return payload != null;
		}

		/// <summary>
		/// Normalizes JSON into deterministic minified form for signing.
		/// </summary>
		/// <param name="json">The JSON content to normalize.</param>
		/// <returns>The normalized JSON content.</returns>
		private static string NormalizeJson(string json)
		{
			using var document = JsonDocument.Parse(json);

			return JsonSerializer.Serialize(document.RootElement);
		}

		/// <summary>
		/// Computes the base64-encoded HMAC-SHA256 signature for a JSON payload.
		/// </summary>
		/// <param name="normalizedJson">The normalized JSON content.</param>
		/// <param name="signingKey">The symmetric signing key.</param>
		/// <returns>The base64-encoded signature value.</returns>
		private static string ComputeSignature(string normalizedJson, string signingKey)
		{
			var keyBytes = Encoding.UTF8.GetBytes(signingKey);
			var dataBytes = Encoding.UTF8.GetBytes(normalizedJson);

			using var hmac = new HMACSHA256(keyBytes);

			return Convert.ToBase64String(hmac.ComputeHash(dataBytes));
		}

		/// <summary>
		/// Compares two base64 strings in constant time.
		/// </summary>
		/// <param name="left">The first base64 value.</param>
		/// <param name="right">The second base64 value.</param>
		/// <returns><see langword="true"/> when both values are equal; otherwise <see langword="false"/>.</returns>
		private static bool ConstantTimeEquals(string left, string right)
		{
			byte[] leftBytes;
			byte[] rightBytes;

			try
			{
				leftBytes = Convert.FromBase64String(left);
				rightBytes = Convert.FromBase64String(right);
			}
			catch (FormatException)
			{
				return false;
			}

			if (leftBytes.Length != rightBytes.Length)
			{
				return false;
			}

			var diff = 0;

			for (var i = 0; i < leftBytes.Length; i++)
			{
				diff |= leftBytes[i] ^ rightBytes[i];
			}

			return diff == 0;
		}
	}
}
