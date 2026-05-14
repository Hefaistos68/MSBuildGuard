using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Tests for <see cref="JsonSignatureService"/>.
	/// </summary>
	[TestFixture]
	public sealed class JsonSignatureServiceTests
	{
		private sealed class DemoPayload
		{
			public string Name { get; set; } = string.Empty;

			public int Count { get; set; }
		}

		/// <summary>
		/// Verifies signed envelope contains signature and payload object wrapper.
		/// </summary>
		[Test]
		public void CreateSignedEnvelopeJson_ShouldContainSignatureAndJsonBlock()
		{
			var service = new JsonSignatureService();
			var payload = new DemoPayload
			{
				Name  = "alpha",
				Count = 7
			};

			var envelope = service.CreateSignedEnvelopeJson(payload, "test-key");

			envelope.ShouldContain("\"SignatureV1\"");
			envelope.ShouldContain("\"JSON\"");
			envelope.ShouldContain("\"Name\": \"alpha\"");
		}

		/// <summary>
		/// Verifies valid signed envelopes can be verified and extracted.
		/// </summary>
		[Test]
		public void TryVerifyAndExtract_ShouldReturnPayload_WhenSignatureIsValid()
		{
			var service = new JsonSignatureService();
			var payload = new DemoPayload
			{
				Name  = "beta",
				Count = 42
			};
			var envelope = service.CreateSignedEnvelopeJson(payload, "my-key");

			var isValid = service.TryVerifyAndExtract<DemoPayload>(envelope, "my-key", out var extracted);

			isValid.ShouldBeTrue();
			extracted.ShouldNotBeNull();
			extracted.Name.ShouldBe("beta");
			extracted.Count.ShouldBe(42);
		}

		/// <summary>
		/// Verifies tampered payload content fails signature validation.
		/// </summary>
		[Test]
		public void TryVerifyAndExtract_ShouldFail_WhenPayloadIsTampered()
		{
			var service = new JsonSignatureService();
			var payload = new DemoPayload
			{
				Name  = "gamma",
				Count = 10
			};
			var envelope = service.CreateSignedEnvelopeJson(payload, "my-key");
			var tampered = envelope.Replace("\"Count\": 10", "\"Count\": 11");

			var isValid = service.TryVerifyAndExtract<DemoPayload>(tampered, "my-key", out var extracted);

			isValid.ShouldBeFalse();
			extracted.ShouldBeNull();
		}
	}
}
