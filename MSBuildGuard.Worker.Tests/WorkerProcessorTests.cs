using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Shouldly;
using MSBuildGuard.Worker;

namespace MSBuildGuard.Worker.Tests
{
	/// <summary>
	/// Unit tests verifying the request processing logic in <see cref="WorkerProcessor"/>.
	/// </summary>
	[TestFixture]
	public sealed class WorkerProcessorTests
	{
		/// <summary>
		/// Verifies that <see cref="WorkerProcessor.ProcessAsync"/> returns an invalid envelope error when the input is null or whitespace.
		/// </summary>
		/// <param name="input">Whitespace or empty input.</param>
		/// <returns>A task tracking execution.</returns>
		[TestCase(null)]
		[TestCase("")]
		[TestCase("   ")]
		public async Task ProcessAsync_NullOrWhitespaceInput_ReturnsInvalidEnvelopeError(string? input)
		{
			var processor = new WorkerProcessor();

			var response = await processor.ProcessAsync(input!, CancellationToken.None);

			response.ShouldNotBeNull();
			response.Success.ShouldBeFalse();
			response.Error.ShouldNotBeNull();
			response.Error.Code.ShouldBe(WorkerErrorCodes.InvalidEnvelope);
		}

		/// <summary>
		/// Verifies that <see cref="WorkerProcessor.ProcessAsync"/> returns an invalid envelope error when the JSON is malformed.
		/// </summary>
		/// <returns>A task tracking execution.</returns>
		[Test]
		public async Task ProcessAsync_MalformedJson_ReturnsInvalidEnvelopeError()
		{
			var processor = new WorkerProcessor();

			var response = await processor.ProcessAsync("{ invalid json }", CancellationToken.None);

			response.ShouldNotBeNull();
			response.Success.ShouldBeFalse();
			response.Error.ShouldNotBeNull();
			response.Error.Code.ShouldBe(WorkerErrorCodes.InvalidEnvelope);
		}

		/// <summary>
		/// Verifies that <see cref="WorkerProcessor.ProcessAsync"/> returns an unsupported version error when the protocol version is mismatch.
		/// </summary>
		/// <returns>A task tracking execution.</returns>
		[Test]
		public async Task ProcessAsync_UnsupportedProtocolVersion_ReturnsUnsupportedVersionError()
		{
			var processor = new WorkerProcessor();

			var request = new WorkerRequest
			{
				Version = "99.0",
				Id      = "req-1",
				Method  = WorkerProtocol.MethodScan,
				Payload = new RequestPayload { TargetPath = "somepath.sln" }
			};

			var line = JsonSerializer.Serialize(request);

			var response = await processor.ProcessAsync(line, CancellationToken.None);

			response.ShouldNotBeNull();
			response.Success.ShouldBeFalse();
			response.Error.ShouldNotBeNull();
			response.Error.Code.ShouldBe(WorkerErrorCodes.UnsupportedVersion);
		}

		/// <summary>
		/// Verifies that <see cref="WorkerProcessor.ProcessAsync"/> returns an invalid argument error when targetPath is missing.
		/// </summary>
		/// <returns>A task tracking execution.</returns>
		[Test]
		public async Task ProcessAsync_MissingTargetPath_ReturnsInvalidArgumentError()
		{
			var processor = new WorkerProcessor();

			var request = new WorkerRequest
			{
				Id      = "req-1",
				Method  = WorkerProtocol.MethodScan,
				Payload = new RequestPayload { TargetPath = string.Empty }
			};

			var line = JsonSerializer.Serialize(request);

			var response = await processor.ProcessAsync(line, CancellationToken.None);

			response.ShouldNotBeNull();
			response.Success.ShouldBeFalse();
			response.Error.ShouldNotBeNull();
			response.Error.Code.ShouldBe(WorkerErrorCodes.InvalidArgument);
		}

		/// <summary>
		/// Verifies that <see cref="WorkerProcessor.ProcessAsync"/> returns an invalid argument error when an unknown method is requested.
		/// </summary>
		/// <returns>A task tracking execution.</returns>
		[Test]
		public async Task ProcessAsync_UnknownMethod_ReturnsInvalidArgumentError()
		{
			var processor = new WorkerProcessor();

			var request = new WorkerRequest
			{
				Id      = "req-1",
				Method  = "unknownMethodName",
				Payload = new RequestPayload { TargetPath = "somepath.sln" }
			};

			var line = JsonSerializer.Serialize(request);

			var response = await processor.ProcessAsync(line, CancellationToken.None);

			response.ShouldNotBeNull();
			response.Success.ShouldBeFalse();
			response.Error.ShouldNotBeNull();
			response.Error.Code.ShouldBe(WorkerErrorCodes.InvalidArgument);
		}

		/// <summary>
		/// Verifies that <see cref="WorkerProcessor.ProcessAsync"/> returns an invalid argument error when targetPath is not found on disk.
		/// </summary>
		/// <returns>A task tracking execution.</returns>
		[Test]
		public async Task ProcessAsync_NonExistentTargetPath_ReturnsInvalidArgumentError()
		{
			var processor = new WorkerProcessor();

			var request = new WorkerRequest
			{
				Id      = "req-1",
				Method  = WorkerProtocol.MethodScan,
				Payload = new RequestPayload { TargetPath = Path.Combine(Directory.GetCurrentDirectory(), Guid.NewGuid().ToString() + ".sln") }
			};

			var line = JsonSerializer.Serialize(request);

			var response = await processor.ProcessAsync(line, CancellationToken.None);

			response.ShouldNotBeNull();
			response.Success.ShouldBeFalse();
			response.Error.ShouldNotBeNull();
			response.Error.Code.ShouldBe(WorkerErrorCodes.InvalidArgument);
		}
	}
}
