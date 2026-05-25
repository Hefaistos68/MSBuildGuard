using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MSBuildGuard.Worker
{
	internal static class Program
	{
		private static async Task<int> Main(string[] args)
		{
			Console.InputEncoding = System.Text.Encoding.UTF8;
			Console.OutputEncoding = System.Text.Encoding.UTF8;

			if (args == null)
			{
				throw new ArgumentNullException(nameof(args));
			}

			var processor = new WorkerProcessor();

			if (args.Length >= 1)
			{
				var targetPath = args[0];

				WorkerRequest request;

				if (args.Length >= 3)
				{
					request = new WorkerRequest
					{
						Id      = "cli-1",
						Method  = WorkerProtocol.MethodCreateBaseline,
						Payload = new RequestPayload
						{
							TargetPath       = targetPath,
							ReviewerIdentity = args[1],
							OutputPath       = args[2]
						}
					};
				}
				else
				{
					request = new WorkerRequest
					{
						Id      = "cli-1",
						Method  = WorkerProtocol.MethodScan,
						Payload = new RequestPayload
						{
							TargetPath = targetPath
						}
					};
				}

				var options      = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
				var line         = JsonSerializer.Serialize(request, options);
				var response     = await processor.ProcessAsync(line, CancellationToken.None).ConfigureAwait(false);
				var responseLine = WorkerProcessor.Serialize(response);

				await Console.Out.WriteLineAsync(responseLine).ConfigureAwait(false);

				return response.Success ? 0 : 1;
			}

			while (true)
			{
				var line = await Console.In.ReadLineAsync().ConfigureAwait(false);

				if (line == null)
				{
					break;
				}

				var response = await processor.ProcessAsync(line, CancellationToken.None).ConfigureAwait(false);
				var responseLine = WorkerProcessor.Serialize(response);

				await Console.Out.WriteLineAsync(responseLine).ConfigureAwait(false);
			}

			return 0;
		}
	}
}
