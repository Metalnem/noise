using System;
using System.IO;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class HandshakeStateTest
	{
		[Fact]
		public void TestHandshake()
		{
			var s = File.ReadAllText("Cacophony.txt");
			var json = JObject.Parse(s);

			foreach (var vector in json["vectors"])
			{
				var protocolName = GetString(vector, "protocol_name");
				var initPrologue = GetBytes(vector, "init_prologue");
				var initEphemeral = GetBytes(vector, "init_ephemeral");
				var respPrologue = GetBytes(vector, "resp_prologue");
				var respEphemeral = GetBytes(vector, "resp_ephemeral");
				var handshakeHash = GetBytes(vector, "handshake_hash");

				foreach (var message in vector["messages"])
				{
					var payload = GetBytes(message, "payload");
					var ciphertext = GetBytes(message, "ciphertext");
				}
			}
		}

		private static string GetString(JToken token, string property)
		{
			return (string)token[property] ?? String.Empty;
		}

		private static byte[] GetBytes(JToken token, string property)
		{
			return Hex.Decode(GetString(token, property));
		}
	}
}
