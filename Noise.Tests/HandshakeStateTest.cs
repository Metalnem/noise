
using System;
using System.IO;
using System.Reflection;
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

			var initBuffer = new byte[Constants.MaxMessageLength];
			var respBuffer = new byte[Constants.MaxMessageLength];

			foreach (var vector in json["vectors"])
			{
				var protocolName = GetString(vector, "protocol_name");
				var initPrologue = GetBytes(vector, "init_prologue");
				var initEphemeral = GetBytes(vector, "init_ephemeral");
				var respPrologue = GetBytes(vector, "resp_prologue");
				var respEphemeral = GetBytes(vector, "resp_ephemeral");
				var handshakeHash = GetBytes(vector, "handshake_hash");

				if (!Protocol.Create(protocolName, true, initPrologue, out var init))
				{
					continue;
				}

				if (!Protocol.Create(protocolName, false, respPrologue, out var resp))
				{
					continue;
				}

				var flags = BindingFlags.Instance | BindingFlags.NonPublic;
				var setDh = init.GetType().GetMethod("SetDh", flags);

				var initDh = new FixedKeyDh(initEphemeral);
				var respDh = new FixedKeyDh(respEphemeral);

				setDh.Invoke(init, new object[] { initDh });
				setDh.Invoke(resp, new object[] { respDh });

				ITransport respTransport = null;
				ITransport initTransport = null;

				foreach (var message in vector["messages"])
				{
					var payload = GetBytes(message, "payload");
					var ciphertext = GetBytes(message, "ciphertext");

					Span<byte> initMessage = null;
					Span<byte> respMessage = null;

					if (initTransport == null && respTransport == null)
					{
						initMessage = init.WriteMessage(payload, initBuffer, out initTransport);
						respMessage = resp.ReadMessage(initMessage, respBuffer, out respTransport);

						Swap(ref init, ref resp);
					}
					else
					{
						initMessage = initTransport.WriteMessage(payload, initBuffer);
						respMessage = respTransport.ReadMessage(initMessage, respBuffer);

						Swap(ref initTransport, ref respTransport);
					}

					Assert.Equal(ciphertext, initMessage.ToArray());
					Assert.Equal(payload, respMessage.ToArray());

					Swap(ref initBuffer, ref respBuffer);
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

		private static void Swap<T>(ref T x, ref T y)
		{
			var temp = x;
			x = y;
			y = temp;
		}
	}
}
