
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

			var initBuffer = new byte[Constants.MaxMessageLength];
			var respBuffer = new byte[Constants.MaxMessageLength];

			foreach (var vector in json["vectors"])
			{
				var protocolName = GetString(vector, "protocol_name");

				if (protocolName != "Noise_NN_25519_AESGCM_BLAKE2b")
				{
					continue;
				}

				var initPrologue = GetBytes(vector, "init_prologue");
				var initEphemeral = GetBytes(vector, "init_ephemeral");
				var respPrologue = GetBytes(vector, "resp_prologue");
				var respEphemeral = GetBytes(vector, "resp_ephemeral");
				var handshakeHash = GetBytes(vector, "handshake_hash");

				var initDh = new FixedKeyDh(initEphemeral);
				var respDh = new FixedKeyDh(respEphemeral);

				var init = new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(HandshakePattern.NN, true, initPrologue, initDh);
				var resp = new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(HandshakePattern.NN, false, respPrologue, respDh);

				Transport<Aes256Gcm> initTransport = null;
				Transport<Aes256Gcm> respTransport = null;

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
