using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class HandshakeStateTest
	{
		private static byte[] initBuffer = new byte[Protocol.MaxMessageLength];
		private static byte[] respBuffer = new byte[Protocol.MaxMessageLength];

		[Fact] public void TestCacophony() => Test("Cacophony.txt");
		[Fact] public void TestMultipsk() => Test("Multipsk.txt");

		private void Test(string file)
		{
			var s = File.ReadAllText(file);
			var json = JObject.Parse(s);

			foreach (var vector in json["vectors"])
			{
				var protocolName = GetString(vector, "protocol_name");

				if (protocolName.Contains("448") || protocolName.Contains("BLAKE2s"))
				{
					continue;
				}

				var initPrologue = GetBytes(vector, "init_prologue");
				var initPsks = GetPsks(vector, "init_psks");
				var initStatic = GetBytes(vector, "init_static");
				var initEphemeral = GetBytes(vector, "init_ephemeral");
				var initRemoteStatic = GetBytes(vector, "init_remote_static");
				var respPrologue = GetBytes(vector, "resp_prologue");
				var respPsks = GetPsks(vector, "resp_psks");
				var respStatic = GetBytes(vector, "resp_static");
				var respEphemeral = GetBytes(vector, "resp_ephemeral");
				var respRemoteStatic = GetBytes(vector, "resp_remote_static");
				var handshakeHash = GetBytes(vector, "handshake_hash");

				var protocol = Protocol.Parse(protocolName.AsReadOnlySpan());

				var init = protocol.Create(true, initPrologue, initStatic, initRemoteStatic, initPsks);
				var resp = protocol.Create(false, respPrologue, respStatic, respRemoteStatic, respPsks);

				var flags = BindingFlags.Instance | BindingFlags.NonPublic;
				var setDh = init.GetType().GetMethod("SetDh", flags);

				setDh.Invoke(init, new object[] { new FixedKeyDh(initEphemeral) });
				setDh.Invoke(resp, new object[] { new FixedKeyDh(respEphemeral) });

				Transport initTransport = null;
				Transport respTransport = null;

				byte[] initHandshakeHash = null;
				byte[] respHandshakeHash = null;

				foreach (var message in vector["messages"])
				{
					var payload = GetBytes(message, "payload");
					var ciphertext = GetBytes(message, "ciphertext");

					Span<byte> initMessage = null;
					Span<byte> respMessage = null;

					int initMessageSize;
					int respMessageSize;

					if (initTransport == null && respTransport == null)
					{
						(initMessageSize, initHandshakeHash, initTransport) = init.WriteMessage(payload, initBuffer);
						initMessage = initBuffer.AsSpan().Slice(0, initMessageSize);

						(respMessageSize, respHandshakeHash, respTransport) = resp.ReadMessage(initMessage, respBuffer);
						respMessage = respBuffer.AsSpan().Slice(0, respMessageSize);
					}
					else
					{
						initMessageSize = initTransport.WriteMessage(payload, initBuffer);
						initMessage = initBuffer.AsSpan().Slice(0, initMessageSize);

						respMessageSize = respTransport.ReadMessage(initMessage, respBuffer);
						respMessage = respBuffer.AsSpan().Slice(0, respMessageSize);
					}

					Assert.Equal(ciphertext, initMessage.ToArray());
					Assert.Equal(payload, respMessage.ToArray());

					Swap(ref initBuffer, ref respBuffer);
					Swap(ref init, ref resp);

					if (initTransport != null && !initTransport.IsOneWay)
					{
						Swap(ref initTransport, ref respTransport);
					}
				}

				if (handshakeHash.Length > 0)
				{
					Assert.Equal(handshakeHash, initHandshakeHash);
					Assert.Equal(handshakeHash, respHandshakeHash);
				}

				init.Dispose();
				resp.Dispose();

				initTransport.Dispose();
				respTransport.Dispose();
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

		private static List<byte[]> GetPsks(JToken token, string property)
		{
			return token[property]?.Select(psk => Hex.Decode((string)psk)).ToList();
		}

		private static void Swap<T>(ref T x, ref T y)
		{
			var temp = x;
			x = y;
			y = temp;
		}
	}
}
