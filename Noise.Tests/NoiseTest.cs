using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class NoiseTest
	{
		private static byte[] initBuffer = new byte[Protocol.MaxMessageLength];
		private static byte[] respBuffer = new byte[Protocol.MaxMessageLength];

		[Fact] public void TestCacophony() => Test("Vectors/cacophony.txt");
		[Fact] public void TestMultipsk() => Test("Vectors/snow-multipsk.txt");

		private void Test(string file)
		{
			var s = File.ReadAllText(file);
			var json = JObject.Parse(s);

			foreach (var vector in json["vectors"])
			{
				var protocolName = GetString(vector, "protocol_name");

				if (protocolName.Contains("448"))
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

				var protocol = Protocol.Parse(protocolName.AsSpan());

                HandshakeState init;
                HandshakeState resp;
                unsafe
                {
                    fixed (byte* iss = initStatic)
                    fixed (byte* rss = respStatic)
                    {
                        init = protocol.Create(true, initPrologue, iss, initStatic.Length, initRemoteStatic, initPsks);
                        resp = protocol.Create(false, respPrologue, rss, respStatic.Length, respRemoteStatic, respPsks);    
                    }
                }

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
						initMessage = initBuffer.AsSpan(0, initMessageSize);

						(respMessageSize, respHandshakeHash, respTransport) = resp.ReadMessage(initMessage, respBuffer);
						respMessage = respBuffer.AsSpan(0, respMessageSize);
					}
					else
					{
						initMessageSize = initTransport.WriteMessage(payload, initBuffer);
						initMessage = initBuffer.AsSpan(0, initMessageSize);

						respMessageSize = respTransport.ReadMessage(initMessage, respBuffer);
						respMessage = respBuffer.AsSpan(0, respMessageSize);
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

		[Fact]
		public void TestFallback()
		{
			var s = File.ReadAllText("Vectors/noise-c-fallback.txt");
			var json = JObject.Parse(s);

			foreach (var vector in json["vectors"])
			{
				var protocolName = GetString(vector, "name");

				if (protocolName.Contains("PSK") || protocolName.Contains("448"))
				{
					continue;
				}

				var initPrologue = GetBytes(vector, "init_prologue");
				var initStatic = GetBytes(vector, "init_static");
				var initEphemeral = GetBytes(vector, "init_ephemeral");
				var initRemoteStatic = GetBytes(vector, "init_remote_static");
				var respPrologue = GetBytes(vector, "resp_prologue");
				var respStatic = GetBytes(vector, "resp_static");
				var respEphemeral = GetBytes(vector, "resp_ephemeral");
				var respRemoteStatic = GetBytes(vector, "resp_remote_static");
				var handshakeHash = GetBytes(vector, "handshake_hash");

				var fallbackProtocol = Protocol.Parse(protocolName.AsSpan());
				var initialProtocol = new Protocol(HandshakePattern.IK, fallbackProtocol.Cipher, fallbackProtocol.Hash);

                HandshakeState init;
                HandshakeState resp;
                unsafe
                {
                    fixed (byte* iss = initStatic)
                    fixed (byte* rss = respStatic)
                    {
                        init = initialProtocol.Create(true, initPrologue, iss, initStatic.Length, initRemoteStatic);
                        resp = initialProtocol.Create(false, respPrologue, rss, respStatic.Length, respRemoteStatic);    
                    }
                }
				
				var flags = BindingFlags.Instance | BindingFlags.NonPublic;
				var setDh = init.GetType().GetMethod("SetDh", flags);

				setDh.Invoke(init, new object[] { new FixedKeyDh(initEphemeral) });
				setDh.Invoke(resp, new object[] { new FixedKeyDh(respEphemeral) });

				Transport initTransport = null;
				Transport respTransport = null;

				byte[] initHandshakeHash = null;
				byte[] respHandshakeHash = null;

				bool fallback = false;

				foreach (var message in vector["messages"])
				{
					var payload = GetBytes(message, "payload");
					var ciphertext = GetBytes(message, "ciphertext");

					Span<byte> initMessage = null;
					Span<byte> respMessage = null;

					int initMessageSize;
					int respMessageSize;

					if (!fallback)
					{
						(initMessageSize, initHandshakeHash, initTransport) = init.WriteMessage(payload, initBuffer);
						initMessage = initBuffer.AsSpan(0, initMessageSize);

						try
						{
							resp.ReadMessage(initMessage, respBuffer);
						}
						catch (CryptographicException)
						{
							var initConfig = new ProtocolConfig { Prologue = initPrologue, LocalStatic = initStatic };
							init.Fallback(fallbackProtocol, initConfig);

							var respConfig = new ProtocolConfig { Prologue = respPrologue, LocalStatic = respStatic };
							resp.Fallback(fallbackProtocol, respConfig);

							respMessage = payload;
							fallback = true;
						}
					}
					else if (initTransport == null && respTransport == null)
					{
						(initMessageSize, initHandshakeHash, initTransport) = init.WriteMessage(payload, initBuffer);
						initMessage = initBuffer.AsSpan(0, initMessageSize);

						(respMessageSize, respHandshakeHash, respTransport) = resp.ReadMessage(initMessage, respBuffer);
						respMessage = respBuffer.AsSpan(0, respMessageSize);
					}
					else
					{
						initMessageSize = initTransport.WriteMessage(payload, initBuffer);
						initMessage = initBuffer.AsSpan(0, initMessageSize);

						respMessageSize = respTransport.ReadMessage(initMessage, respBuffer);
						respMessage = respBuffer.AsSpan(0, respMessageSize);
					}

					Assert.Equal(ciphertext, initMessage.ToArray());
					Assert.Equal(payload, respMessage.ToArray());

					Swap(ref initBuffer, ref respBuffer);
					Swap(ref init, ref resp);
					Swap(ref initTransport, ref respTransport);
				}

				Assert.Equal(handshakeHash, initHandshakeHash);
				Assert.Equal(handshakeHash, respHandshakeHash);

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
