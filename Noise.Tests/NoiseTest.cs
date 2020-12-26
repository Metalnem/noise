using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
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

				if (protocolName.Contains("AESGCM") && !Libsodium.IsAes256GcmAvailable)
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

				if (protocolName.Contains("AESGCM") && !Libsodium.IsAes256GcmAvailable)
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

				var init = initialProtocol.Create(true, initPrologue, initStatic, initRemoteStatic);
				var resp = initialProtocol.Create(false, respPrologue, respStatic, respRemoteStatic);

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

		[Fact]
		public void TestOutOfOrder()
		{
			Span<byte> buffer1 = new byte[4098];
			Span<byte> buffer2 = new byte[4098];

			byte[] psk;
			using(var rnd = RandomNumberGenerator.Create())
				psk = new byte[32];

			var initiator_static = KeyPair.Generate();
			var responder_static = KeyPair.Generate();

			var protocol = Protocol.Parse("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b".AsSpan());

			var identifier = Encoding.UTF8.GetBytes("out-of-order test");

			var initiator = protocol.Create(true, identifier,
				initiator_static.PrivateKey,  responder_static.PublicKey, new[] { psk });

			var responder = protocol.Create(false, identifier,
				responder_static.PrivateKey, null, new[] { psk });

			int bytesWritten, bytesRead;
			Transport initiator_transport;
			Transport responder_transport;

			//handshake
			(bytesWritten, _, _) = initiator.WriteMessage(Span<byte>.Empty, buffer1);
			Assert.True(bytesWritten > 0);

			(bytesRead, _, _) = responder.ReadMessage(buffer1.Slice(0, bytesWritten), Span<byte>.Empty);
			Assert.True(bytesRead == 0);

			(bytesWritten, _, responder_transport) = responder.WriteMessage(Span<byte>.Empty, buffer1);
			Assert.True(bytesWritten > 0);
			Assert.NotNull(responder_transport);

			(bytesRead, _, initiator_transport) = initiator.ReadMessage(buffer1.Slice(0, bytesWritten), Span<byte>.Empty);
			Assert.True(bytesRead == 0);
			Assert.NotNull(initiator_transport);

			//test: exchange single empty message from initiator to responder and back
			//wireguard: The responder must wait to use the new session until it has recieved one encrypted session packet from the initiator, in order to provide key confirmation. 
			ulong counter;

			bytesWritten = initiator_transport.WriteMessage(Span<byte>.Empty, buffer1, out counter);
			Assert.Equal(0, (int)counter);
			Assert.True(bytesWritten == 16);

			bytesRead = responder_transport.ReadMessage(counter, buffer1.Slice(0, bytesWritten), buffer2);
			Assert.Equal(0, bytesRead);

			bytesWritten = responder_transport.WriteMessage(Span<byte>.Empty, buffer1, out counter);
			Assert.Equal(0, (int)counter);
			Assert.True(bytesWritten == 16);

			bytesRead = initiator_transport.ReadMessage(counter, buffer1.Slice(0, bytesWritten), buffer2);
			Assert.Equal(0, bytesRead);


			//out-of-order messages
			var messages = new List<byte[]>();

			for (int i = 0; i < 5; i++)
			{
				bytesWritten = initiator_transport.WriteMessage(Encoding.UTF8.GetBytes($"Hallo {i}"), buffer1, out counter);
				Assert.Equal(i+1, (int)counter);

				messages.Add(buffer1.Slice(0, bytesWritten).ToArray());
			}

			bytesWritten = responder_transport.ReadMessage(1, messages[0], buffer2);
			Assert.Equal(7, bytesWritten);
			Assert.Equal("Hallo 0", Encoding.UTF8.GetString(buffer2.Slice(0, bytesWritten).ToArray()));

			for (int i = messages.Count - 2; i > 0; i--)
			{
				bytesWritten = responder_transport.ReadMessage((ulong)i+1, messages[i], buffer2);
				Assert.Equal(7, bytesWritten);
				Assert.Equal($"Hallo {i}", Encoding.UTF8.GetString(buffer2.Slice(0, bytesWritten).ToArray()));
			}

			bytesWritten = responder_transport.ReadMessage(5, messages[4], buffer2);
			Assert.Equal(7, bytesWritten);
			Assert.Equal("Hallo 4", Encoding.UTF8.GetString(buffer2.Slice(0, bytesWritten).ToArray()));

			initiator.Dispose();
			responder.Dispose();

			initiator_transport.Dispose();
			responder_transport.Dispose();
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
