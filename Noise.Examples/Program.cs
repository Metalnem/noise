using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace Noise.Examples
{
	public class Program
	{
		private static readonly Channel clientToServer = new Channel();
		private static readonly Channel serverToClient = new Channel();

		// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2b
		private static readonly Protocol protocol = new Protocol(
			HandshakePattern.IK,
			CipherFunction.ChaChaPoly,
			HashFunction.Blake2b,
			PatternModifiers.Psk2
		);

		private static readonly List<string> messages = new List<string>
		{
			"Now that the party is jumping",
			"With the bass kicked in, the fingers are pumpin'",
			"Quick to the point, to the point no faking",
			"I'm cooking MC's like a pound of bacon"
		};

		public static void Main(string[] args)
		{
			// Generate static keys for the client and the server.
			using (var clientStatic = KeyPair.Generate())
			using (var serverStatic = KeyPair.Generate())
			{
                unsafe
                {
                    var psk = new byte[32];

                    // Generate a random 32-byte pre-shared secret key.
                    using (var random = RandomNumberGenerator.Create())
                    {
                        random.GetBytes(psk);
                    }

                    // Initialize and run the client.
                    var xck = new Span<byte>(clientStatic.PrivateKey, KeyPair.DhLen).ToArray();
                    var client = Task.Run((Func<Task?>) (() => Client(xck, serverStatic.PublicKey, Singleton(psk))));

                    // Initialize and run the server.
					var xsk = new Span<byte>(serverStatic.PrivateKey, KeyPair.DhLen).ToArray();
                    var server = Task.Run((Func<Task?>) (() => Server(xsk, Singleton(psk))));

                    client.GetAwaiter().GetResult();
                }
            }
		}

		private static async Task Client(byte[] s, byte[] rs, IEnumerable<byte[]> psks)
		{
			var buffer = new byte[Protocol.MaxMessageLength];

			using (var handshakeState = protocol.Create(true, s: s, rs: rs, psks: psks))
			{
				// Send the first handshake message to the server.
				var (bytesWritten, _, _) = handshakeState.WriteMessage(null, buffer);
				await clientToServer.Send(Slice(buffer, bytesWritten));

				// Receive the second handshake message from the server.
				var received = await serverToClient.Receive();
				var (_, _, transport) = handshakeState.ReadMessage(received, buffer);

				// Handshake complete, switch to transport mode.
				using (transport)
				{
					foreach (var message in messages)
					{
						Memory<byte> request = Encoding.UTF8.GetBytes(message);

						// Send the message to the server.
						bytesWritten = transport.WriteMessage(request.Span, buffer);
						await clientToServer.Send(Slice(buffer, bytesWritten));

						// Receive the response and print it to the standard output.
						var response = await serverToClient.Receive();
						var bytesRead = transport.ReadMessage(response, buffer);

						Console.WriteLine(Encoding.UTF8.GetString(Slice(buffer, bytesRead)));
					}
				}
			}
		}

		private static async Task Server(byte[] s, IEnumerable<byte[]> psks)
		{
			var buffer = new byte[Protocol.MaxMessageLength];

			using (var handshakeState = protocol.Create(false, s: s, psks: psks))
			{
				// Receive the first handshake message from the client.
				var received = await clientToServer.Receive();
				handshakeState.ReadMessage(received, buffer);

				// Send the second handshake message to the client.
				var (bytesWritten, _, transport) = handshakeState.WriteMessage(null, buffer);
				await serverToClient.Send(Slice(buffer, bytesWritten));

				// Handshake complete, switch to transport mode.
				using (transport)
				{
					for (; ; )
					{
						// Receive the message from the client.
						var request = await clientToServer.Receive();
						var bytesRead = transport.ReadMessage(request, buffer);

						// Echo the message back to the client.
						bytesWritten = transport.WriteMessage(Slice(buffer, bytesRead), buffer);
						await serverToClient.Send(Slice(buffer, bytesWritten));
					}
				}
			}
		}

		private static IEnumerable<T> Singleton<T>(T item)
		{
			yield return item;
		}

		private static byte[] Slice(byte[] array, int length)
		{
			return array.AsSpan(0, length).ToArray();
		}

		// Channel simulates the network between the client and the server.
		private class Channel
		{
			private readonly BufferBlock<byte[]> buffer = new BufferBlock<byte[]>();

			public async Task Send(byte[] message)
			{
				await buffer.SendAsync(message);
			}

			public async Task<byte[]> Receive()
			{
				return await buffer.ReceiveAsync();
			}
		}
	}
}
