using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Noise
{
	/// <summary>
	/// A HandshakeState object contains a SymmetricState plus
	/// the local and remote keys (any of which may be empty),
	/// a boolean indicating the initiator or responder role, and
	/// the remaining portion of the handshake pattern.
	/// </summary>
	internal sealed class HandshakeState<CipherType, DhType, HashType> : IDisposable
		where CipherType : Cipher, new()
		where DhType : Dh, new()
		where HashType : Hash, new()
	{
		private static readonly Dictionary<Type, string> functionNames = new Dictionary<Type, string>
		{
			{typeof(Aes256Gcm), "AESGCM"},
			{typeof(ChaCha20Poly1305), "ChaChaPoly"},
			{typeof(Curve25519), "25519"},
			{typeof(Sha256), "SHA256"},
			{typeof(Sha512), "SHA512"},
			{typeof(Blake2b), "BLAKE2b"}
		};

		private readonly SymmetricState<CipherType, DhType, HashType> state;
		private readonly Dh dh;
		private readonly bool initiator;
		private readonly Queue<MessagePattern> messagePatterns;
		private KeyPair e;
		private byte[] re;
		private bool disposed;

		/// <summary>
		/// Initializes a new HandshakeState.
		/// </summary>
		public HandshakeState(HandshakePattern handshakePattern, bool initiator, byte[] prologue)
			: this(handshakePattern, initiator, prologue, new DhType())
		{
		}

		/// <summary>
		/// Initializes a new HandshakeState.
		/// </summary>
		internal HandshakeState(HandshakePattern handshakePattern, bool initiator, byte[] prologue, Dh dh)
		{
			var protocolName = GetProtocolName(handshakePattern.Name);

			state = new SymmetricState<CipherType, DhType, HashType>(protocolName);
			state.MixHash(prologue);

			this.dh = dh;
			this.initiator = initiator;

			messagePatterns = new Queue<MessagePattern>(handshakePattern.Patterns);
		}

		/// <summary>
		/// Takes a payload byte sequence which may be zero-length,
		/// and a messageBuffer to write the output into. 
		/// </summary>
		public Span<byte> WriteMessage(Span<byte> payload, Span<byte> messageBuffer, out Transport<CipherType> transport)
		{
			var next = messagePatterns.Dequeue();
			var message = messageBuffer;

			foreach (var token in next.Tokens)
			{
				switch (token)
				{
					case Token.E: messageBuffer = WriteE(messageBuffer); break;
					case Token.EE: WriteEE(); break;
					default: throw new NotImplementedException();
				}
			}

			var ciphertext = state.EncryptAndHash(payload, messageBuffer);
			transport = null;

			if (messagePatterns.Count == 0)
			{
				var (c1, c2) = state.Split();
				transport = new Transport<CipherType>(initiator, c1, c2);
			}

			return message.Slice(0, message.Length - messageBuffer.Length + ciphertext.Length);
		}

		private Span<byte> WriteE(Span<byte> buffer)
		{
			if (e != null)
			{
				throw new CryptographicException("Ephemeral key can be initialized only once.");
			}

			e = dh.GenerateKeyPair();
			e.PublicKey.CopyTo(buffer);
			state.MixHash(e.PublicKey);

			return buffer.Slice(e.PublicKey.Length);
		}

		private void WriteEE()
		{
			state.MixKey(dh.Dh(e, re));
		}

		/// <summary>
		/// Takes a byte sequence containing a Noise handshake message,
		/// and a payloadBuffer to write the message's plaintext payload into.
		/// </summary>
		public Span<byte> ReadMessage(Span<byte> message, Span<byte> payloadBuffer, out Transport<CipherType> transport)
		{
			var next = messagePatterns.Dequeue();

			foreach (var token in next.Tokens)
			{
				switch (token)
				{
					case Token.E: message = ReadE(message); break;
					case Token.EE: ReadEE(); break;
					default: throw new NotImplementedException();
				}
			}

			var payload = state.DecryptAndHash(message, payloadBuffer);
			transport = null;

			if (messagePatterns.Count == 0)
			{
				var (c1, c2) = state.Split();
				transport = new Transport<CipherType>(initiator, c1, c2);
			}

			return payload;
		}

		private Span<byte> ReadE(Span<byte> buffer)
		{
			if (re != null)
			{
				throw new CryptographicException("Remote ephemeral key can be initialized only once.");
			}

			re = buffer.Slice(0, dh.DhLen).ToArray();
			state.MixHash(re);

			return buffer.Slice(re.Length);
		}

		private void ReadEE()
		{
			state.MixKey(dh.Dh(e, re));
		}

		private static string GetFunctionName<T>()
		{
			return functionNames[typeof(T)];
		}

		private static byte[] GetProtocolName(string handshakePatternName)
		{
			string cipher = GetFunctionName<CipherType>();
			string dh = GetFunctionName<DhType>();
			string hash = GetFunctionName<HashType>();
			string protocolName = $"Noise_{handshakePatternName}_{dh}_{cipher}_{hash}";

			if (protocolName.Length > 255)
			{
				throw new ArgumentException("The Noise protocol name is too long.");
			}

			return Encoding.ASCII.GetBytes(protocolName);
		}

		/// <summary>
		/// Disposes the object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				state.Dispose();
				e?.Dispose();
				disposed = true;
			}
		}
	}
}
