using System;
using System.Collections.Generic;
using System.Linq;
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
	public interface HandshakeState : IDisposable
	{
		/// <summary>
		/// Takes a payload byte sequence which may be zero-length,
		/// and a messageBuffer to write the output into. 
		/// </summary>
		(int, Transport) WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer);

		/// <summary>
		/// Takes a byte sequence containing a Noise handshake message,
		/// and a payloadBuffer to write the message's plaintext payload into.
		/// </summary>
		(int, Transport) ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer);

		/// <summary>
		/// Returns h. This function should only be called at the end of
		/// a handshake, i.e. after the Split() function has been called.
		/// </summary>
		byte[] GetHandshakeHash();
	}

	internal sealed class HandshakeState<CipherType, DhType, HashType> : HandshakeState
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

		private Dh dh = new DhType();
		private readonly SymmetricState<CipherType, DhType, HashType> state;
		private readonly bool initiator;
		private readonly Queue<MessagePattern> messagePatterns;
		private readonly bool isOneWay;
		private KeyPair e;
		private KeyPair s;
		private byte[] re;
		private byte[] rs;
		private bool disposed;

		public HandshakeState(
			HandshakePattern handshakePattern,
			bool initiator,
			ReadOnlySpan<byte> prologue,
			KeyPair s,
			ReadOnlySpan<byte> rs)
		{
			var protocolName = GetProtocolName(handshakePattern.Name);

			state = new SymmetricState<CipherType, DhType, HashType>(protocolName);
			state.MixHash(prologue);

			this.initiator = initiator;
			messagePatterns = new Queue<MessagePattern>(handshakePattern.Patterns);
			isOneWay = messagePatterns.Count == 1;

			this.s = s;
			this.rs = rs.ToArray();

			foreach (var preMessage in handshakePattern.Initiator.Tokens)
			{
				if (preMessage == Token.S)
				{
					state.MixHash(initiator ? s.PublicKey : rs);
				}
			}

			foreach (var preMessage in handshakePattern.Responder.Tokens)
			{
				if (preMessage == Token.S)
				{
					state.MixHash(initiator ? rs : s.PublicKey);
				}
			}
		}

		/// <summary>
		/// Overrides the DH function. It should only be used
		/// from Noise.Tests to fix the ephemeral private key.
		/// </summary>
		internal void SetDh(Dh dh)
		{
			this.dh = dh;
		}

		public (int, Transport) WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(HandshakeState<CipherType, DhType, HashType>));

			var next = messagePatterns.Dequeue();
			var message = messageBuffer;

			foreach (var token in next.Tokens)
			{
				switch (token)
				{
					case Token.E: messageBuffer = WriteE(messageBuffer); break;
					case Token.S: messageBuffer = WriteS(messageBuffer); break;
					case Token.EE: WriteEE(); break;
					case Token.ES: WriteES(); break;
					case Token.SE: WriteSE(); break;
					case Token.SS: WriteSS(); break;
					default: throw new NotImplementedException();
				}
			}

			int bytesWritten = state.EncryptAndHash(payload, messageBuffer);
			Transport transport = null;

			if (messagePatterns.Count == 0)
			{
				var (c1, c2) = state.Split();

				if (isOneWay)
				{
					c2.Dispose();
					c2 = null;
				}

				transport = new Transport<CipherType>(initiator, c1, c2);
			}

			return (message.Length - messageBuffer.Length + bytesWritten, transport);
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

		private Span<byte> WriteS(Span<byte> buffer)
		{
			var bytesWritten = state.EncryptAndHash(s.PublicKey, buffer);
			return buffer.Slice(bytesWritten);
		}

		private void WriteEE()
		{
			MixKey(e, re);
		}

		private void WriteES()
		{
			if (initiator)
			{
				MixKey(e, rs);
			}
			else
			{
				MixKey(s, re);
			}
		}

		private void WriteSE()
		{
			if (initiator)
			{
				MixKey(s, re);
			}
			else
			{
				MixKey(e, rs);
			}
		}

		private void WriteSS()
		{
			MixKey(s, rs);
		}

		public (int, Transport) ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(HandshakeState<CipherType, DhType, HashType>));

			var next = messagePatterns.Dequeue();

			foreach (var token in next.Tokens)
			{
				switch (token)
				{
					case Token.E: message = ReadE(message); break;
					case Token.S: message = ReadS(message); break;
					case Token.EE: ReadEE(); break;
					case Token.ES: ReadES(); break;
					case Token.SE: ReadSE(); break;
					case Token.SS: ReadSS(); break;
					default: throw new NotImplementedException();
				}
			}

			int bytesRead = state.DecryptAndHash(message, payloadBuffer);
			Transport transport = null;

			if (messagePatterns.Count == 0)
			{
				var (c1, c2) = state.Split();

				if (isOneWay)
				{
					c2.Dispose();
					c2 = null;
				}

				transport = new Transport<CipherType>(initiator, c1, c2);
			}

			return (bytesRead, transport);
		}

		private ReadOnlySpan<byte> ReadE(ReadOnlySpan<byte> buffer)
		{
			if (re != null)
			{
				throw new CryptographicException("Remote ephemeral key can be initialized only once.");
			}

			re = buffer.Slice(0, dh.DhLen).ToArray();
			state.MixHash(re);

			return buffer.Slice(re.Length);
		}

		private ReadOnlySpan<byte> ReadS(ReadOnlySpan<byte> message)
		{
			var length = state.HasKey() ? dh.DhLen + Aead.TagSize : dh.DhLen;
			var temp = message.Slice(0, length);

			rs = new byte[dh.DhLen];
			state.DecryptAndHash(temp, rs);

			return message.Slice(length);
		}

		private void ReadEE()
		{
			MixKey(e, re);
		}

		private void ReadES()
		{
			if (initiator)
			{
				MixKey(e, rs);
			}
			else
			{
				MixKey(s, re);
			}
		}

		private void ReadSE()
		{
			if (initiator)
			{
				MixKey(s, re);
			}
			else
			{
				MixKey(e, rs);
			}
		}

		private void ReadSS()
		{
			MixKey(s, rs);
		}

		public byte[] GetHandshakeHash()
		{
			return state.GetHandshakeHash();
		}

		private void MixKey(KeyPair keyPair, ReadOnlySpan<byte> publicKey)
		{
			Span<byte> sharedKey = stackalloc byte[dh.DhLen];
			dh.Dh(keyPair, publicKey, sharedKey);
			state.MixKey(sharedKey);
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

			if (protocolName.Length > Protocol.MaxProtocolNameLength)
			{
				throw new ArgumentException("The Noise protocol name is too long.");
			}

			return Encoding.ASCII.GetBytes(protocolName);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				state.Dispose();
				e?.Dispose();
				s?.Dispose();
				disposed = true;
			}
		}
	}
}
