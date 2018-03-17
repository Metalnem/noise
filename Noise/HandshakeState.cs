using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

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
		(int, byte[], Transport) WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer);

		/// <summary>
		/// Takes a byte sequence containing a Noise handshake message,
		/// and a payloadBuffer to write the message's plaintext payload into.
		/// </summary>
		(int, byte[], Transport) ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer);
	}

	internal sealed class HandshakeState<CipherType, DhType, HashType> : HandshakeState
		where CipherType : Cipher, new()
		where DhType : Dh, new()
		where HashType : Hash, new()
	{
		private Dh dh = new DhType();
		private readonly SymmetricState<CipherType, DhType, HashType> state;
		private readonly bool initiator;
		private KeyPair e;
		private KeyPair s;
		private byte[] re;
		private byte[] rs;
		private readonly bool isOneWay;
		private readonly bool isPsk;
		private readonly Queue<MessagePattern> messagePatterns = new Queue<MessagePattern>();
		private readonly Queue<byte[]> psks = new Queue<byte[]>();
		private bool disposed;

		public HandshakeState(
			Protocol protocol,
			bool initiator,
			ReadOnlySpan<byte> prologue,
			ReadOnlySpan<byte> s,
			ReadOnlySpan<byte> rs,
			IEnumerable<byte[]> psks)
		{
			Debug.Assert(psks != null);

			if (!s.IsEmpty && s.Length != dh.DhLen)
			{
				throw new ArgumentException("Invalid local static DH private key.", nameof(s));
			}

			if (!rs.IsEmpty && rs.Length != dh.DhLen)
			{
				throw new ArgumentException("Invalid remote static DH public key.", nameof(rs));
			}

			state = new SymmetricState<CipherType, DhType, HashType>(protocol.Name);
			state.MixHash(prologue);

			this.initiator = initiator;
			this.s = s.IsEmpty ? null : dh.GenerateKeyPair(s);
			this.rs = rs.IsEmpty ? null : rs.ToArray();

			ProcessPreMessages(protocol.HandshakePattern);
			ProcessPreSharedKeys(protocol, psks);

			isOneWay = messagePatterns.Count == 1;
			isPsk = protocol.Modifiers != PatternModifiers.None;
		}

		private void ProcessPreMessages(HandshakePattern handshakePattern)
		{
			foreach (var preMessage in handshakePattern.Initiator.Tokens)
			{
				if (preMessage == Token.S)
				{
					state.MixHash(initiator ? this.s.PublicKey : rs);
				}
			}

			foreach (var preMessage in handshakePattern.Responder.Tokens)
			{
				if (preMessage == Token.S)
				{
					state.MixHash(initiator ? rs : this.s.PublicKey);
				}
			}
		}

		private void ProcessPreSharedKeys(Protocol protocol, IEnumerable<byte[]> psks)
		{
			var patterns = protocol.HandshakePattern.Patterns;
			var modifiers = protocol.Modifiers;
			var position = 0;

			foreach (var pattern in patterns)
			{
				var modified = pattern;

				if (position == 0 && modifiers.HasFlag(PatternModifiers.Psk0))
				{
					modified = modified.PrependPsk();
				}

				if (((int)modifiers & ((int)PatternModifiers.Psk1 << position)) != 0)
				{
					modified = modified.AppendPsk();
				}

				messagePatterns.Enqueue(modified);
				++position;
			}

			foreach (var psk in psks)
			{
				this.psks.Enqueue(psk);
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

		public (int, byte[], Transport) WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer)
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
					case Token.EE: DhAndMixKey(e, re); break;
					case Token.ES: ProcessES(); break;
					case Token.SE: ProcessSE(); break;
					case Token.SS: DhAndMixKey(s, rs); break;
					case Token.PSK: ProcessPSK(); break;
					default: throw new NotImplementedException();
				}
			}

			int bytesWritten = state.EncryptAndHash(payload, messageBuffer);
			byte[] handshakeHash = null;
			Transport transport = null;

			if (messagePatterns.Count == 0)
			{
				var (c1, c2) = state.Split();

				if (isOneWay)
				{
					c2.Dispose();
					c2 = null;
				}

				Debug.Assert(psks.Count == 0);

				handshakeHash = state.GetHandshakeHash();
				transport = new Transport<CipherType>(initiator, c1, c2);
			}

			return (message.Length - messageBuffer.Length + bytesWritten, handshakeHash, transport);
		}

		private Span<byte> WriteE(Span<byte> buffer)
		{
			e = dh.GenerateKeyPair();
			e.PublicKey.CopyTo(buffer);
			state.MixHash(e.PublicKey);

			if (isPsk)
			{
				state.MixKey(e.PublicKey);
			}

			return buffer.Slice(e.PublicKey.Length);
		}

		private Span<byte> WriteS(Span<byte> buffer)
		{
			var bytesWritten = state.EncryptAndHash(s.PublicKey, buffer);
			return buffer.Slice(bytesWritten);
		}

		public (int, byte[], Transport) ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(HandshakeState<CipherType, DhType, HashType>));

			var next = messagePatterns.Dequeue();

			foreach (var token in next.Tokens)
			{
				switch (token)
				{
					case Token.E: message = ReadE(message); break;
					case Token.S: message = ReadS(message); break;
					case Token.EE: DhAndMixKey(e, re); break;
					case Token.ES: ProcessES(); break;
					case Token.SE: ProcessSE(); break;
					case Token.SS: DhAndMixKey(s, rs); break;
					case Token.PSK: ProcessPSK(); break;
					default: throw new NotImplementedException();
				}
			}

			int bytesRead = state.DecryptAndHash(message, payloadBuffer);
			byte[] handshakeHash = null;
			Transport transport = null;

			if (messagePatterns.Count == 0)
			{
				var (c1, c2) = state.Split();

				if (isOneWay)
				{
					c2.Dispose();
					c2 = null;
				}

				Debug.Assert(psks.Count == 0);

				handshakeHash = state.GetHandshakeHash();
				transport = new Transport<CipherType>(initiator, c1, c2);
			}

			return (bytesRead, handshakeHash, transport);
		}

		private ReadOnlySpan<byte> ReadE(ReadOnlySpan<byte> buffer)
		{
			re = buffer.Slice(0, dh.DhLen).ToArray();
			state.MixHash(re);

			if (isPsk)
			{
				state.MixKey(re);
			}

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

		private void ProcessES()
		{
			if (initiator)
			{
				DhAndMixKey(e, rs);
			}
			else
			{
				DhAndMixKey(s, re);
			}
		}

		private void ProcessSE()
		{
			if (initiator)
			{
				DhAndMixKey(s, re);
			}
			else
			{
				DhAndMixKey(e, rs);
			}
		}

		private void ProcessPSK()
		{
			var psk = psks.Dequeue();
			state.MixKeyAndHash(psk);
			Array.Clear(psk, 0, psk.Length);
		}

		private void DhAndMixKey(KeyPair keyPair, ReadOnlySpan<byte> publicKey)
		{
			Span<byte> sharedKey = stackalloc byte[dh.DhLen];
			dh.Dh(keyPair, publicKey, sharedKey);
			state.MixKey(sharedKey);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				state.Dispose();
				e?.Dispose();
				s?.Dispose();

				foreach (var psk in psks)
				{
					Array.Clear(psk, 0, psk.Length);
				}

				disposed = true;
			}
		}
	}
}
