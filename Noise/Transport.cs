using System;
using System.Diagnostics;

namespace Noise
{
	/// <summary>
	/// A pair of CipherState objects for encrypting transport messages.
	/// </summary>
	public interface Transport : IDisposable
	{
		/// <summary>
		/// Indicates if this Transport is one-way (supporting only a
		/// one-way stream of data from a sender to a recipient).
		/// </summary>
		bool IsOneWay { get; }

		/// <summary>
		/// Encrypts the payload and writes the ciphertext into message.
		/// </summary>
		int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> message);

		/// <summary>
		/// Decrypts the message and writes the plaintext into payload.
		/// </summary>
		int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payload);
	}

	internal sealed class Transport<CipherType> : Transport where CipherType : Cipher, new()
	{
		private readonly bool initiator;
		private readonly CipherState<CipherType> c1;
		private readonly CipherState<CipherType> c2;
		private bool disposed;

		public Transport(bool initiator, CipherState<CipherType> c1, CipherState<CipherType> c2)
		{
			this.initiator = initiator;
			this.c1 = c1 ?? throw new ArgumentNullException(nameof(c1));
			this.c2 = c2;
		}

		public bool IsOneWay => c2 == null;

		public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> message)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Transport<CipherType>));

			if (!initiator && IsOneWay)
			{
				throw new InvalidOperationException("Responder cannot write messages to a one-way stream.");
			}

			if (payload.Length + Aead.TagSize > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			if (payload.Length + Aead.TagSize > message.Length)
			{
				throw new ArgumentException("Message buffer does not have enough space to hold the ciphertext.");
			}

			var cipher = initiator ? c1 : c2;
			Debug.Assert(cipher.HasKey());

			return cipher.EncryptWithAd(null, payload, message);
		}

		public int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payload)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Transport<CipherType>));

			if (initiator && IsOneWay)
			{
				throw new InvalidOperationException("Initiator cannot read messages from a one-way stream.");
			}

			if (message.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Noise message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			if (message.Length < Aead.TagSize)
			{
				throw new ArgumentException($"Noise message must be greater than {Aead.TagSize} bytes in length.");
			}

			if (message.Length - Aead.TagSize > payload.Length)
			{
				throw new ArgumentException("Message buffer does not have enough space to hold the plaintext.");
			}

			var cipher = initiator ? c2 : c1;
			Debug.Assert(cipher.HasKey());

			return cipher.DecryptWithAd(null, message, payload);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				c1.Dispose();
				c2?.Dispose();
				disposed = true;
			}
		}
	}
}
