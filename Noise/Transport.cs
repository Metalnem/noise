using System;

namespace Noise
{
	/// <summary>
	/// A pair of CipherState objects for encrypting transport messages.
	/// </summary>
	public interface Transport : IDisposable
	{
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
			this.c1 = c1;
			this.c2 = c2;
		}

		public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> message)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Transport<CipherType>));

			var cipher = initiator ? c2 : c1;
			return cipher.EncryptWithAd(null, payload, message);
		}

		public int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payload)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Transport<CipherType>));

			var cipher = initiator ? c1 : c2;
			return cipher.DecryptWithAd(null, message, payload);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				c1.Dispose();
				c2.Dispose();
				disposed = true;
			}
		}
	}
}
