using System;

namespace Noise
{
	/// <summary>
	/// A pair of CipherState objects for encrypting transport messages.
	/// </summary>
	internal sealed class Transport<CipherType> : IDisposable where CipherType : Cipher, new()
	{
		private readonly CipherState<CipherType> c1;
		private readonly CipherState<CipherType> c2;
		private bool disposed;

		/// <summary>
		/// Initializes a new Transport.
		/// </summary>
		public Transport(CipherState<CipherType> c1, CipherState<CipherType> c2)
		{
			this.c1 = c1;
			this.c2 = c2;
		}

		/// <summary>
		/// Encrypts the payload and writes the ciphertext into message.
		/// </summary>
		public Span<byte> WriteMessage(Span<byte> payload, Span<byte> message)
		{
			return c1.EncryptWithAd(null, payload, message);
		}

		/// <summary>
		/// Decrypts the message and writes the plaintext into payload.
		/// </summary>
		public Span<byte> ReadMessage(Span<byte> message, Span<byte> payload)
		{
			return c2.DecryptWithAd(null, message, payload);
		}

		/// <summary>
		/// Disposes the object.
		/// </summary>
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
