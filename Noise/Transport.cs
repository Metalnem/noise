using System;

namespace Noise
{
	/// <summary>
	/// A pair of CipherState objects for encrypting transport messages.
	/// </summary>
	internal sealed class Transport<CipherType> : ITransport where CipherType : Cipher, new()
	{
		private readonly bool initiator;
		private readonly CipherState<CipherType> c1;
		private readonly CipherState<CipherType> c2;
		private bool disposed;

		/// <summary>
		/// Initializes a new Transport.
		/// </summary>
		public Transport(bool initiator, CipherState<CipherType> c1, CipherState<CipherType> c2)
		{
			this.initiator = initiator;
			this.c1 = c1;
			this.c2 = c2;
		}

		/// <summary>
		/// Encrypts the payload and writes the ciphertext into message.
		/// </summary>
		public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> message)
		{
			var cipher = initiator ? c2 : c1;
			return cipher.EncryptWithAd(null, payload, message);
		}

		/// <summary>
		/// Decrypts the message and writes the plaintext into payload.
		/// </summary>
		public int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payload)
		{
			var cipher = initiator ? c1 : c2;
			return cipher.DecryptWithAd(null, message, payload);
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
