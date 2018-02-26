using System;

namespace Noise
{
	/// <summary>
	/// A Diffie-Hellman private/public key pair.
	/// </summary>
	internal sealed class KeyPair : IDisposable
	{
		private bool disposed;

		/// <summary>
		/// Initializes a new KeyPair.
		/// </summary>
		public KeyPair(byte[] privateKey, byte[] publicKey)
		{
			PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
			PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
		}

		/// <summary>
		/// Gets the private key.
		/// </summary>
		public byte[] PrivateKey { get; }

		/// <summary>
		/// Gets the public key.
		/// </summary>
		public byte[] PublicKey { get; }

		/// <summary>
		/// Disposes the object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				Array.Clear(PrivateKey, 0, PrivateKey.Length);
				Array.Clear(PublicKey, 0, PublicKey.Length);
				disposed = true;
			}
		}
	}
}
