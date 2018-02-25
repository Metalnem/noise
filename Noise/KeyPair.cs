using System;

namespace Noise
{
	/// <summary>
	/// A Curve25519 private/public key pair.
	/// </summary>
	internal sealed class KeyPair : IDisposable
	{
		private bool disposed;

		private KeyPair()
		{
			PrivateKey = Random.GetBytes(Curve25519.KeySize);
			PublicKey = Curve25519.ScalarBaseMult(PrivateKey);
		}

		/// <summary>
		/// Generates a random private key and its corresponding public key.
		/// </summary>
		/// <returns>The generated key pair.</returns>
		public static KeyPair Generate() => new KeyPair();

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
