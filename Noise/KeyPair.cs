using System;

namespace Noise
{
	/// <summary>
	/// A Diffie-Hellman private/public key pair.
	/// </summary>
	internal sealed class KeyPair : IDisposable
	{
		private readonly byte[] privateKey;
		private readonly byte[] publicKey;
		private bool disposed;

		private KeyPair()
		{
			privateKey = Random.GetBytes(Curve25519.KeySize);
			publicKey = Curve25519.ScalarBaseMult(privateKey);
		}

		/// <summary>
		/// Generates a random private key and its corresponding public key.
		/// </summary>
		/// <returns>The generated key pair.</returns>
		public static KeyPair Generate()
		{
			return new KeyPair();
		}

		/// <summary>
		/// Gets the private key.
		/// </summary>
		public byte[] PrivateKey
		{
			get
			{
				ThrowIfDisposed();
				return privateKey;
			}
		}

		/// <summary>
		/// Gets the public key.
		/// </summary>
		public byte[] PublicKey
		{
			get
			{
				ThrowIfDisposed();
				return publicKey;
			}
		}

		private void ThrowIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(KeyPair));
			}
		}

		/// <summary>
		/// Remove the keys from memory.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				Array.Clear(privateKey, 0, privateKey.Length);
				Array.Clear(publicKey, 0, publicKey.Length);

				disposed = true;
			}
		}
	}
}
