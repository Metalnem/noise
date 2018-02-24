using System;

namespace Noise
{
	/// <summary>
	/// A Curve25519 private/public key pair.
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
				Exceptions.ThrowIfDisposed(disposed, nameof(KeyPair));
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
				Exceptions.ThrowIfDisposed(disposed, nameof(KeyPair));
				return publicKey;
			}
		}

		/// <summary>
		/// Disposes the object and clears the keys.
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
