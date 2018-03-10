using System;

namespace Noise
{
	/// <summary>
	/// A Diffie-Hellman private/public key pair.
	/// </summary>
	public sealed class KeyPair : IDisposable
	{
		private readonly byte[] privateKey;
		private readonly byte[] publicKey;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="KeyPair"/> class.
		/// </summary>
		/// <param name="privateKey">The private key.</param>
		/// <param name="publicKey">The public key.</param>
		/// <exception cref="ArgumentNullException">
		/// Thrown if the <paramref name="privateKey"/> or the <paramref name="publicKey"/> are null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the lengths of the <paramref name="privateKey"/> or the <paramref name="publicKey"/> were invalid.
		/// </exception>
		public KeyPair(byte[] privateKey, byte[] publicKey)
		{
			if (privateKey == null)
			{
				throw new ArgumentNullException(nameof(privateKey));
			}

			if (publicKey == null)
			{
				throw new ArgumentNullException(nameof(publicKey));
			}

			if (privateKey.Length != 32 && privateKey.Length != 56)
			{
				throw new ArgumentException($"Private key must have length of either 32 bytes or 56 bytes.", nameof(privateKey));
			}

			if (publicKey.Length != 32 && publicKey.Length != 56)
			{
				throw new ArgumentException($"Public key must have length of either 32 bytes or 56 bytes.", nameof(publicKey));
			}

			this.privateKey = privateKey;
			this.publicKey = publicKey;
		}

		/// <summary>
		/// Gets the private key.
		/// </summary>
		public ReadOnlySpan<byte> PrivateKey
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
		public ReadOnlySpan<byte> PublicKey
		{
			get
			{
				Exceptions.ThrowIfDisposed(disposed, nameof(KeyPair));
				return publicKey;
			}
		}

		/// <summary>
		/// Erases the key pair from the memory.
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
