using System;

namespace Noise
{
	/// <summary>
	/// A Diffie-Hellman private/public key pair.
	/// </summary>
	public sealed class KeyPair : IDisposable
	{
		private static readonly Curve25519 dh = new Curve25519();
		private readonly unsafe byte* privateKey;
		private readonly byte[] publicKey;
		private bool disposed;

        /// <summary>
        /// A constant specifying the size in bytes of public keys and DH outputs.
        /// For security reasons, DhLen must be 32 or greater.
        /// </summary>
        public static int DhLen => dh.DhLen;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyPair"/> class.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="privateKeyLength">The length of the private key.</param>
        /// <param name="publicKey">The public key.</param>
        /// <exception cref="ArgumentNullException">
        /// Thrown if the <paramref name="privateKey"/> or the <paramref name="publicKey"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if the lengths of the <paramref name="privateKey"/> or the <paramref name="publicKey"/> are invalid.
        /// </exception>
        internal unsafe KeyPair(byte* privateKey, int privateKeyLength, byte[] publicKey)
		{
			Exceptions.ThrowIfNull(privateKey, nameof(privateKey));
			Exceptions.ThrowIfNull(publicKey, nameof(publicKey));

			if (privateKeyLength != 32)
			{
				throw new ArgumentException("Private key must have length of 32 bytes.", nameof(privateKey));
			}

			if (publicKey.Length != 32)
			{
				throw new ArgumentException("Public key must have length of 32 bytes.", nameof(publicKey));
			}

            var privateKeyCopy = (byte*) Libsodium.sodium_malloc((ulong) privateKeyLength);
            for (var i = 0; i < privateKeyLength; i++)
                privateKeyCopy[i] = privateKey[i];

			this.privateKey = privateKeyCopy;
			this.publicKey = publicKey;
		}

		/// <summary>
		/// Generates a new Diffie-Hellman key pair.
		/// </summary>
		/// <returns>A randomly generated private key and its corresponding public key.</returns>
		public static KeyPair Generate()
		{
			return dh.GenerateKeyPair();
		}

		/// <summary>
		/// Gets the private key.
		/// </summary>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		public unsafe byte* PrivateKey
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
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		public byte[] PublicKey
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
                unsafe
                {
                    Libsodium.sodium_free(privateKey);
                }
                disposed = true;
			}
		}
	}
}
