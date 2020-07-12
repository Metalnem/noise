using System;
using System.Diagnostics;

namespace Noise
{
	/// <summary>
	/// A CipherState can encrypt and decrypt data based on its variables k
	/// (a cipher key of 32 bytes) and n (an 8-byte unsigned integer nonce).
	/// </summary>
	internal sealed class CipherState<CipherType> : IDisposable where CipherType : Cipher, new()
	{
		private const ulong MaxNonce = UInt64.MaxValue;

		private static readonly byte[] zeroLen = new byte[0];
		private static readonly byte[] zeros = new byte[32];

		private readonly CipherType cipher = new CipherType();
		private unsafe byte* k;
		private ulong n;
		private bool disposed;

		/// <summary>
		/// Sets k = key. Sets n = 0.
		/// </summary>
		public void InitializeKey(ReadOnlySpan<byte> key)
		{
			Debug.Assert(key.Length == Aead.KeySize);

			EnsureInitialized();
            unsafe
            {
                for (var i = 0; i < key.Length; i++)
                {
                    k[i] = key[i];
                }
            }

            n = 0;
		}

        /// <summary>
		/// Returns true if k is non-empty, false otherwise.
		/// </summary>
		public bool HasKey()
        {
            unsafe
            {
                return k != default;
            }
        }

		/// <summary>
		/// Sets n = nonce. This function is used for handling out-of-order transport messages.
		/// </summary>
		public void SetNonce(ulong nonce)
		{
			n = nonce;
		}

		/// <summary>
		/// If k is non-empty returns ENCRYPT(k, n++, ad, plaintext).
		/// Otherwise copies the plaintext to the ciphertext parameter
		/// and returns the length of the plaintext.
		/// </summary>
		public int EncryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
		{
            if (n == MaxNonce)
            {
                throw new OverflowException("Nonce has reached its maximum value.");
            }

            unsafe
            {
                if (k == default)
                {
                    plaintext.CopyTo(ciphertext);
                    return plaintext.Length;
                }
				
				var kx = new Span<byte>(k, Aead.KeySize);
                return cipher.Encrypt(kx, n++, ad, plaintext, ciphertext);
            }
        }

		/// <summary>
		/// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
		/// Otherwise copies the ciphertext to the plaintext parameter and returns
		/// the length of the ciphertext. If an authentication failure occurs
		/// then n is not incremented and an error is signaled to the caller.
		/// </summary>
		public int DecryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
		{
            if (n == MaxNonce)
            {
                throw new OverflowException("Nonce has reached its maximum value.");
            }

			unsafe
            {
                if (k == default)
                {
                    ciphertext.CopyTo(plaintext);
                    return ciphertext.Length;
                }

                var kx = new Span<byte>(k, Aead.KeySize);
                int bytesRead = cipher.Decrypt(kx, n, ad, ciphertext, plaintext);
                ++n;

                return bytesRead;
            }
        }

		/// <summary>
		/// Sets k = REKEY(k).
		/// </summary>
		public void Rekey()
		{
            Debug.Assert(HasKey());

            unsafe
            {
                Span<byte> key = stackalloc byte[Aead.KeySize + Aead.TagSize];
                var kx = new Span<byte>(k, Aead.KeySize);
                cipher.Encrypt(kx, MaxNonce, zeroLen, zeros, key);

                EnsureInitialized();
                var s = key.Slice(Aead.KeySize);
                for (var i = 0; i < s.Length; i++)
                    k[i] = s[i];
            }
        }

        private unsafe void EnsureInitialized()
        {
            if (k == default)
            {
                k = (byte*) Libsodium.sodium_malloc(Aead.KeySize);
            }
        }

		public void Dispose()
		{
			if (!disposed)
			{
                unsafe
                {
                    Libsodium.sodium_free(k);
                }
                disposed = true;
			}
		}
	}
}
