using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// ChaCha20-Poly1305 authenticated encryption with associated data (AEAD), defined in
	/// <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
	/// </summary>
	internal static class ChaCha20Poly1305
	{
		/// <summary>
		/// Secret key size in bytes.
		/// </summary>
		public const int KeySize = Libsodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES;

		/// <summary>
		/// Nonce size in bytes.
		/// </summary>
		public const int NonceSize = Libsodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

		/// <summary>
		/// Authentication tag size in bytes.
		/// </summary>
		public const int TagSize = Libsodium.crypto_aead_chacha20poly1305_ietf_ABYTES;

		/// <summary>
		/// Encrypts and authenticates the plaintext, and authenticates the associated data.
		/// </summary>
		/// <param name="k">The 32-byte secret key.</param>
		/// <param name="n">The 12-byte nonce.</param>
		/// <param name="ad">The additional data to authenticate (can be null).</param>
		/// <param name="plaintext">The plaintext to encrypt.</param>
		/// <returns>The encrypted ciphertext.</returns>
		public static byte[] Encrypt(byte[] k, byte[] n, byte[] ad, byte[] plaintext)
		{
			ValidateKey(k);
			ValidateNonce(n);
			ValidatePlaintext(plaintext);

			byte[] ciphertext = new byte[plaintext.LongLength + TagSize];

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, out long length,
			 	plaintext, plaintext.LongLength, ad, ad?.LongLength ?? 0, IntPtr.Zero, n, k);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			return Trim(ciphertext, length);
		}

		/// <summary>
		/// Decrypts the ciphertext, and authenticates the decrypted plaintext and the associated data.
		/// </summary>
		/// <param name="k">The 32-byte secret key.</param>
		/// <param name="n">The 12-byte nonce.</param>
		/// <param name="ad">The additional data to authenticate (can be null).</param>
		/// <param name="ciphertext">The ciphertext to decrypt.</param>
		/// <returns>The decrypted plaintext.</returns>
		public static byte[] Decrypt(byte[] k, byte[] n, byte[] ad, byte[] ciphertext)
		{
			ValidateKey(k);
			ValidateNonce(n);
			ValidateCiphertext(ciphertext);

			byte[] plaintext = new byte[ciphertext.LongLength - TagSize];

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, out long length,
				IntPtr.Zero, ciphertext, ciphertext.LongLength, ad, ad?.LongLength ?? 0, n, k);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			return Trim(plaintext, length);
		}

		private static void ValidateKey(byte[] k)
		{
			if (k == null || k.Length != KeySize)
			{
				throw new CryptographicException($"Key must be {KeySize} bytes long.");
			}
		}

		private static void ValidateNonce(byte[] n)
		{
			if (n == null || n.Length != NonceSize)
			{
				throw new CryptographicException($"Nonce must be {NonceSize} bytes long.");
			}
		}

		private static void ValidatePlaintext(byte[] plaintext)
		{
			if (plaintext == null)
			{
				throw new ArgumentNullException(nameof(plaintext));
			}
		}

		private static void ValidateCiphertext(byte[] ciphertext)
		{
			if (ciphertext == null || ciphertext.Length < TagSize)
			{
				throw new CryptographicException($"Ciphertext must be at least {TagSize} bytes long.");
			}
		}

		private static byte[] Trim(byte[] a, long length)
		{
			if (a.LongLength == length)
			{
				return a;
			}

			var temp = new byte[length];
			Array.Copy(a, temp, length);

			return temp;
		}
	}
}
