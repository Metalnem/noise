using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The ChaChaPoly cipher functions.
	/// </summary>
	internal class ChaCha20Poly1305 : Cipher
	{
		private const int KeySize = Libsodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
		private const int NonceSize = Libsodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
		private const int TagSize = Libsodium.crypto_aead_chacha20poly1305_ietf_ABYTES;

		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		public byte[] Encrypt(byte[] k, ulong n, byte[] ad, byte[] plaintext)
		{
			ValidateKey(k);
			ValidatePlaintext(plaintext);

			byte[] ciphertext = new byte[plaintext.LongLength + TagSize];
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, out long length,
			 	plaintext, plaintext.LongLength, ad, ad?.LongLength ?? 0, IntPtr.Zero, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			return Trim(ciphertext, length);
		}

		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		public byte[] Decrypt(byte[] k, ulong n, byte[] ad, byte[] ciphertext)
		{
			ValidateKey(k);
			ValidateCiphertext(ciphertext);

			byte[] plaintext = new byte[ciphertext.LongLength - TagSize];
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, out long length,
				IntPtr.Zero, ciphertext, ciphertext.LongLength, ad, ad?.LongLength ?? 0, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			return Trim(plaintext, length);
		}

		private static byte[] EncodeNonce(ulong n)
		{
			byte[] nonce = new byte[NonceSize];

			for (int i = 0; i < 8; ++i)
			{
				nonce[4 + i] = (byte)(n & 0xff);
				n = n >> 8;
			}

			return nonce;
		}

		private static void ValidateKey(byte[] k)
		{
			if (k == null || k.Length != KeySize)
			{
				throw new CryptographicException($"Key must be {KeySize} bytes long.");
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
