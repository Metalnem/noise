using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The ChaChaPoly cipher functions.
	/// </summary>
	internal sealed class ChaCha20Poly1305 : Cipher
	{
		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		public byte[] Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext)
		{
			Utilities.ValidateKey(k);

			ref byte message = ref MemoryMarshal.GetReference(plaintext);
			byte[] ciphertext = new byte[plaintext.Length + Constants.TagSize];
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, out long length,
			 	ref message, plaintext.Length, ad, ad?.LongLength ?? 0, IntPtr.Zero, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			return Utilities.Trim(ciphertext, length);
		}

		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		public byte[] Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext)
		{
			Utilities.ValidateKey(k);
			Utilities.ValidateCiphertext(ciphertext);

			ref byte message = ref MemoryMarshal.GetReference(ciphertext);
			byte[] plaintext = new byte[ciphertext.Length - Constants.TagSize];
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, out long length,
				IntPtr.Zero, ref message, ciphertext.Length, ad, ad?.LongLength ?? 0, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			return Utilities.Trim(plaintext, length);
		}

		private static byte[] EncodeNonce(ulong n)
		{
			byte[] nonce = new byte[Constants.NonceSize];

			for (int i = 0; i < 8; ++i)
			{
				nonce[4 + i] = (byte)(n & 0xff);
				n = n >> 8;
			}

			return nonce;
		}
	}
}
