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
		public Span<byte> Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
		{
			Span<byte> nonce = stackalloc byte[Constants.NonceSize];
			EncodeNonce(n, nonce);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(
				ref MemoryMarshal.GetReference(ciphertext),
				out long length,
			 	ref MemoryMarshal.GetReference(plaintext),
				plaintext.Length,
				ad,
				ad?.LongLength ?? 0,
				IntPtr.Zero,
				ref MemoryMarshal.GetReference(nonce),
				k
			);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			return ciphertext.Slice(0, (int)length);
		}

		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		public Span<byte> Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
		{
			Span<byte> nonce = stackalloc byte[Constants.NonceSize];
			EncodeNonce(n, nonce);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(
				ref MemoryMarshal.GetReference(plaintext),
				out long length,
				IntPtr.Zero,
				ref MemoryMarshal.GetReference(ciphertext),
				ciphertext.Length,
				ad,
				ad?.LongLength ?? 0,
				ref MemoryMarshal.GetReference(nonce),
				k
			);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			return plaintext.Slice(0, (int)length);
		}

		private static void EncodeNonce(ulong n, Span<byte> nonce)
		{
			for (int i = 0; i < 8; ++i)
			{
				nonce[4 + i] = (byte)(n & 0xff);
				n = n >> 8;
			}
		}
	}
}
