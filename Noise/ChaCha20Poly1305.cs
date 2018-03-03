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
			ref byte c = ref MemoryMarshal.GetReference(ciphertext);
			ref byte m = ref MemoryMarshal.GetReference(plaintext);
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(ref c, out long length,
			 	ref m, plaintext.Length, ad, ad?.LongLength ?? 0, IntPtr.Zero, nonce, k);

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
			ref byte m = ref MemoryMarshal.GetReference(plaintext);
			ref byte c = ref MemoryMarshal.GetReference(ciphertext);
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(ref m, out long length,
				IntPtr.Zero, ref c, ciphertext.Length, ad, ad?.LongLength ?? 0, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			return plaintext.Slice(0, (int)length);
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
