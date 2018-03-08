using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
	/// The 96-bit nonce is formed by encoding 32 bits
	/// of zeros followed by little-endian encoding of n.
	/// </summary>
	internal sealed class ChaCha20Poly1305 : Cipher
	{
		public int Encrypt(ReadOnlySpan<byte> k, ulong n, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
		{
			Debug.Assert(k.Length == Constants.KeySize);
			Debug.Assert(ciphertext.Length >= plaintext.Length + Constants.TagSize);

			Span<byte> nonce = stackalloc byte[Constants.NonceSize];
			EncodeNonce(n, nonce);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(
				ref MemoryMarshal.GetReference(ciphertext),
				out long length,
			 	ref MemoryMarshal.GetReference(plaintext),
				plaintext.Length,
				ref MemoryMarshal.GetReference(ad),
				ad.Length,
				IntPtr.Zero,
				ref MemoryMarshal.GetReference(nonce),
				ref MemoryMarshal.GetReference(k)
			);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			Debug.Assert(length == plaintext.Length + Constants.TagSize);
			return (int)length;
		}

		public int Decrypt(ReadOnlySpan<byte> k, ulong n, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
		{
			Debug.Assert(k.Length == Constants.KeySize);
			Debug.Assert(ciphertext.Length >= Constants.TagSize);
			Debug.Assert(plaintext.Length >= ciphertext.Length - Constants.TagSize);

			Span<byte> nonce = stackalloc byte[Constants.NonceSize];
			EncodeNonce(n, nonce);

			int result = Libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(
				ref MemoryMarshal.GetReference(plaintext),
				out long length,
				IntPtr.Zero,
				ref MemoryMarshal.GetReference(ciphertext),
				ciphertext.Length,
				ref MemoryMarshal.GetReference(ad),
				ad.Length,
				ref MemoryMarshal.GetReference(nonce),
				ref MemoryMarshal.GetReference(k)
			);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			Debug.Assert(length == ciphertext.Length - Constants.TagSize);
			return (int)length;
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
