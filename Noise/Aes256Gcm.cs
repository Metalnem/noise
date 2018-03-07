using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The AESGCM cipher functions.
	/// </summary>
	internal sealed class Aes256Gcm : Cipher
	{
		/// <summary>
		/// Initializes a new Aes256Gcm.
		/// </summary>
		public Aes256Gcm()
		{
			if (!Libsodium.IsAes256GcmAvailable)
			{
				throw new NotSupportedException("AES-GCM is not available on this CPU.");
			}
		}

		/// <summary>
		/// AES256 with GCM from NIST Special Publication
		/// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>.
		/// </summary>
		public int Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
		{
			Span<byte> nonce = stackalloc byte[Constants.NonceSize];
			EncodeNonce(n, nonce);

			int result = Libsodium.crypto_aead_aes256gcm_encrypt(
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

			return (int)length;
		}

		/// <summary>
		/// AES256 with GCM from NIST Special Publication
		/// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>.
		/// </summary>
		public int Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
		{
			Span<byte> nonce = stackalloc byte[Constants.NonceSize];
			EncodeNonce(n, nonce);

			int result = Libsodium.crypto_aead_aes256gcm_decrypt(
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

			return (int)length;
		}

		private static void EncodeNonce(ulong n, Span<byte> nonce)
		{
			int end = nonce.Length - 1;

			for (int i = 0; i < 8; ++i)
			{
				nonce[end - i] = (byte)(n & 0xff);
				n = n >> 8;
			}
		}
	}
}
