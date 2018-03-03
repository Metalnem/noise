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
		public Span<byte> Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
		{
			ref byte c = ref MemoryMarshal.GetReference(ciphertext);
			ref byte m = ref MemoryMarshal.GetReference(plaintext);
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_aes256gcm_encrypt(ref c, out long length,
			 	ref m, plaintext.Length, ad, ad?.LongLength ?? 0, IntPtr.Zero, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			return ciphertext.Slice(0, (int)length);
		}

		/// <summary>
		/// AES256 with GCM from NIST Special Publication
		/// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>.
		/// </summary>
		public Span<byte> Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
		{
			ref byte m = ref MemoryMarshal.GetReference(plaintext);
			ref byte c = ref MemoryMarshal.GetReference(ciphertext);
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_aes256gcm_decrypt(ref m, out long length,
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
			int end = nonce.Length - 1;

			for (int i = 0; i < 8; ++i)
			{
				nonce[end - i] = (byte)(n & 0xff);
				n = n >> 8;
			}

			return nonce;
		}
	}
}
