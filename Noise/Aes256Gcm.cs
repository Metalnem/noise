using System;
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
		public byte[] Encrypt(byte[] k, ulong n, byte[] ad, byte[] plaintext)
		{
			Utilities.ValidateKey(k);
			Utilities.ValidatePlaintext(plaintext);

			byte[] ciphertext = new byte[plaintext.LongLength + Constants.TagSize];
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_aes256gcm_encrypt(ciphertext, out long length,
			 	plaintext, plaintext.LongLength, ad, ad?.LongLength ?? 0, IntPtr.Zero, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			return Utilities.Trim(ciphertext, length);
		}

		/// <summary>
		/// AES256 with GCM from NIST Special Publication
		/// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>.
		/// </summary>
		public byte[] Decrypt(byte[] k, ulong n, byte[] ad, byte[] ciphertext)
		{
			Utilities.ValidateKey(k);
			Utilities.ValidateCiphertext(ciphertext);

			byte[] plaintext = new byte[ciphertext.LongLength - Constants.TagSize];
			byte[] nonce = EncodeNonce(n);

			int result = Libsodium.crypto_aead_aes256gcm_decrypt(plaintext, out long length,
				IntPtr.Zero, ciphertext, ciphertext.LongLength, ad, ad?.LongLength ?? 0, nonce, k);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			return Utilities.Trim(plaintext, length);
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
