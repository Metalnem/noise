using System;

namespace Noise
{
	/// <summary>
	/// A CipherState can encrypt and decrypt data based on its variables k
	/// (a cipher key of 32 bytes) and n (an 8-byte unsigned integer nonce).
	/// </summary>
	internal sealed class CipherState : IDisposable
	{
		private const ulong MaxNonce = UInt64.MaxValue;

		private static readonly byte[] zeroLen = new byte[0];
		private static readonly byte[] zeros = new byte[32];

		private byte[] k;
		private ulong n;
		private bool disposed;

		/// <summary>
		/// Sets k = key. Sets n = 0.
		/// </summary>
		public void InitializeKey(byte[] key)
		{
			if (k != null)
			{
				Array.Clear(k, 0, k.Length);
			}

			k = key;
			n = 0;
		}

		/// <summary>
		/// Returns true if k is non-empty, false otherwise.
		/// </summary>
		public bool HasKey()
		{
			return k != null;
		}

		/// <summary>
		///  Sets n = nonce. This function is used for handling out-of-order transport messages.
		/// </summary>
		public void SetNonce(ulong nonce)
		{
			n = nonce;
		}

		/// <summary>
		/// If k is non-empty returns ENCRYPT(k, n++, ad, plaintext).
		/// Otherwise returns plaintext.
		/// </summary>
		public byte[] EncryptWithAd(byte[] ad, byte[] plaintext)
		{
			if (n == MaxNonce)
			{
				throw new OverflowException("Nonce has reached its maximum value.");
			}

			if (k == null)
			{
				return plaintext;
			}

			var ciphertext = ChaCha20Poly1305.Encrypt(k, n, ad, plaintext);
			++n;

			return ciphertext;
		}

		/// <summary>
		/// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
		/// Otherwise returns ciphertext. If an authentication failure
		/// occurs in DECRYPT() then n is not incremented and an error
		/// is signaled to the caller.
		/// </summary>
		public byte[] DecryptWithAd(byte[] ad, byte[] ciphertext)
		{
			if (n == MaxNonce)
			{
				throw new OverflowException("Nonce has reached its maximum value.");
			}

			if (k == null)
			{
				return ciphertext;
			}

			var plaintext = ChaCha20Poly1305.Decrypt(k, n, ad, ciphertext);
			++n;

			return plaintext;
		}

		/// <summary>
		/// Sets k = REKEY(k).
		/// </summary>
		public void Rekey()
		{
			InitializeKey(ChaCha20Poly1305.Encrypt(k, MaxNonce, zeroLen, zeros));
		}

		/// <summary>
		/// Disposes the object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				InitializeKey(null);
				disposed = true;
			}
		}
	}
}
