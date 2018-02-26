using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// Various utility functions.
	/// </summary>
	internal static class Utilities
	{
		/// <summary>
		/// Verify that the secret key is 32 bytes long.
		/// </summary>
		public static void ValidateKey(byte[] k)
		{
			if (k == null || k.Length != Constants.KeySize)
			{
				throw new CryptographicException($"Key must be {Constants.KeySize} bytes long.");
			}
		}

		/// <summary>
		/// Verify that the plaintext is not null.
		/// </summary>
		public static void ValidatePlaintext(byte[] plaintext)
		{
			if (plaintext == null)
			{
				throw new ArgumentNullException(nameof(plaintext));
			}
		}

		/// <summary>
		/// Verify that the ciphertext is at least 16 bytes long.
		/// </summary>
		public static void ValidateCiphertext(byte[] ciphertext)
		{
			if (ciphertext == null || ciphertext.Length < Constants.TagSize)
			{
				throw new CryptographicException($"Ciphertext must be at least {Constants.TagSize} bytes long.");
			}
		}

		/// <summary>
		/// Returns a if a.LongLength is equal to n. Otherwise allocates
		/// a new array with the length n, copies n elements from the old
		/// array to the new one, and returns the new array.
		/// </summary>
		public static byte[] Trim(byte[] a, long n)
		{
			if (a.LongLength == n)
			{
				return a;
			}

			var temp = new byte[n];
			Array.Copy(a, temp, n);

			return temp;
		}
	}
}
