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
		/// Creates a new instance of Hash for the specified algorithm.
		/// </summary>
		public static Hash Create(this HashAlgorithmName hashName)
		{
			if (hashName == HashAlgorithmName.SHA256)
			{
				return new Sha256();
			}
			else if (hashName == HashAlgorithmName.SHA512)
			{
				return new Sha512();
			}

			throw new ArgumentException($"Unknown hash algorithm name: {hashName.Name}.", nameof(hashName));
		}

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
