using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// Cryptographic random number generator.
	/// </summary>
	internal static class Random
	{
		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		/// <summary>
		/// Generates a cryptographically strong random sequence of n bytes.
		/// </summary>
		public static byte[] GetBytes(int n)
		{
			if (n <= 0)
			{
				throw new ArgumentOutOfRangeException(nameof(n));
			}

			var bytes = new byte[n];
			random.GetBytes(bytes);

			return bytes;
		}
	}
}
