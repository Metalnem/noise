using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// Various utility functions.
	/// </summary>
	internal static class Utilities
	{
		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		/// <summary>
		/// Alignes the pointer to the nearest alignment boundary.
		/// </summary>
		public static IntPtr Align(IntPtr ptr, int alignment)
		{
			ulong mask = (ulong)alignment - 1;
			return (IntPtr)(((ulong)ptr + mask) & ~mask);
		}

		/// <summary>
		/// Generates a cryptographically strong random sequence of n bytes.
		/// </summary>
		public static byte[] GetRandomBytes(int n)
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
