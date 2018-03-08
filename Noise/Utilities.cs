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
		/// Alignes the pointer up to the nearest alignment boundary.
		/// </summary>
		public static IntPtr Align(IntPtr ptr, int alignment)
		{
			ulong mask = (ulong)alignment - 1;
			return (IntPtr)(((ulong)ptr + mask) & ~mask);
		}

		/// <summary>
		/// Generates a cryptographically strong pseudorandom sequence of n bytes.
		/// </summary>
		public static byte[] GetRandomBytes(int n)
		{
			Exceptions.ThrowIfOutOfRange(n, nameof(n), 1);

			var bytes = new byte[n];
			random.GetBytes(bytes);

			return bytes;
		}
	}
}
