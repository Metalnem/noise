using System;
using System.Security.Cryptography;

namespace Noise
{
	internal static class Random
	{
		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

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
