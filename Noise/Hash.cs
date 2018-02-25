using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// Hash functions.
	/// </summary>
	internal static class Hash
	{
		/// <summary>
		/// A constant specifying the size in bytes of the hash output.
		/// </summary>
		public const int HashLen = 32;

		/// <summary>
		/// A constant specifying the size in bytes that the hash function
		/// uses internally to divide its input for iterative processing.
		/// </summary>
		public const int BlockLen = 64;

		private static readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

		/// <summary>
		/// Hashes some arbitrary-length data with a collision-resistant
		/// cryptographic hash function and returns an output of HashLen bytes.
		/// </summary>
		public static byte[] Sum(params byte[][] data)
		{
			foreach (var item in data)
			{
				hash.AppendData(item);
			}

			return hash.GetHashAndReset();
		}
	}
}
