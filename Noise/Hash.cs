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

		/// <summary>
		/// Takes a chainingKey byte sequence of length HashLen, and an
		/// inputKeyMaterial byte sequence with length either zero bytes,
		/// 32 bytes, or DhLen bytes. Returns a pair or triple of byte
		/// sequences each of length HashLen, depending on whether
		/// numOutputs is two or three.
		/// </summary>
		public static byte[] Hkdf(byte[] chainingKey, byte[] inputKeyMaterial, int numOutputs)
		{
			if (inputKeyMaterial != null)
			{
				int length = inputKeyMaterial.Length;

				if (length != 0 && length != 32 && length != DiffieHellman.DhLen)
				{
					throw new CryptographicException("Input key material must be either 0 bytes, 32 byte, or DhLen bytes long.");
				}
			}

			if (numOutputs != 2 && numOutputs != 3)
			{
				throw new CryptographicException("Number of HKDF outputs must be either two or three.");
			}

			using (var hkdf = Cryptography.Hkdf.CreateSha256Hkdf(inputKeyMaterial, chainingKey, null))
			{
				byte[] bytes = new byte[numOutputs * HashLen];
				hkdf.GetBytes(bytes);

				return bytes;
			}
		}
	}
}
