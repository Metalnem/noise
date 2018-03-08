using System;

namespace Noise
{
	/// <summary>
	/// A cipher suite is a combination of cipher, DH, and hash functions.
	/// </summary>
	public sealed class CipherSuite
	{
		/// <summary>
		/// Initializes a new CipherSuite.
		/// </summary>
		public CipherSuite(CipherFunction cipher, DhFunction dh, HashFunction hash)
		{
			if (!Enum.IsDefined(typeof(CipherFunction), cipher))
			{
				throw new ArgumentException($"Unknown cipher: {cipher}.");
			}

			if (!Enum.IsDefined(typeof(DhFunction), dh))
			{
				throw new ArgumentException($"Unknown DH: {dh}.");
			}

			if (!Enum.IsDefined(typeof(HashFunction), hash))
			{
				throw new ArgumentException($"Unknown hash: {hash}.");
			}

			Cipher = cipher;
			Dh = dh;
			Hash = hash;
		}

		/// <summary>
		/// Type of the cipher function.
		/// </summary>
		public CipherFunction Cipher { get; }

		/// <summary>
		/// Type of the DH function.
		/// </summary>
		public DhFunction Dh { get; }

		/// <summary>
		/// Type of the hash function.
		/// </summary>
		public HashFunction Hash { get; }
	}
}
