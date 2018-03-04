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
		public CipherSuite(CipherType cipher, DhType dh, HashType hash)
		{
			if (!Enum.IsDefined(typeof(CipherType), cipher))
			{
				throw new ArgumentException($"Unknown cipher: {cipher}.");
			}

			if (!Enum.IsDefined(typeof(DhType), dh))
			{
				throw new ArgumentException($"Unknown DH: {dh}.");
			}

			if (!Enum.IsDefined(typeof(HashType), hash))
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
		public CipherType Cipher { get; }

		/// <summary>
		/// Type of the DH function.
		/// </summary>
		public DhType Dh { get; }

		/// <summary>
		/// Type of the hash function.
		/// </summary>
		public HashType Hash { get; }

		/// <summary>
		/// Available cipher functions.
		/// </summary>
		public enum CipherType
		{
			AesGcm,
			ChaChaPoly
		}

		/// <summary>
		/// Available DH functions.
		/// </summary>
		public enum DhType
		{
			Curve25519
		}

		/// <summary>
		/// Available hash functions.
		/// </summary>
		public enum HashType
		{
			Sha256,
			Sha512,
			Blake2b
		}
	}
}
