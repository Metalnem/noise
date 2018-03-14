using System;

namespace Noise
{
	/// <summary>
	/// Constants representing the available hash functions.
	/// </summary>
	public sealed class HashFunction
	{
		/// <summary>
		/// SHA-256 from <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4</see>.
		/// </summary>
		public static readonly HashFunction Sha256 = new HashFunction("SHA256");

		/// <summary>
		/// SHA-512 from <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4</see>.
		/// </summary>
		public static readonly HashFunction Sha512 = new HashFunction("SHA512");

		/// <summary>
		/// BLAKE2b from <see href="https://tools.ietf.org/html/rfc7693">RFC 7693</see>.
		/// </summary>
		public static readonly HashFunction Blake2b = new HashFunction("BLAKE2b");

		private readonly string name;

		private HashFunction(string name) => this.name = name;
		public override string ToString() => name;

		internal static HashFunction Parse(ReadOnlySpan<char> s)
		{
			switch (s)
			{
				case var _ when s.SequenceEqual(Sha256.name.AsReadOnlySpan()): return Sha256;
				case var _ when s.SequenceEqual(Sha512.name.AsReadOnlySpan()): return Sha512;
				case var _ when s.SequenceEqual(Blake2b.name.AsReadOnlySpan()): return Blake2b;
				default: throw new ArgumentException("Unknown hash function.", nameof(s));
			}
		}
	}
}
