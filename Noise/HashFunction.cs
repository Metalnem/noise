namespace Noise
{
	/// <summary>
	/// Enum representing the available hash functions.
	/// </summary>
	public enum HashFunction
	{
		/// <summary>
		/// SHA-256 from <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4</see>.
		/// </summary>
		Sha256,

		/// <summary>
		/// SHA-512 from <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4</see>.
		/// </summary>
		Sha512,

		/// <summary>
		/// BLAKE2b from <see href="https://tools.ietf.org/html/rfc7693">RFC 7693</see>.
		/// </summary>
		Blake2b
	}
}
