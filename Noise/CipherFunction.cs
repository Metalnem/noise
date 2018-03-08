namespace Noise
{
	/// <summary>
	/// Enum representing the available cipher functions.
	/// </summary>
	public enum CipherFunction
	{
		/// <summary>
		/// AES256 with GCM from NIST Special Publication
		/// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>.
		/// </summary>
		AesGcm,

		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		ChaChaPoly
	}
}
