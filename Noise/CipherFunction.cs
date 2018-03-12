namespace Noise
{
	/// <summary>
	/// Constants representing the available cipher functions.
	/// </summary>
	public sealed class CipherFunction
	{
		/// <summary>
		/// AES256 with GCM from NIST Special Publication
		/// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>.
		/// </summary>
		public static readonly CipherFunction AesGcm = new CipherFunction("AESGCM");

		/// <summary>
		/// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
		/// </summary>
		public static readonly CipherFunction ChaChaPoly = new CipherFunction("ChaChaPoly");

		private CipherFunction(string name)
		{
			Name = name;
		}

		internal string Name { get; }
	}
}
