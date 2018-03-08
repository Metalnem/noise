namespace Noise
{
	/// <summary>
	/// DH functions (and an associated constant).
	/// </summary>
	internal interface Dh
	{
		/// <summary>
		/// A constant specifying the size in bytes of public keys and DH outputs.
		/// </summary>
		int DhLen { get; }

		/// <summary>
		/// Generates a new Diffie-Hellman key pair.
		/// </summary>
		KeyPair GenerateKeyPair();

		/// <summary>
		/// Performs a Diffie-Hellman calculation between the private
		/// key in keyPair and the publicKey and returns an output
		/// sequence of bytes of length DhLen.
		/// </summary>
		byte[] Dh(KeyPair keyPair, byte[] publicKey);
	}
}
