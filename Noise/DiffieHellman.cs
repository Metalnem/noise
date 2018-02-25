namespace Noise
{
	/// <summary>
	/// Diffie-Hellman functions.
	/// </summary>
	internal static class DiffieHellman
	{
		/// <summary>
		/// A constant specifying the size in bytes of public keys and DH outputs.
		/// </summary>
		public const int DhLen = 32;

		/// <summary>
		/// Generates a new Diffie-Hellman key pair.
		/// </summary>
		public static KeyPair GenerateKeyPair()
		{
			return KeyPair.Generate();
		}

		/// <summary>
		/// Performs a Diffie-Hellman calculation between the private
		/// key in keyPair and the publicKey and returns an output
		/// sequence of bytes of length DhLen.
		/// </summary>
		public static byte[] Dh(KeyPair keyPair, byte[] publicKey)
		{
			return Curve25519.ScalarMult(keyPair.PrivateKey, publicKey);
		}
	}
}
