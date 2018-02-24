namespace Noise
{
	/// <summary>
	/// The 25519 DH functions.
	/// </summary>
	internal static class DiffieHellman
	{
		/// <summary>
		/// Shared secret key size in bytes.
		/// </summary>
		public const int DhLen = 32;

		/// <summary>
		/// Generates a new Curve25519 key pair.
		/// </summary>
		/// <returns>The generated key pair.</returns>
		public static KeyPair GenerateKeyPair()
		{
			return KeyPair.Generate();
		}

		/// <summary>
		/// Executes the Curve25519 DH function.
		/// </summary>
		/// <param name="key">The private/public key pair.</param>
		/// <param name="publicKey">The public key.</param>
		/// <returns>The computed shared secret key.</returns>
		public static byte[] Dh(KeyPair key, byte[] publicKey)
		{
			return Curve25519.ScalarMult(key.PrivateKey, publicKey);
		}
	}
}
