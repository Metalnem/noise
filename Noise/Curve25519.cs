using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// Scalar multiplication on the elliptic curve Curve25519, defined in
	/// <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>.
	/// </summary>
	internal static class Curve25519
	{
		/// <summary>
		/// Secret key size in bytes.
		/// </summary>
		public const int KeySize = Libsodium.crypto_scalarmult_curve25519_SCALARBYTES;

		/// <summary>
		/// Computes the Diffie-Hellman public key.
		/// </summary>
		/// <param name="privateKey">The 32-byte secret key.</param>
		/// <returns>The computed public key.</returns>
		public static byte[] ScalarBaseMult(byte[] privateKey)
		{
			ValidateKey(privateKey);

			var publicKey = new byte[KeySize];
			Libsodium.crypto_scalarmult_curve25519_base(publicKey, privateKey);

			return publicKey;
		}

		/// <summary>
		/// Computes the Diffie-Hellman shared secret key.
		/// </summary>
		/// <param name="privateKey">The 32-byte secret key.</param>
		/// <param name="publicKey">The 32-byte public key.</param>
		/// <returns>The computed shared secret key.</returns>
		public static byte[] ScalarMult(byte[] privateKey, byte[] publicKey)
		{
			ValidateKey(privateKey);
			ValidateKey(publicKey);

			var sharedKey = new byte[KeySize];
			Libsodium.crypto_scalarmult_curve25519(sharedKey, privateKey, publicKey);

			return sharedKey;
		}

		private static void ValidateKey(byte[] key)
		{
			if (key == null || key.Length != KeySize)
			{
				throw new CryptographicException($"Key must be {KeySize} bytes long.");
			}
		}
	}
}
