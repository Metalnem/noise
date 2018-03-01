using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The 25519 DH functions.
	/// </summary>
	internal sealed class Curve25519 : Dh
	{
		/// <summary>
		/// Name of the Curve25519 DH function.
		/// </summary>
		public string Name => "25519";

		/// <summary>
		/// Size in bytes of the Curve25519 public keys and DH outputs.
		/// </summary>
		public int DhLen => Libsodium.crypto_scalarmult_curve25519_SCALARBYTES;

		/// <summary>
		/// Returns a new Curve25519 key pair.
		/// </summary>
		public KeyPair GenerateKeyPair()
		{
			var privateKey = Random.GetBytes(DhLen);
			var publicKey = new byte[DhLen];

			Libsodium.crypto_scalarmult_curve25519_base(publicKey, privateKey);

			return new KeyPair(privateKey, publicKey);
		}

		/// <summary>
		/// Executes the Curve25519 DH function (aka "X25519" in
		/// <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>).
		/// </summary>
		public byte[] Dh(KeyPair keyPair, byte[] publicKey)
		{
			ValidateKey(keyPair.PrivateKey);
			ValidateKey(publicKey);

			var sharedKey = new byte[DhLen];
			Libsodium.crypto_scalarmult_curve25519(sharedKey, keyPair.PrivateKey, publicKey);

			return sharedKey;
		}

		private void ValidateKey(byte[] key)
		{
			if (key == null || key.Length != DhLen)
			{
				throw new CryptographicException($"Key must be {DhLen} bytes long.");
			}
		}
	}
}
