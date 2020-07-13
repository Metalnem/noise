using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Noise
{
	/// <summary>
	/// The Curve25519 DH function (aka "X25519" in
	/// <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>).
	/// </summary>
	internal sealed class Curve25519 : Dh
	{
		public int DhLen => Libsodium.crypto_scalarmult_curve25519_SCALARBYTES;

		public KeyPair GenerateKeyPair()
        {
            unsafe
            {
                var privateKey = (byte*) Libsodium.sodium_malloc((ulong) DhLen);
                try
                {
                    Libsodium.randombytes_buf(privateKey, (uint) DhLen);

                    var publicKey = new byte[DhLen];

                    Libsodium.crypto_scalarmult_curve25519_base(publicKey, privateKey);

                    return new KeyPair(privateKey, DhLen, publicKey);
                }
                finally
                {
                    Libsodium.sodium_free(privateKey);
                }
            }
        }

        public unsafe KeyPair GenerateKeyPair(byte* privateKey)
        {
            var privateKeyCopy = (byte*) Libsodium.sodium_malloc((ulong) DhLen);

            try
            {
                for (var i = 0; i < DhLen; i++)
                    privateKeyCopy[i] = privateKey[i];

                var publicKey = new byte[DhLen];

                Libsodium.crypto_scalarmult_curve25519_base(publicKey, privateKeyCopy);

                return new KeyPair(privateKeyCopy, DhLen, publicKey);
            }
            finally
            {
                Libsodium.sodium_free(privateKeyCopy);
            }
        }

        
		public unsafe void Dh(KeyPair keyPair, ReadOnlySpan<byte> publicKey, byte* sharedKey, int sharedKeyLen)
		{
            Debug.Assert(publicKey.Length == DhLen);
            Debug.Assert(sharedKeyLen == DhLen);

            Debug.Assert(keyPair.PrivateKey != null);

            Libsodium.crypto_scalarmult_curve25519(
                sharedKey,
                keyPair.PrivateKey,
                ref MemoryMarshal.GetReference(publicKey)
            );
        }
	}
}
