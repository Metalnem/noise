using System;

namespace Noise.Tests
{
	internal class FixedKeyDh : Dh
	{
		private static readonly Curve25519 dh = new Curve25519();
		private readonly byte[] fixedPrivateKey;

		public FixedKeyDh(byte[] privateKey)
		{
			fixedPrivateKey = privateKey;
		}

		public int DhLen => dh.DhLen;

		public KeyPair GenerateKeyPair()
		{
            unsafe
            {
                var sk = (byte*) Libsodium.sodium_malloc((ulong) DhLen);
                for (var i = 0; i < DhLen; i++)
                    sk[i] = fixedPrivateKey[i];

                return GenerateKeyPair(sk);
            }
		}

        public unsafe KeyPair GenerateKeyPair(byte* privateKey)
        {
            var publicKey = new byte[DhLen];
            Libsodium.crypto_scalarmult_curve25519_base(publicKey, privateKey);
            return new KeyPair(privateKey, DhLen, publicKey);
        }

		public void Dh(KeyPair keyPair, ReadOnlySpan<byte> publicKey, Span<byte> sharedKey)
		{
			dh.Dh(keyPair, publicKey, sharedKey);
		}
	}
}
