using System;
using System.Diagnostics;
using System.Threading;

namespace Noise
{
	/// <summary>
	/// A SymmetricState object contains a CipherState plus ck (a chaining
	/// key of HashLen bytes) and h (a hash output of HashLen bytes).
	/// </summary>
	internal sealed class SymmetricState<CipherType, DhType, HashType> : IDisposable
		where CipherType : Cipher, new()
		where DhType : Dh, new()
		where HashType : Hash, new()
	{
		private readonly Cipher cipher = new CipherType();
		private readonly DhType dh = new DhType();
		private readonly Hash hash = new HashType();
		private readonly Hkdf<HashType> hkdf = new Hkdf<HashType>();
		private readonly CipherState<CipherType> state = new CipherState<CipherType>();
		private readonly unsafe byte* ck;
		private readonly byte[] h;
		private int disposed;

        /// <summary>
        /// Initializes a new SymmetricState with an
        /// arbitrary-length protocolName byte sequence.
        /// </summary>
        public SymmetricState(ReadOnlySpan<byte> protocolName)
        {

            int length = hash.HashLen;

            unsafe
            {
                ck = (byte*) Libsodium.sodium_malloc((ulong) length);
            }

            h = new byte[length];

            if (protocolName.Length <= length)
            {
                protocolName.CopyTo(h);
            }
            else
            {
                hash.AppendData(protocolName);
                hash.GetHashAndReset(h);
            }

            unsafe
            {
                for (var i = 0; i < length; i++)
                    ck[i] = h[i];    
            }
        }

        /// <summary>
		/// Sets ck, tempK = HKDF(ck, inputKeyMaterial, 2).
		/// If HashLen is 64, then truncates tempK to 32 bytes.
		/// Calls InitializeKey(tempK).
		/// </summary>
		public unsafe void MixKey(byte* inputKeyMaterial, int inputKeyMaterialLength)
		{
            var length = inputKeyMaterialLength;
            Debug.Assert(length == 0 || length == Aead.KeySize || length == dh.DhLen);

            Span<byte> output = stackalloc byte[2 * hash.HashLen];
            hkdf.ExtractAndExpand2(ck, hash.HashLen, inputKeyMaterial, inputKeyMaterialLength, output);

            var slice = output.Slice(0, hash.HashLen);
            for (var i = 0; i < hash.HashLen; i++)
                ck[i] = slice[i];

            var tempK = output.Slice(hash.HashLen, Aead.KeySize);
            state.InitializeKey(tempK);
        }

		/// <summary>
		/// Sets h = HASH(h || data).
		/// </summary>
		public void MixHash(ReadOnlySpan<byte> data)
		{
			hash.AppendData(h);
			hash.AppendData(data);
			hash.GetHashAndReset(h);
		}

		/// <summary>
		/// Sets ck, tempH, tempK = HKDF(ck, inputKeyMaterial, 3).
		/// Calls MixHash(tempH).
		/// If HashLen is 64, then truncates tempK to 32 bytes.
		/// Calls InitializeKey(tempK).
		/// </summary>
		public void MixKeyAndHash(PskRef inputKeyMaterial)
		{
            unsafe
            {
                var length = inputKeyMaterial.len;
                Debug.Assert(length == 0 || length == Aead.KeySize || length == dh.DhLen);

                Span<byte> output = stackalloc byte[3 * hash.HashLen];
                hkdf.ExtractAndExpand3(ck, hash.HashLen, inputKeyMaterial.ptr, length, output);

                var slice = output.Slice(0, hash.HashLen);
                for (var i = 0; i < hash.HashLen; i++)
                    ck[i] = slice[i];

                var tempH = output.Slice(hash.HashLen, hash.HashLen);
                var tempK = output.Slice(2 * hash.HashLen, Aead.KeySize);

                MixHash(tempH);
                state.InitializeKey(tempK);
            }
        }

		/// <summary>
		/// Returns h. This function should only be called at the end of
		/// a handshake, i.e. after the Split() function has been called.
		/// </summary>
		public byte[] GetHandshakeHash()
		{
			return h;
		}

		/// <summary>
		/// Sets ciphertext = EncryptWithAd(h, plaintext),
		/// calls MixHash(ciphertext), and returns ciphertext.
		/// </summary>
		public int EncryptAndHash(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
		{
			int bytesWritten = state.EncryptWithAd(h, plaintext, ciphertext);
			MixHash(ciphertext.Slice(0, bytesWritten));

			return bytesWritten;
		}

		/// <summary>
		/// Sets plaintext = DecryptWithAd(h, ciphertext),
		/// calls MixHash(ciphertext), and returns plaintext.
		/// </summary>
		public int DecryptAndHash(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
		{
			var bytesRead = state.DecryptWithAd(h, ciphertext, plaintext);
			MixHash(ciphertext);

			return bytesRead;
		}

		/// <summary>
		/// Returns a pair of CipherState objects for encrypting transport messages.
		/// </summary>
		public (CipherState<CipherType> c1, CipherState<CipherType> c2) Split()
		{
            unsafe
            {
                Span<byte> output = stackalloc byte[2 * hash.HashLen];
                hkdf.ExtractAndExpand2(ck, hash.HashLen, default, 0, output);

                var tempK1 = output.Slice(0, Aead.KeySize);
                var tempK2 = output.Slice(hash.HashLen, Aead.KeySize);

                var c1 = new CipherState<CipherType>();
                var c2 = new CipherState<CipherType>();

                c1.InitializeKey(tempK1);
                c2.InitializeKey(tempK2);

                return (c1, c2);
            }
        }

		/// <summary>
		/// Returns true if k is non-empty, false otherwise.
		/// </summary>
		public bool HasKey()
		{
			return state.HasKey();
		}

		public void Dispose()
		{
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
                return;

            hash.Dispose();
            hkdf.Dispose();
            state.Dispose();
            unsafe
            {
                Libsodium.sodium_free(ck);
            }
        }
	}
}
