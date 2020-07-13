using System;
using System.Diagnostics;

namespace Noise
{
	/// <summary>
	/// HMAC-based Extract-and-Expand Key Derivation Function, defined in
	/// <see href="https://tools.ietf.org/html/rfc5869">RFC 5869</see>.
	/// </summary>
	internal sealed class Hkdf<HashType> : IDisposable where HashType : Hash, new()
	{
		private static readonly byte[] one = new byte[] { 1 };
		private static readonly byte[] two = new byte[] { 2 };
		private static readonly byte[] three = new byte[] { 3 };

		private readonly HashType inner = new HashType();
		private readonly HashType outer = new HashType();
		private bool disposed;

		/// <summary>
        /// Takes a chainingKey byte sequence of length HashLen,
        /// and an inputKeyMaterial byte sequence with length
        /// either zero bytes, 32 bytes, or DhLen bytes. Writes a
        /// byte sequences of length 2 * HashLen into output parameter.
        /// </summary>
        public unsafe void ExtractAndExpand2(
            byte* chainingKey,
            int chainingKeyLen,
            ReadOnlySpan<byte> inputKeyMaterial,
            Span<byte> output)
        {
            var hashLen = inner.HashLen;

            Debug.Assert(chainingKeyLen == hashLen);
            Debug.Assert(output.Length == 2 * hashLen);

            var tempKey = stackalloc byte[hashLen];

            HmacHash(chainingKey, chainingKeyLen, tempKey, hashLen, inputKeyMaterial);

            var output1 = output.Slice(0, hashLen);
            fixed (byte* o1 = &output1.GetPinnableReference())
            {
                HmacHash(tempKey, hashLen, o1, hashLen, one);
            }
                    
            var output2 = output.Slice(hashLen, hashLen);
            fixed(byte* o2 = &output2.GetPinnableReference())
            {
                HmacHash(tempKey, hashLen, o2, hashLen, output1, two);    
            }
        }
        
        /// <summary>
        /// Takes a chainingKey byte sequence of length HashLen,
        /// and an inputKeyMaterial byte sequence with length
        /// either zero bytes, 32 bytes, or DhLen bytes. Writes a
        /// byte sequences of length 3 * HashLen into output parameter.
        /// </summary>
        public unsafe void ExtractAndExpand3(
            byte* chainingKey,
            int chainingKeyLen,
            ReadOnlySpan<byte> inputKeyMaterial,
            Span<byte> output)
        {
            var hashLen = inner.HashLen;

            Debug.Assert(chainingKeyLen == hashLen);
            Debug.Assert(output.Length == 3 * hashLen);

            var tempKey = stackalloc byte[hashLen];

            HmacHash(chainingKey, chainingKeyLen, tempKey, hashLen, inputKeyMaterial);

            var output1 = output.Slice(0, hashLen);
            fixed (byte* o1 = &output1.GetPinnableReference())
            {
                HmacHash(tempKey, hashLen, o1, hashLen, one);
            }

            var output2 = output.Slice(hashLen, hashLen);
            fixed (byte* o2 = &output2.GetPinnableReference())
            {
                HmacHash(tempKey, hashLen, o2, hashLen, output1, two);
            }
                   
            var output3 = output.Slice(2 * hashLen, hashLen);
            fixed (byte* o3 = &output3.GetPinnableReference())
            {
                HmacHash(tempKey, hashLen, o3, hashLen, output2, three); 
            }
        }
        private unsafe void HmacHash(
			byte* key,
			int keyLen,
			byte* hmac,
			int hmacLen,
			ReadOnlySpan<byte> data1 = default,
			ReadOnlySpan<byte> data2 = default)
		{
            Debug.Assert(keyLen == inner.HashLen);
            Debug.Assert(hmacLen == inner.HashLen);

            var blockLen = inner.BlockLen;

            var ipad = stackalloc byte[blockLen];
            var opad = stackalloc byte[blockLen];

            for (var i = 0; i < keyLen; i++)
            {
                ipad[i] = key[i];
                opad[i] = key[i];
            }

            for (var i = 0; i < blockLen; ++i)
            {
                ipad[i] ^= 0x36;
                opad[i] ^= 0x5C;
            }

            inner.AppendData(ipad, blockLen);
            inner.AppendData(data1);
            inner.AppendData(data2);
            inner.GetHashAndReset(hmac, hmacLen);

            outer.AppendData(opad, blockLen);
            outer.AppendData(hmac, hmacLen);
            outer.GetHashAndReset(hmac, hmacLen);
        }

		public void Dispose()
		{
			if (!disposed)
			{
				inner.Dispose();
				outer.Dispose();
				disposed = true;
			}
		}
	}
}
