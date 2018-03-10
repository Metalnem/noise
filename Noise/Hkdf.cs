using System;
using System.Diagnostics;

namespace Noise
{
	/// <summary>
	/// HMAC-based Extract-and-Expand Key Derivation Function, defined in
	/// <see href="https://tools.ietf.org/html/rfc5869">RFC 5869</see>.
	/// </summary>
	internal static class Hkdf<HashType> where HashType : Hash, new()
	{
		private static readonly byte[] one = new byte[] { 1 };
		private static readonly byte[] two = new byte[] { 2 };
		private static readonly byte[] three = new byte[] { 3 };

		/// <summary>
		/// Takes a chainingKey byte sequence of length HashLen,
		/// and an inputKeyMaterial byte sequence with length
		/// either zero bytes, 32 bytes, or DhLen bytes. Writes a
		/// byte sequences of length 2 * HashLen into output parameter.
		/// </summary>
		public static void ExtractAndExpand2(
			ReadOnlySpan<byte> chainingKey,
			ReadOnlySpan<byte> inputKeyMaterial,
			Span<byte> output)
		{
			int hashLen = chainingKey.Length;
			Debug.Assert(output.Length == 2 * hashLen);

			Span<byte> tempKey = stackalloc byte[hashLen];
			HmacHash(chainingKey, tempKey, inputKeyMaterial);

			var output1 = output.Slice(0, hashLen);
			HmacHash(tempKey, output1, one);

			var output2 = output.Slice(hashLen, hashLen);
			HmacHash(tempKey, output2, output1, two);
		}

		/// <summary>
		/// Takes a chainingKey byte sequence of length HashLen,
		/// and an inputKeyMaterial byte sequence with length
		/// either zero bytes, 32 bytes, or DhLen bytes. Writes a
		/// byte sequences of length 3 * HashLen into output parameter.
		/// </summary>
		public static void ExtractAndExpand3(
			ReadOnlySpan<byte> chainingKey,
			ReadOnlySpan<byte> inputKeyMaterial,
			Span<byte> output)
		{
			int hashLen = chainingKey.Length;
			Debug.Assert(output.Length == 3 * hashLen);

			Span<byte> tempKey = stackalloc byte[hashLen];
			HmacHash(chainingKey, tempKey, inputKeyMaterial);

			var output1 = output.Slice(0, hashLen);
			HmacHash(tempKey, output1, one);

			var output2 = output.Slice(hashLen, hashLen);
			HmacHash(tempKey, output2, output1, two);

			var output3 = output.Slice(2 * hashLen, hashLen);
			HmacHash(tempKey, output3, output2, three);
		}

		private static void HmacHash(
			ReadOnlySpan<byte> key,
			Span<byte> hmac,
			ReadOnlySpan<byte> data1 = default,
			ReadOnlySpan<byte> data2 = default)
		{
			using (var inner = new HashType())
			using (var outer = new HashType())
			{
				Debug.Assert(key.Length == inner.HashLen);
				Debug.Assert(hmac.Length == inner.HashLen);

				var blockLen = inner.BlockLen;

				Span<byte> ipad = stackalloc byte[blockLen];
				Span<byte> opad = stackalloc byte[blockLen];

				key.CopyTo(ipad);
				key.CopyTo(opad);

				for (int i = 0; i < blockLen; ++i)
				{
					ipad[i] ^= 0x36;
					opad[i] ^= 0x5C;
				}

				inner.AppendData(ipad);
				inner.AppendData(data1);
				inner.AppendData(data2);
				inner.GetHashAndReset(hmac);

				outer.AppendData(opad);
				outer.AppendData(hmac);
				outer.GetHashAndReset(hmac);
			}
		}
	}
}
