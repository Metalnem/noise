using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// HMAC-based Extract-and-Expand Key Derivation Function, defined in
	/// <see href="https://tools.ietf.org/html/rfc5869">RFC 5869</see>.
	/// </summary>
	internal static class Hkdf
	{
		private static readonly byte[] one = new byte[] { 1 };
		private static readonly byte[] two = new byte[] { 2 };
		private static readonly byte[] three = new byte[] { 3 };

		/// <summary>
		/// Takes a chainingKey byte sequence of length HashLen,
		/// and an inputKeyMaterial byte sequence with length
		/// either zero bytes, 32 bytes, or DhLen bytes. Returns
		/// a pair of byte sequences each of length HashLen.
		/// </summary>
		public static (byte[], byte[]) ExtractAndExpand2(HashAlgorithmName hashName, byte[] chainingKey, byte[] inputKeyMaterial)
		{
			var tempKey = HmacHash(hashName, chainingKey, inputKeyMaterial);
			var output1 = HmacHash(hashName, tempKey, one);
			var output2 = HmacHash(hashName, tempKey, output1, two);

			return (output1, output2);
		}

		/// <summary>
		/// Takes a chainingKey byte sequence of length HashLen,
		/// and an inputKeyMaterial byte sequence with length
		/// either zero bytes, 32 bytes, or DhLen bytes. Returns
		/// a triple of byte sequences each of length HashLen.
		/// </summary>
		public static (byte[], byte[], byte[]) ExtractAndExpand3(HashAlgorithmName hashName, byte[] chainingKey, byte[] inputKeyMaterial)
		{
			var tempKey = HmacHash(hashName, chainingKey, inputKeyMaterial);
			var output1 = HmacHash(hashName, tempKey, one);
			var output2 = HmacHash(hashName, tempKey, output1, two);
			var output3 = HmacHash(hashName, tempKey, output2, three);

			return (output1, output2, output3);
		}

		private static byte[] HmacHash(HashAlgorithmName hashName, byte[] key, params byte[][] data)
		{
			using (var inner = hashName.Create())
			using (var outer = hashName.Create())
			{
				int blockLen = inner.BlockLen;

				if (key.Length > blockLen)
				{
					outer.AppendData(key);
					key = outer.GetHashAndReset();
				}

				byte[] ipad = new byte[blockLen];
				byte[] opad = new byte[blockLen];

				Array.Copy(key, ipad, ipad.Length);
				Array.Copy(key, opad, opad.Length);

				for (int i = 0; i < blockLen; ++i)
				{
					ipad[i] ^= 0x36;
					opad[i] ^= 0x5C;
				}

				inner.AppendData(ipad);

				foreach (var item in data)
				{
					inner.AppendData(item);
				}

				outer.AppendData(opad);
				outer.AppendData(inner.GetHashAndReset());

				return outer.GetHashAndReset();
			}
		}
	}
}
