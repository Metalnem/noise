using System.Collections.Generic;
using System.Security.Cryptography;
using Blake2Core;
using Xunit;

namespace Noise.Tests
{
	public class HashTest
	{
		[Fact]
		public void TestGetHashAndReset()
		{
			int maxSize = 2048;

			var algorithms = new Dictionary<Hash, HashAlgorithm>
			{
				{new Sha256(), SHA256.Create()},
				{new Sha512(), SHA512.Create()},
				{new Blake2b(), Blake2B.Create().AsHashAlgorithm()}
			};

			foreach (var algorithm in algorithms)
			{
				using (var hash = algorithm.Key)
				using (var reference = algorithm.Value)
				{
					for (int size = 0; size < maxSize; ++size)
					{
						Test(hash, reference, new byte[size]);

						if (size > 0)
						{
							Test(hash, reference, Utilities.GetRandomBytes(size));
						}
					}
				}
			}
		}

		private void Test(Hash hash, HashAlgorithm reference, byte[] data)
		{
			hash.AppendData(data);
			var full = hash.GetHashAndReset();

			for (int i = 0; i < data.Length; ++i)
			{
				hash.AppendData(new byte[] { data[i] });
			}

			var incremental = hash.GetHashAndReset();
			var expected = reference.ComputeHash(data);

			Assert.Equal(expected, full);
			Assert.Equal(expected, incremental);
		}
	}
}
