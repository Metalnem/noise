using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class BlakeTest
	{
		[Fact]
		public void TestVectors()
		{
			var s = File.ReadAllText("Vectors/blake2-kat.json");
			var json = JArray.Parse(s);

			using (var hasher = new Blake2s())
			{
				byte[] hash = new byte[hasher.HashLen];

				foreach (var vector in json)
				{
					var name = (string)vector["hash"];
					var input = Hex.Decode((string)vector["in"]);
					var key = (string)vector["key"];
					var output = Hex.Decode((string)vector["out"]);

					if (name == "blake2s" && String.IsNullOrEmpty(key))
					{
						hasher.AppendData(input);
						hasher.GetHashAndReset(hash);

						Assert.Equal(output, hash);
					}
				}
			}
		}

		[Fact(Skip = "Takes too long to complete.")]
		public void TestLargeInput()
		{
			var factor = 1031;
			var data = new byte[factor];

			using (var hasher = new Blake2s())
			{
				int count = 4 * factor * factor;

				for (int i = 0; i < count; ++i)
				{
					hasher.AppendData(data);
				}

				var hash = new byte[hasher.HashLen];
				hasher.GetHashAndReset(hash);

				string expected = "3c965aaac533c5a1715a40ae8beaf8d1fe1242502f2c30db34239b16c54b1d78";
				string actual = Hex.Encode(hash);

				Assert.Equal(expected, actual);
			}
		}

		[Fact(Skip = "Takes too long to complete.")]
		public void TestSplits()
		{
			var data = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray().AsReadOnlySpan();

			using (var hasher = new Blake2s())
			{
				var hash1 = new byte[hasher.HashLen];
				var hash2 = new byte[hasher.HashLen];

				for (int i = 0; i <= data.Length; ++i)
				{
					hasher.AppendData(data.Slice(0, i));
					hasher.GetHashAndReset(hash1);

					for (int j = 0; j <= i; ++j)
					{
						for (int k = j; k <= i; ++k)
						{
							hasher.AppendData(data.Slice(0, j));
							hasher.AppendData(data.Slice(j, k - j));
							hasher.AppendData(data.Slice(k, i - k));
							hasher.GetHashAndReset(hash2);

							Assert.Equal(hash1, hash2);
						}
					}
				}
			}
		}
	}
}
