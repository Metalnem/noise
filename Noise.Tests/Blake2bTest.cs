using Blake2Core;
using Xunit;

namespace Noise.Tests
{
	public class Blake2bTest
	{
		[Fact]
		public void TestGetHashAndReset()
		{
			int maxSize = 2048;

			using (var hash = new Blake2b())
			{
				for (int size = 0; size < maxSize; ++size)
				{
					Test(hash, new byte[size]);

					if (size > 0)
					{
						Test(hash, Random.GetBytes(size));
					}
				}
			}
		}

		private void Test(Hash hash, byte[] data)
		{
			hash.AppendData(data);
			var full = hash.GetHashAndReset();

			for (int i = 0; i < data.Length; ++i)
			{
				hash.AppendData(new byte[] { data[i] });
			}

			var incremental = hash.GetHashAndReset();
			var expected = Blake2B.ComputeHash(data);

			Assert.Equal(expected, full);
			Assert.Equal(expected, incremental);
		}
	}
}
