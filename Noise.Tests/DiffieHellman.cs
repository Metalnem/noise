using Xunit;

namespace Noise.Tests
{
	public class DiffieHellmanTest
	{
		[Fact]
		public void TestDh()
		{
			var keyA = DiffieHellman.GenerateKeyPair();
			var keyB = DiffieHellman.GenerateKeyPair();

			var sharedKeyA = DiffieHellman.Dh(keyA, keyB.PublicKey);
			var sharedKeyB = DiffieHellman.Dh(keyB, keyA.PublicKey);

			Assert.Equal(sharedKeyA, sharedKeyB);
		}
	}
}
