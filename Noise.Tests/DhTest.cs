using Xunit;

namespace Noise.Tests
{
	public class DhTest
	{
		[Fact]
		public void TestDh()
		{
			var dh = new Curve25519();

			var keyA = dh.GenerateKeyPair();
			var keyB = dh.GenerateKeyPair();

			var sharedKeyA = dh.Dh(keyA, keyB.PublicKey);
			var sharedKeyB = dh.Dh(keyB, keyA.PublicKey);

			Assert.Equal(sharedKeyA, sharedKeyB);
		}
	}
}
