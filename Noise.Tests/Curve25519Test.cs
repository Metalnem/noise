using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Noise.Tests
{
	public class Curve25519Test
	{
		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		[Fact]
		public void TestDiffieHellman()
		{
			var privateKeyA = Random.GetBytes(Curve25519.KeySize);
			var privateKeyB = Random.GetBytes(Curve25519.KeySize);

			var publicKeyA = Curve25519.ScalarBaseMult(privateKeyA);
			var publicKeyB = Curve25519.ScalarBaseMult(privateKeyB);

			var sharedKeyA = Curve25519.ScalarMult(privateKeyA, publicKeyB);
			var sharedKeyB = Curve25519.ScalarMult(privateKeyB, publicKeyA);

			Assert.Equal(sharedKeyA, sharedKeyB);
		}
	}
}
