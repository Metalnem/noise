using System;
using System.Text;
using Xunit;

namespace Noise.Tests
{
	public class ChaCha20Poly1305Test
	{
		[Fact]
		public void TestEncryptAndDecrypt()
		{
			byte[] key = new byte[ChaCha20Poly1305.KeySize];
			byte[] data = Encoding.UTF8.GetBytes("Ice Ice Baby");
			string message = "I'm cooking MC's like a pound of bacon";

			byte[] ciphertext = ChaCha20Poly1305.Encrypt(key, UInt64.MaxValue, data, Encoding.UTF8.GetBytes(message));
			byte[] plaintext = ChaCha20Poly1305.Decrypt(key, UInt64.MaxValue, data, ciphertext);

			Assert.Equal(message, Encoding.UTF8.GetString(plaintext));
		}
	}
}
