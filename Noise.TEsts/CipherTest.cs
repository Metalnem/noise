using System;
using System.Text;
using Xunit;

namespace Noise.Tests
{
	public class CipherTest
	{
		[Fact]
		public void TestEncryptAndDecrypt()
		{
			byte[] key = new byte[32];
			byte[] data = Encoding.UTF8.GetBytes("Ice Ice Baby");
			string message = "I'm cooking MC's like a pound of bacon";

			Cipher cipher = new ChaCha20Poly1305();
			byte[] ciphertext = cipher.Encrypt(key, UInt64.MaxValue, data, Encoding.UTF8.GetBytes(message));
			byte[] plaintext = cipher.Decrypt(key, UInt64.MaxValue, data, ciphertext);

			Assert.Equal(message, Encoding.UTF8.GetString(plaintext));
		}
	}
}
