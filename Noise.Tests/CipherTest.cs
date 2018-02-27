using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Noise.Tests
{
	public class CipherTest
	{
		[Fact]
		public void TestEncryptAndDecrypt()
		{
			var ciphers = new List<Cipher>
			{
				new Aes256Gcm(),
				new ChaCha20Poly1305()
			};

			foreach (var cipher in ciphers)
			{
				byte[] key = new byte[32];
				byte[] data = Encoding.UTF8.GetBytes("Ice Ice Baby");
				string message = "I'm cooking MC's like a pound of bacon";

				byte[] ciphertext = cipher.Encrypt(key, UInt64.MaxValue, data, Encoding.UTF8.GetBytes(message));
				byte[] plaintext = cipher.Decrypt(key, UInt64.MaxValue, data, ciphertext);

				Assert.Equal(message, Encoding.UTF8.GetString(plaintext));
			}
		}
	}
}
