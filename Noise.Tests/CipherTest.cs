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
				var key = new byte[32];
				var data = Encoding.UTF8.GetBytes("Ice Ice Baby");
				var message = "I'm cooking MC's like a pound of bacon";

				var ciphertextBuffer = new byte[message.Length + Constants.TagSize];
				var ciphertext = cipher.Encrypt(key, UInt64.MaxValue, data, Encoding.UTF8.GetBytes(message), ciphertextBuffer);

				var plaintextBuffer = new byte[message.Length];
				var plaintext = cipher.Decrypt(key, UInt64.MaxValue, data, ciphertext, plaintextBuffer);

				Assert.Equal(message, Encoding.UTF8.GetString(plaintext.ToArray()));
			}
		}
	}
}
