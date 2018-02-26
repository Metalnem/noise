using System;
using System.Security.Cryptography;
using Cryptography;

namespace Noise
{
	/// <summary>
	/// A SymmetricState object contains a CipherState plus ck (a chaining
	/// key of HashLen bytes) and h (a hash output of HashLen bytes).
	/// </summary>
	internal sealed class SymmetricState : IDisposable
	{
		private readonly Cipher cipher;
		private readonly Dh dh;
		private readonly CipherState state;
		private readonly byte[] ck;
		private byte[] h;
		private bool disposed;

		/// <summary>
		/// Initializes a new SymmetricState with an
		/// arbitrary-length protocolName byte sequence.
		/// </summary>
		public SymmetricState(byte[] protocolName, Cipher cipher, Dh dh)
		{
			if (protocolName == null)
			{
				throw new ArgumentNullException(nameof(protocolName));
			}

			this.cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
			this.dh = dh ?? throw new ArgumentNullException(nameof(dh));

			if (protocolName.Length <= Hash.HashLen)
			{
				h = new byte[Hash.HashLen];
				Array.Copy(protocolName, h, protocolName.Length);
			}
			else
			{
				h = Hash.Sum(protocolName);
			}

			state = new CipherState(cipher);
			ck = h;
		}

		/// <summary>
		/// Sets ck, tempK = HKDF(ck, inputKeyMaterial, 2).
		/// If HashLen is 64, then truncates tempK to 32 bytes.
		/// Calls InitializeKey(tempK).
		/// </summary>
		public void MixKey(byte[] inputKeyMaterial)
		{
			ValidateInputKeyMaterial(inputKeyMaterial);

			using (var hkdf = Hkdf.CreateSha256Hkdf(inputKeyMaterial, ck, null))
			{
				var tempK = new byte[32];

				hkdf.GetBytes(ck);
				hkdf.GetBytes(tempK);

				state.InitializeKey(tempK);
			}
		}

		/// <summary>
		/// Sets h = HASH(h || data).
		/// </summary>
		public void MixHash(byte[] data)
		{
			h = Hash.Sum(h, data);
		}

		/// <summary>
		/// Sets ck, tempH, tempK = HKDF(ck, inputKeyMaterial, 3).
		/// Calls MixHash(tempH).
		/// If HashLen is 64, then truncates tempK to 32 bytes.
		/// Calls InitializeKey(tempK).
		/// </summary>
		public void MixKeyAndHash(byte[] inputKeyMaterial)
		{
			ValidateInputKeyMaterial(inputKeyMaterial);

			using (var hkdf = Hkdf.CreateSha256Hkdf(inputKeyMaterial, ck, null))
			{
				var tempH = new byte[Hash.HashLen];
				var tempK = new byte[32];

				hkdf.GetBytes(ck);
				hkdf.GetBytes(tempH);
				hkdf.GetBytes(tempK);

				MixHash(tempH);
				state.InitializeKey(tempK);
			}
		}

		/// <summary>
		/// Returns h. This function should only be called at the end of
		/// a handshake, i.e. after the Split() function has been called.
		/// </summary>
		public byte[] GetHandshakeHash()
		{
			return h;
		}

		/// <summary>
		/// Sets ciphertext = EncryptWithAd(h, plaintext),
		/// calls MixHash(ciphertext), and returns ciphertext.
		/// </summary>
		public byte[] EncryptAndHash(byte[] plaintext)
		{
			var ciphertext = state.EncryptWithAd(h, plaintext);
			MixHash(ciphertext);

			return ciphertext;
		}

		/// <summary>
		/// Sets plaintext = DecryptWithAd(h, ciphertext),
		/// calls MixHash(ciphertext), and returns plaintext.
		/// </summary>
		public byte[] DecryptAndHash(byte[] ciphertext)
		{
			var plaintext = state.DecryptWithAd(h, ciphertext);
			MixHash(ciphertext);

			return plaintext;
		}

		/// <summary>
		/// Returns a pair of CipherState objects for encrypting transport messages.
		/// </summary>
		public (CipherState c1, CipherState c2) Split()
		{
			using (var hkdf = Hkdf.CreateSha256Hkdf(null, ck, null))
			{
				var tempK1 = new byte[32];
				var tempK2 = new byte[32];

				hkdf.GetBytes(tempK1);
				hkdf.GetBytes(tempK2);

				var c1 = new CipherState(cipher);
				var c2 = new CipherState(cipher);

				c1.InitializeKey(tempK1);
				c2.InitializeKey(tempK2);

				return (c1, c2);
			}
		}

		private void ValidateInputKeyMaterial(byte[] inputKeyMaterial)
		{
			if (inputKeyMaterial != null)
			{
				int length = inputKeyMaterial.Length;

				if (length != 0 && length != 32 && length != dh.DhLen)
				{
					throw new CryptographicException("Input key material must be either 0 bytes, 32 byte, or DhLen bytes long.");
				}
			}
		}

		/// <summary>
		/// Disposes the object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				state.Dispose();
				Array.Clear(ck, 0, ck.Length);
				Array.Clear(h, 0, h.Length);
				disposed = true;
			}
		}
	}
}
