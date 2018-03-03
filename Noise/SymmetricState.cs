using System;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// A SymmetricState object contains a CipherState plus ck (a chaining
	/// key of HashLen bytes) and h (a hash output of HashLen bytes).
	/// </summary>
	internal sealed class SymmetricState<CipherType, DhType, HashType> : IDisposable
		where CipherType : Cipher, new()
		where DhType : Dh, new()
		where HashType : Hash, new()
	{
		private readonly Cipher cipher = new CipherType();
		private readonly DhType dh = new DhType();
		private readonly Hash hash = new HashType();
		private readonly CipherState<CipherType> state = new CipherState<CipherType>();
		private byte[] ck;
		private byte[] h;
		private bool disposed;

		/// <summary>
		/// Initializes a new SymmetricState with an
		/// arbitrary-length protocolName byte sequence.
		/// </summary>
		public SymmetricState(byte[] protocolName)
		{
			if (protocolName == null)
			{
				throw new ArgumentNullException(nameof(protocolName));
			}

			if (protocolName.Length <= this.hash.HashLen)
			{
				h = new byte[this.hash.HashLen];
				Array.Copy(protocolName, h, protocolName.Length);
			}
			else
			{
				this.hash.AppendData(protocolName);
				h = this.hash.GetHashAndReset();
			}

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

			var (ck, tempK) = Hkdf<HashType>.ExtractAndExpand2(this.ck, inputKeyMaterial);

			Array.Clear(this.ck, 0, this.ck.Length);
			this.ck = ck;

			state.InitializeKey(Truncate(tempK));
		}

		/// <summary>
		/// Sets h = HASH(h || data).
		/// </summary>
		public void MixHash(ReadOnlySpan<byte> data)
		{
			hash.AppendData(h);
			hash.AppendData(data);

			h = hash.GetHashAndReset();
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

			var (ck, tempH, tempK) = Hkdf<HashType>.ExtractAndExpand3(this.ck, inputKeyMaterial);

			Array.Clear(this.ck, 0, this.ck.Length);
			this.ck = ck;

			MixHash(tempH);
			state.InitializeKey(Truncate(tempK));
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
		public Span<byte> EncryptAndHash(Span<byte> plaintext)
		{
			var ciphertext = state.EncryptWithAd(h, plaintext);
			MixHash(ciphertext);

			return ciphertext;
		}

		/// <summary>
		/// Sets plaintext = DecryptWithAd(h, ciphertext),
		/// calls MixHash(ciphertext), and returns plaintext.
		/// </summary>
		public Span<byte> DecryptAndHash(Span<byte> ciphertext)
		{
			var plaintext = state.DecryptWithAd(h, ciphertext);
			MixHash(ciphertext);

			return plaintext;
		}

		/// <summary>
		/// Returns a pair of CipherState objects for encrypting transport messages.
		/// </summary>
		public (CipherState<CipherType> c1, CipherState<CipherType> c2) Split()
		{
			var (tempK1, tempK2) = Hkdf<HashType>.ExtractAndExpand2(ck, null);

			var c1 = new CipherState<CipherType>();
			var c2 = new CipherState<CipherType>();

			c1.InitializeKey(Truncate(tempK1));
			c2.InitializeKey(Truncate(tempK2));

			return (c1, c2);
		}

		private void ValidateInputKeyMaterial(byte[] inputKeyMaterial)
		{
			if (inputKeyMaterial == null)
			{
				throw new ArgumentNullException(nameof(inputKeyMaterial));
			}

			int length = inputKeyMaterial.Length;

			if (length != 0 && length != Constants.KeySize && length != dh.DhLen)
			{
				throw new CryptographicException("Input key material must be either 0 bytes, 32 byte, or DhLen bytes long.");
			}
		}

		private static byte[] Truncate(byte[] key)
		{
			if (key.Length == Constants.KeySize)
			{
				return key;
			}

			var temp = new byte[Constants.KeySize];

			Array.Copy(key, temp, temp.Length);
			Array.Clear(key, 0, key.Length);

			return temp;
		}

		/// <summary>
		/// Disposes the object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				hash.Dispose();
				state.Dispose();
				Array.Clear(ck, 0, ck.Length);
				Array.Clear(h, 0, h.Length);
				disposed = true;
			}
		}
	}
}
