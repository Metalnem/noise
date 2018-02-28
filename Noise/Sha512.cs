using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The SHA512 hash function.
	/// </summary>
	internal sealed class Sha512 : Hash
	{
		private readonly IncrementalHash hash;
		private bool disposed;

		public Sha512()
		{
			hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
		}

		public int HashLen => 64;
		public int BlockLen => 128;

		public void AppendData(byte[] data) => hash.AppendData(data);
		public byte[] GetHashAndReset() => hash.GetHashAndReset();

		public void Dispose()
		{
			if (!disposed)
			{
				hash.Dispose();
				disposed = true;
			}
		}
	}
}
