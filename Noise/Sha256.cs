using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The SHA256 hash function.
	/// </summary>
	internal sealed class Sha256 : Hash
	{
		private readonly IncrementalHash hash;
		private bool disposed;

		public Sha256()
		{
			hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
		}

		public string Name => "SHA256";
		public int HashLen => 32;
		public int BlockLen => 64;

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
