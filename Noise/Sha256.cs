using System;
using System.Runtime.InteropServices;

namespace Noise
{
	/// <summary>
	/// The SHA256 hash function.
	/// </summary>
	internal sealed class Sha256 : Hash
	{
		// typedef struct crypto_hash_sha256_state {
		//     uint32_t state[8];
		//     uint64_t count;
		//     uint8_t  buf[64];
		// } crypto_hash_sha256_state;

		private readonly IntPtr state = Marshal.AllocHGlobal(104);
		private bool disposed;

		public Sha256() => Reset();

		public int HashLen => 32;
		public int BlockLen => 64;

		public void AppendData(ReadOnlySpan<byte> data)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Sha256));
			}

			ref byte message = ref MemoryMarshal.GetReference(data);
			Libsodium.crypto_hash_sha256_update(state, ref message, (ulong)data.Length);
		}

		public byte[] GetHashAndReset()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Sha256));
			}

			byte[] hash = new byte[HashLen];
			Libsodium.crypto_hash_sha256_final(state, hash);

			Reset();

			return hash;
		}

		private void Reset()
		{
			Libsodium.crypto_hash_sha256_init(state);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				Marshal.FreeHGlobal(state);
				disposed = true;
			}
		}
	}
}
