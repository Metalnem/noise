using System;
using System.Runtime.InteropServices;

namespace Noise
{
	/// <summary>
	/// The SHA512 hash function.
	/// </summary>
	internal sealed class Sha512 : Hash
	{
		// typedef struct crypto_hash_sha512_state {
		//     uint64_t state[8];
		//     uint64_t count[2];
		//     uint8_t  buf[128];
		// } crypto_hash_sha512_state;

		private readonly IntPtr state = Marshal.AllocHGlobal(208);
		private bool disposed;

		public Sha512() => Reset();

		public int HashLen => 64;
		public int BlockLen => 128;

		public void AppendData(ReadOnlySpan<byte> data)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Sha512));
			}

			ref byte message = ref MemoryMarshal.GetReference(data);
			Libsodium.crypto_hash_sha512_update(state, ref message, (ulong)data.Length);
		}

		public byte[] GetHashAndReset()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Sha512));
			}

			byte[] hash = new byte[HashLen];
			Libsodium.crypto_hash_sha512_final(state, hash);

			Reset();

			return hash;
		}

		private void Reset()
		{
			Libsodium.crypto_hash_sha512_init(state);
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
