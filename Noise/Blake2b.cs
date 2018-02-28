using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Noise
{
	/// <summary>
	/// The BLAKE2b hash function.
	/// </summary>
	internal sealed class Blake2b : Hash
	{
		/// <summary>
		/// Gets the name of the algorithm being performed.
		/// </summary>
		public static readonly HashAlgorithmName Name = new HashAlgorithmName("BLAKE2b");

		private readonly IntPtr raw;
		private readonly IntPtr aligned;
		private bool disposed;

		public Blake2b()
		{
			// The crypto_generichash_state structure is packed and its length is
			// either 357 or 361 bytes. For this reason, padding must be added in
			// order to ensure proper alignment.

			int size = 361;
			int alignment = 64;

			raw = Marshal.AllocHGlobal(size + alignment);
			aligned = (IntPtr)((ulong)raw & ~(63UL));

			Reset();
		}

		public int HashLen => 64;
		public int BlockLen => 128;

		public void AppendData(byte[] data)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Blake2b));
			}

			if (data == null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			Libsodium.crypto_generichash_blake2b_update(aligned, data, (ulong)data.LongLength);
		}

		public byte[] GetHashAndReset()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Blake2b));
			}

			byte[] hash = new byte[HashLen];
			Libsodium.crypto_generichash_blake2b_final(aligned, hash, (UIntPtr)hash.Length);

			Reset();

			return hash;
		}

		private void Reset()
		{
			Libsodium.crypto_generichash_blake2b_init(aligned, null, UIntPtr.Zero, (UIntPtr)HashLen);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				Marshal.FreeHGlobal(raw);
				disposed = true;
			}
		}
	}
}
