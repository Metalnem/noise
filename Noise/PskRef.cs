using System;
using System.Threading;

namespace Noise
{
    /// <summary>
    /// Holds a reference to a pre-shared key in unmanaged memory.
    /// </summary>
    public struct PskRef : IDisposable
    {
        /// <summary>
        /// A reference to the pre-shared key in memory. 
        /// </summary>
        public unsafe byte* ptr;

        /// <summary>
        /// The length of the pre-shared key.
        /// </summary>
        public int len;

        private unsafe PskRef(byte* ptr, uint size)
        {
            this.ptr = ptr;
            len = (int) size;
            _disposed = 0;
        }

        /// <summary>
        /// Creates a new pre-shared key of a given length.
        /// The key is filled with random, non-zero bytes in a cryptographically secure fashion. 
        /// </summary>
        /// <param name="size">Tge size of the key to generate.</param>
        /// <returns></returns>
        public static PskRef Create(uint size = Aead.KeySize)
        {
            unsafe
            {
                var ptr = (byte*) Libsodium.sodium_malloc(size);
                Libsodium.randombytes_buf(ptr, size);
                return new PskRef(ptr, size);
            }
        }

        /// <summary>
        /// Creates a new pre-shared key based on an existing pointer.
        /// This allocates a new copy of the existing key, which protects against disposal of the cloned key.
        /// </summary>
        /// <param name="buffer">A reference to the existing key.</param>
        /// <param name="len">The length of the existing key to copy into the new key.</param>
        /// <returns></returns>
        public static unsafe PskRef Create(byte* buffer, uint len = Aead.KeySize)
        {
            var b = (byte*) Libsodium.sodium_malloc(len);
            for (var i = 0; i < len; i++)
                b[i] = buffer[i];
            return new PskRef(b, len);
        }

        /// <summary>
        /// Creates a new pre-shared key reference based on an existing data buffer.
        /// Mainly useful for tests, as passing an in-memory buffer exposes the key.
        /// </summary>
        /// <param name="buffer">The pre-defined buffer representing the key.</param>
        /// <returns></returns>
        public static PskRef Create(byte[] buffer)
        {
            unsafe
            {
                var len = buffer.Length;
                var b = (byte*) Libsodium.sodium_malloc((ulong) len);
                for (var i = 0; i < buffer.Length; i++)
                    b[i] = buffer[i];
                return new PskRef(b, (uint) len);
            }
        }

        private int _disposed;

        /// <inheritdoc />
        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
                return;

            unsafe
            {
                Libsodium.sodium_free(ptr);
            }
        }
    }
}