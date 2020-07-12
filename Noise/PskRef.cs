using System;

namespace Noise
{
    public sealed class PskRef : IDisposable
    {
        public unsafe byte* ptr;
        public int len;

        private unsafe PskRef(byte* ptr, uint size)
        {
            this.ptr = ptr;
            len = (int) size;
        }

        public static PskRef Create(uint size = Aead.KeySize)
        {
            unsafe
            {
                var ptr = (byte*) Libsodium.sodium_malloc(size);
                Libsodium.randombytes_buf(ptr, size);
                return new PskRef(ptr, size);
            }
        }

        public static unsafe PskRef Create(byte* buffer, uint len = Aead.KeySize)
        {
            unsafe
            {
                var b = (byte*) Libsodium.sodium_malloc(len);
                for (var i = 0; i < len; i++)
                    b[i] = buffer[i];
                return new PskRef(b, len);
            }
        }

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

        private void ReleaseUnmanagedResources()
        {
            unsafe
            {
                Libsodium.sodium_free(ptr);
            }
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        ~PskRef()
        {
            ReleaseUnmanagedResources();
        }
    }
}