using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Noise
{
	internal static class Libsodium
	{
		private const string Name = "libsodium";

		public const int crypto_scalarmult_curve25519_BYTES = 32;
		public const int crypto_scalarmult_curve25519_SCALARBYTES = 32;

		public static readonly bool IsAes256GcmAvailable;

		static Libsodium()
		{
			if (sodium_init() == -1)
			{
				throw new CryptographicException("Failed to initialize libsodium.");
			}

			IsAes256GcmAvailable = crypto_aead_aes256gcm_is_available() == 1;
		}

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		private static extern int sodium_init();

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		private static extern int crypto_aead_aes256gcm_is_available();

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_aead_aes256gcm_encrypt(
			byte[] c,
			out long clen_p,
			ref byte m,
			long mlen,
			byte[] ad,
			long adlen,
			IntPtr nsec,
			byte[] npub,
			byte[] k
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_aead_aes256gcm_decrypt(
			byte[] m,
			out long mlen_p,
			IntPtr nsec,
			ref byte c,
			long clen,
			byte[] ad,
			long adlen,
			byte[] npub,
			byte[] k
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_aead_chacha20poly1305_ietf_encrypt(
			byte[] c,
			out long clen_p,
			ref byte m,
			long mlen,
			byte[] ad,
			long adlen,
			IntPtr nsec,
			byte[] npub,
			byte[] k
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_aead_chacha20poly1305_ietf_decrypt(
			byte[] m,
			out long mlen_p,
			IntPtr nsec,
			ref byte c,
			long clen,
			byte[] ad,
			long adlen,
			byte[] npub,
			byte[] k
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_scalarmult_curve25519_base(
			byte[] q,
			byte[] n
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_scalarmult_curve25519(
			byte[] q,
			byte[] n,
			byte[] p
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_hash_sha256_init(
			IntPtr state
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_hash_sha256_update(
			IntPtr state,
			ref byte @in,
			ulong inlen
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_hash_sha256_final(
			IntPtr state,
			byte[] @out
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_hash_sha512_init(
			IntPtr state
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_hash_sha512_update(
			IntPtr state,
			ref byte @in,
			ulong inlen
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_hash_sha512_final(
			IntPtr state,
			byte[] @out
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_generichash_blake2b_init(
			IntPtr state,
			byte[] key,
			UIntPtr keylen,
			UIntPtr outlen
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_generichash_blake2b_update(
			IntPtr state,
			ref byte @in,
			ulong inlen
		);

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_generichash_blake2b_final(
			IntPtr state,
			byte[] @out,
			UIntPtr outlen
		);
	}
}
