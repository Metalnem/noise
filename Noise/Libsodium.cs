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

		static Libsodium()
		{
			if (sodium_init() == -1)
			{
				throw new CryptographicException("Failed to initialize libsodium.");
			}
		}

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		private static extern int sodium_init();

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		public static extern int crypto_aead_aes256gcm_encrypt(
			byte[] c,
			out long clen_p,
			byte[] m,
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
			byte[] c,
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
			byte[] m,
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
			byte[] c,
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
	}
}
