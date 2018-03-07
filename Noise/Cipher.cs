using System;

namespace Noise
{
	/// <summary>
	/// Cipher functions.
	/// </summary>
	internal interface Cipher
	{
		/// <summary>
		/// Encrypts plaintext using the cipher key k of 32 bytes
		/// and an 8-byte unsigned integer nonce n which must be
		/// unique for the key k. Returns the ciphertext. Encryption
		/// must be done with an "AEAD" encryption mode with the
		/// associated data ad and returns a ciphertext that is the
		/// same size as the plaintext plus 16 bytes for authentication data.
		/// </summary>
		int Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext);

		/// <summary>
		/// Decrypts ciphertext using a cipher key k of 32 bytes,
		/// an 8-byte unsigned integer nonce n, and associated data ad.
		/// Returns the plaintext, unless authentication fails,
		/// in which case an error is signaled to the caller.
		/// </summary>
		int Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);
	}
}
