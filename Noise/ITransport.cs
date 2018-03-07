using System;

namespace Noise
{
	/// <summary>
	/// A pair of CipherState objects for encrypting transport messages.
	/// </summary>
	public interface ITransport : IDisposable
	{
		/// <summary>
		/// Encrypts the payload and writes the ciphertext into message.
		/// </summary>
		int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> message);

		/// <summary>
		/// Decrypts the message and writes the plaintext into payload.
		/// </summary>
		int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payload);
	}
}
