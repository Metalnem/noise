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
		Span<byte> WriteMessage(Span<byte> payload, Span<byte> message);

		/// <summary>
		/// Decrypts the message and writes the plaintext into payload.
		/// </summary>
		Span<byte> ReadMessage(Span<byte> message, Span<byte> payload);
	}
}
