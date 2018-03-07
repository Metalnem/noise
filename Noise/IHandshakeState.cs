using System;

namespace Noise
{
	/// <summary>
	/// A HandshakeState object contains a SymmetricState plus
	/// the local and remote keys (any of which may be empty),
	/// a boolean indicating the initiator or responder role, and
	/// the remaining portion of the handshake pattern.
	/// </summary>
	public interface IHandshakeState : IDisposable
	{
		/// <summary>
		/// Takes a payload byte sequence which may be zero-length,
		/// and a messageBuffer to write the output into. 
		/// </summary>
		int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer, out ITransport transport);

		/// <summary>
		/// Takes a byte sequence containing a Noise handshake message,
		/// and a payloadBuffer to write the message's plaintext payload into.
		/// </summary>
		int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer, out ITransport transport);

		/// <summary>
		/// Returns h. This function should only be called at the end of
		/// a handshake, i.e. after the Split() function has been called.
		/// </summary>
		byte[] GetHandshakeHash();
	}
}
