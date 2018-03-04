using System;

namespace Noise
{
	/// <summary>
	/// A set of functions for instantiating a Noise protocol.
	/// </summary>
	public static class Protocol
	{
		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		public static IHandshakeState Create(
			CipherSuite cipherSuite,
			HandshakePattern handshakePattern,
			bool initiator,
			byte[] prologue)
		{
			return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(handshakePattern, initiator, prologue);
		}

		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		internal static IHandshakeState Create(
			CipherSuite cipherSuite,
			HandshakePattern handshakePattern,
			bool initiator,
			byte[] prologue,
			Dh dh)
		{
			return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(handshakePattern, initiator, prologue, dh);
		}

		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		internal static bool Create(
			string protocolName,
			bool initiator,
			byte[] prologue,
			Dh dh,
			out IHandshakeState handshakeState)
		{
			if (protocolName == "Noise_NN_25519_AESGCM_BLAKE2b")
			{
				handshakeState = new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(HandshakePattern.NN, initiator, prologue, dh);
				return true;
			}
			else
			{
				handshakeState = null;
				return false;
			}
		}
	}
}
