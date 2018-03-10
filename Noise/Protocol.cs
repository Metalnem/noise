using System;

namespace Noise
{
	/// <summary>
	/// A set of functions for instantiating a Noise protocol.
	/// </summary>
	public static class Protocol
	{
		/// <summary>
		/// Maximum size of Noise messages in bytes.
		/// </summary>
		public const int MaxMessageLength = 65535;

		/// <summary>
		/// Maximum size of the protocol name in bytes.
		/// </summary>
		internal const int MaxProtocolNameLength = 255;

		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		public static HandshakeState Create(
			CipherFunction cipher,
			DhFunction dh,
			HashFunction hash,
			HandshakePattern handshakePattern,
			bool initiator,
			byte[] prologue,
			KeyPair s,
			byte[] rs)
		{

			if (cipher == CipherFunction.AesGcm && hash == HashFunction.Sha256)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha256>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipher == CipherFunction.AesGcm && hash == HashFunction.Sha512)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha512>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipher == CipherFunction.AesGcm && hash == HashFunction.Blake2b)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipher == CipherFunction.ChaChaPoly && hash == HashFunction.Sha256)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha256>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipher == CipherFunction.ChaChaPoly && hash == HashFunction.Sha512)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha512>(handshakePattern, initiator, prologue, s, rs);
			}
			else if (cipher == CipherFunction.ChaChaPoly && hash == HashFunction.Blake2b)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Blake2b>(handshakePattern, initiator, prologue, s, rs);
			}
			else
			{
				throw new ArgumentException("Cipher suite not supported.");
			}
		}

		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		internal static bool Create(
			string protocolName,
			bool initiator,
			byte[] prologue,
			KeyPair s,
			byte[] rs,
			out HandshakeState handshakeState)
		{
			if (protocolName == null)
			{
				throw new ArgumentNullException(nameof(protocolName));
			}

			handshakeState = null;

			if (protocolName.Length > MaxProtocolNameLength)
			{
				return false;
			}

			string[] parts = protocolName.Split('_');

			if (parts.Length != 5 || parts[0] != "Noise")
			{
				return false;
			}

			if (!HandshakePattern.TryGetValue(parts[1], out var pattern))
			{
				return false;
			}

			DhFunction dh;
			CipherFunction cipher;
			HashFunction hash;

			switch (parts[2])
			{
				case "25519": dh = DhFunction.Curve25519; break;
				default: return false;
			}

			switch (parts[3])
			{
				case "AESGCM": cipher = CipherFunction.AesGcm; break;
				case "ChaChaPoly": cipher = CipherFunction.ChaChaPoly; break;
				default: return false;
			}

			switch (parts[4])
			{
				case "SHA256": hash = HashFunction.Sha256; break;
				case "SHA512": hash = HashFunction.Sha512; break;
				case "BLAKE2b": hash = HashFunction.Blake2b; break;
				default: return false;
			}

			handshakeState = Create(cipher, dh, hash, pattern, initiator, prologue, s, rs);
			return true;
		}
	}
}
