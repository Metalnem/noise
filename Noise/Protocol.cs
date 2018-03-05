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

			if (cipherSuite.Cipher == CipherType.AesGcm && cipherSuite.Hash == HashType.Sha256)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha256>(handshakePattern, initiator, prologue);
			}
			else if (cipherSuite.Cipher == CipherType.AesGcm && cipherSuite.Hash == HashType.Sha512)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha512>(handshakePattern, initiator, prologue);
			}
			else if (cipherSuite.Cipher == CipherType.AesGcm && cipherSuite.Hash == HashType.Blake2b)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(handshakePattern, initiator, prologue);
			}
			else if (cipherSuite.Cipher == CipherType.ChaChaPoly && cipherSuite.Hash == HashType.Sha256)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha256>(handshakePattern, initiator, prologue);
			}
			else if (cipherSuite.Cipher == CipherType.ChaChaPoly && cipherSuite.Hash == HashType.Sha512)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha512>(handshakePattern, initiator, prologue);
			}
			else if (cipherSuite.Cipher == CipherType.ChaChaPoly && cipherSuite.Hash == HashType.Blake2b)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Blake2b>(handshakePattern, initiator, prologue);
			}
			else
			{
				throw new ArgumentException("Cipher suite not supported.", nameof(cipherSuite));
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
			out IHandshakeState handshakeState)
		{
			if (protocolName == null)
			{
				throw new ArgumentNullException(nameof(protocolName));
			}

			handshakeState = null;

			if (protocolName.Length > Constants.MaxProtocolNameLength)
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

			DhType dhType;
			CipherType cipherType;
			HashType hashType;

			switch (parts[2])
			{
				case "25519": dhType = DhType.Curve25519; break;
				default: return false;
			}

			switch (parts[3])
			{
				case "AESGCM": cipherType = CipherType.AesGcm; break;
				case "ChaChaPoly": cipherType = CipherType.ChaChaPoly; break;
				default: return false;
			}

			switch (parts[4])
			{
				case "SHA256": hashType = HashType.Sha256; break;
				case "SHA512": hashType = HashType.Sha512; break;
				case "BLAKE2b": hashType = HashType.Blake2b; break;
				default: return false;
			}

			CipherSuite cipherSuite = new CipherSuite(cipherType, dhType, hashType);
			handshakeState = Create(cipherSuite, pattern, initiator, prologue);

			return true;
		}
	}
}
