using System;
using System.Collections.Generic;

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
			HandshakePattern handshakePattern,
			bool initiator,
			CipherFunction cipher = CipherFunction.ChaChaPoly,
			DhFunction dh = DhFunction.Curve25519,
			HashFunction hash = HashFunction.Sha256,
			PatternModifiers modifiers = PatternModifiers.None,
			ReadOnlySpan<byte> prologue = default,
			KeyPair s = default,
			ReadOnlySpan<byte> rs = default,
			IEnumerable<byte[]> psks = default)
		{
			if (cipher == CipherFunction.AesGcm && hash == HashFunction.Sha256)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha256>(handshakePattern, initiator, modifiers, prologue, s, rs, psks);
			}
			else if (cipher == CipherFunction.AesGcm && hash == HashFunction.Sha512)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha512>(handshakePattern, initiator, modifiers, prologue, s, rs, psks);
			}
			else if (cipher == CipherFunction.AesGcm && hash == HashFunction.Blake2b)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(handshakePattern, initiator, modifiers, prologue, s, rs, psks);
			}
			else if (cipher == CipherFunction.ChaChaPoly && hash == HashFunction.Sha256)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha256>(handshakePattern, initiator, modifiers, prologue, s, rs, psks);
			}
			else if (cipher == CipherFunction.ChaChaPoly && hash == HashFunction.Sha512)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha512>(handshakePattern, initiator, modifiers, prologue, s, rs, psks);
			}
			else if (cipher == CipherFunction.ChaChaPoly && hash == HashFunction.Blake2b)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Blake2b>(handshakePattern, initiator, modifiers, prologue, s, rs, psks);
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
			out HandshakeState handshakeState,
			ReadOnlySpan<byte> prologue = default,
			KeyPair s = default,
			ReadOnlySpan<byte> rs = default,
			IEnumerable<byte[]> psks = default)
		{
			Exceptions.ThrowIfNull(protocolName, nameof(protocolName));

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

			PatternModifiers modifiers = PatternModifiers.None;
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

			handshakeState = Create(pattern, initiator, cipher, dh, hash, modifiers, prologue, s, rs, psks);
			return true;
		}
	}
}
