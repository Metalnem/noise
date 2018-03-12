using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Noise
{
	/// <summary>
	/// A set of functions for instantiating a Noise protocol.
	/// </summary>
	public sealed class Protocol
	{
		/// <summary>
		/// Maximum size of Noise messages in bytes.
		/// </summary>
		public const int MaxMessageLength = 65535;

		/// <summary>
		/// Maximum size of the protocol name in bytes.
		/// </summary>
		internal const int MaxProtocolNameLength = 255;

		public Protocol(
			HandshakePattern handshakePattern,
			CipherFunction cipher = CipherFunction.ChaChaPoly,
			DhFunction dh = DhFunction.Curve25519,
			HashFunction hash = HashFunction.Sha256,
			PatternModifiers modifiers = PatternModifiers.None)
		{
			Exceptions.ThrowIfNull(handshakePattern, nameof(handshakePattern));
			Exceptions.ThrowIfNotDefined(typeof(CipherFunction), cipher, nameof(cipher));
			Exceptions.ThrowIfNotDefined(typeof(DhFunction), dh, nameof(dh));
			Exceptions.ThrowIfNotDefined(typeof(HashFunction), hash, nameof(hash));

			HandshakePattern = handshakePattern;
			Cipher = cipher;
			Dh = dh;
			Hash = hash;
			Modifiers = modifiers;

			Name = GetName();
		}

		internal HandshakePattern HandshakePattern { get; }
		internal CipherFunction Cipher { get; }
		internal DhFunction Dh { get; }
		internal HashFunction Hash { get; }
		internal PatternModifiers Modifiers { get; }
		internal byte[] Name { get; }

		/// <summary>
		/// Instantiates a Noise protocol with a concrete set of
		/// cipher functions, DH functions, and hash functions.
		/// </summary>
		public HandshakeState Create(
			bool initiator,
			ReadOnlySpan<byte> prologue = default,
			KeyPair s = default,
			ReadOnlySpan<byte> rs = default,
			IEnumerable<byte[]> psks = default)
		{
			if (Cipher == CipherFunction.AesGcm && Hash == HashFunction.Sha256)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha256>(this, initiator, prologue, s, rs, psks);
			}
			else if (Cipher == CipherFunction.AesGcm && Hash == HashFunction.Sha512)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Sha512>(this, initiator, prologue, s, rs, psks);
			}
			else if (Cipher == CipherFunction.AesGcm && Hash == HashFunction.Blake2b)
			{
				return new HandshakeState<Aes256Gcm, Curve25519, Blake2b>(this, initiator, prologue, s, rs, psks);
			}
			else if (Cipher == CipherFunction.ChaChaPoly && Hash == HashFunction.Sha256)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha256>(this, initiator, prologue, s, rs, psks);
			}
			else if (Cipher == CipherFunction.ChaChaPoly && Hash == HashFunction.Sha512)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Sha512>(this, initiator, prologue, s, rs, psks);
			}
			else if (Cipher == CipherFunction.ChaChaPoly && Hash == HashFunction.Blake2b)
			{
				return new HandshakeState<ChaCha20Poly1305, Curve25519, Blake2b>(this, initiator, prologue, s, rs, psks);
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

			var protocol = new Protocol(pattern, cipher, dh, hash, modifiers);
			handshakeState = protocol.Create(initiator, prologue, s, rs, psks);

			return true;
		}

		private byte[] GetName()
		{
			var protocolName = new StringBuilder("Noise");

			protocolName.Append('_');
			protocolName.Append(HandshakePattern.Name);

			if (Modifiers != PatternModifiers.None)
			{
				var separator = String.Empty;

				foreach (PatternModifiers modifier in Enum.GetValues(typeof(PatternModifiers)))
				{
					if ((Modifiers & modifier) != PatternModifiers.None)
					{
						protocolName.Append(separator);
						protocolName.Append(modifier.ToString().ToLowerInvariant());
						separator = "+";
					}
				}
			}

			protocolName.Append('_');

			switch (Dh)
			{
				case DhFunction.Curve25519: protocolName.Append("25519"); break;
			}

			protocolName.Append('_');

			switch (Cipher)
			{
				case CipherFunction.AesGcm: protocolName.Append("AESGCM"); break;
				case CipherFunction.ChaChaPoly: protocolName.Append("ChaChaPoly"); break;
			}

			protocolName.Append('_');

			switch (Hash)
			{
				case HashFunction.Sha256: protocolName.Append("SHA256"); break;
				case HashFunction.Sha512: protocolName.Append("SHA512"); break;
				case HashFunction.Blake2b: protocolName.Append("BLAKE2b"); break;
			}

			Debug.Assert(protocolName.Length <= Protocol.MaxProtocolNameLength);

			return Encoding.ASCII.GetBytes(protocolName.ToString());
		}
	}
}
