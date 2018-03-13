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

		public Protocol(HandshakePattern handshakePattern, PatternModifiers modifiers = PatternModifiers.None)
			: this(handshakePattern, CipherFunction.ChaChaPoly, DhFunction.Curve25519, HashFunction.Sha256, modifiers)
		{
		}

		public Protocol(
			HandshakePattern handshakePattern,
			CipherFunction cipher,
			DhFunction dh,
			HashFunction hash,
			PatternModifiers modifiers = PatternModifiers.None)
		{
			Exceptions.ThrowIfNull(handshakePattern, nameof(handshakePattern));
			Exceptions.ThrowIfNull(cipher, nameof(cipher));
			Exceptions.ThrowIfNull(dh, nameof(dh));
			Exceptions.ThrowIfNull(hash, nameof(hash));

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
			byte[] prologue = default,
			KeyPair s = default,
			byte[] rs = default,
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
			byte[] prologue = default,
			KeyPair s = default,
			byte[] rs = default,
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

			try
			{
				DhFunction dh = DhFunction.Parse(parts[2].AsReadOnlySpan());
				CipherFunction cipher = CipherFunction.Parse(parts[3].AsReadOnlySpan());
				HashFunction hash = HashFunction.Parse(parts[4].AsReadOnlySpan());
				PatternModifiers modifiers = PatternModifiers.None;

				var protocol = new Protocol(pattern, cipher, dh, hash, modifiers);
				handshakeState = protocol.Create(initiator, prologue, s, rs, psks);

				return true;
			}
			catch
			{
				return false;
			}
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
			protocolName.Append(Dh);

			protocolName.Append('_');
			protocolName.Append(Cipher);

			protocolName.Append('_');
			protocolName.Append(Hash);

			Debug.Assert(protocolName.Length <= Protocol.MaxProtocolNameLength);

			return Encoding.ASCII.GetBytes(protocolName.ToString());
		}
	}
}
