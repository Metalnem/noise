using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
		/// Minimum size of the protocol name in bytes.
		/// </summary>
		private static readonly int MinProtocolNameLength = "Noise_N_448_AESGCM_SHA256".Length;

		/// <summary>
		/// Maximum size of the protocol name in bytes.
		/// </summary>
		private const int MaxProtocolNameLength = 255;

		private static readonly Dictionary<string, HandshakePattern> patterns = typeof(HandshakePattern).GetFields()
			.Where(field => field.IsPublic && field.IsStatic && field.FieldType == typeof(HandshakePattern))
			.ToDictionary(field => field.Name, field => (HandshakePattern)field.GetValue(null));

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

		public static Protocol Parse(ReadOnlySpan<char> s)
		{
			if (s.Length < MinProtocolNameLength || s.Length > MaxProtocolNameLength)
			{
				throw new ArgumentException("Invalid Noise protocol name.", nameof(s));
			}

			var splitter = new StringSplitter(s, '_');
			var noise = splitter.Next();

			if (!noise.SequenceEqual("Noise".AsReadOnlySpan()))
			{
				throw new ArgumentException("Invalid Noise protocol name.", nameof(s));
			}

			var next = splitter.Next();
			var pattern = next.Length > 1 && Char.IsUpper(next[1]) ? next.Slice(0, 2) : next.Slice(0, 1);

			var handshakePattern = ParseHandshakePattern(pattern);
			var modifiers = ParseModifiers(next.Slice(pattern.Length));

			var dh = DhFunction.Parse(splitter.Next());
			var cipher = CipherFunction.Parse(splitter.Next());
			var hash = HashFunction.Parse(splitter.Next());

			if (!splitter.Next().IsEmpty)
			{
				throw new ArgumentException("Invalid Noise protocol name.", nameof(s));
			}

			return new Protocol(handshakePattern, cipher, dh, hash, modifiers);
		}

		private static HandshakePattern ParseHandshakePattern(ReadOnlySpan<char> s)
		{
			foreach (var pattern in patterns)
			{
				if (pattern.Key.AsReadOnlySpan().SequenceEqual(s))
				{
					return pattern.Value;
				}
			}

			throw new ArgumentException("Invalid Noise handshake pattern name.", nameof(s));
		}

		private static PatternModifiers ParseModifiers(ReadOnlySpan<char> s)
		{
			var splitter = new StringSplitter(s, '+');
			var modifiers = PatternModifiers.None;

			for (var next = splitter.Next(); !next.IsEmpty; next = splitter.Next())
			{
				var modifier = ParseModifier(next);

				if (modifier <= modifiers)
				{
					throw new ArgumentException("PSK pattern modifiers are required to be sorted alphabetically.");
				}

				modifiers |= modifier;
			}

			return modifiers;
		}

		private static PatternModifiers ParseModifier(ReadOnlySpan<char> s)
		{
			switch (s)
			{
				case var _ when s.SequenceEqual("psk0".AsReadOnlySpan()): return PatternModifiers.Psk0;
				case var _ when s.SequenceEqual("psk1".AsReadOnlySpan()): return PatternModifiers.Psk1;
				case var _ when s.SequenceEqual("psk2".AsReadOnlySpan()): return PatternModifiers.Psk2;
				case var _ when s.SequenceEqual("psk3".AsReadOnlySpan()): return PatternModifiers.Psk3;
				default: throw new ArgumentException("Unknown pattern modifier.", nameof(s));
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

			Debug.Assert(protocolName.Length <= MaxProtocolNameLength);

			return Encoding.ASCII.GetBytes(protocolName.ToString());
		}

		private ref struct StringSplitter
		{
			private ReadOnlySpan<char> s;
			private char separator;

			public StringSplitter(ReadOnlySpan<char> s, char separator)
			{
				this.s = s;
				this.separator = separator;
			}

			public ReadOnlySpan<char> Next()
			{
				int index = s.IndexOf(separator);

				if (index > 0)
				{
					var next = s.Slice(0, index);
					s = s.Slice(index + 1);

					return next;
				}
				else
				{
					var next = s;
					s = ReadOnlySpan<char>.Empty;

					return next;
				}
			}
		}
	}
}
