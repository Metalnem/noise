using System;
using System.Collections.Generic;
using System.Linq;

namespace Noise
{
	/// <summary>
	/// A handshake pattern consists of a pre-message pattern for
	/// the initiator, a pre-message pattern for the responder, and
	/// a sequence of message patterns for the actual handshake messages.
	/// </summary>
	public sealed class HandshakePattern
	{
		/// <summary>
		/// NN():
		///   → e
		///   ← e, ee
		/// </summary>
		public static readonly HandshakePattern NN = new HandshakePattern(
			nameof(NN),
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE)
		);

		/// <summary>
		/// NK():
		///   ← s
		///   ...
		///   → e, es
		///   ← e, ee
		/// </summary>
		public static readonly HandshakePattern NK = new HandshakePattern(
			nameof(NK),
			PreMessagePattern.Empty,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES),
			new MessagePattern(Token.E, Token.EE)
		);

		/// <summary>
		/// NX():
		///   → e
		///   ← e, ee, s, es
		/// </summary>
		public static readonly HandshakePattern NX = new HandshakePattern(
			nameof(NX),
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE, Token.S, Token.ES)
		);

		/// <summary>
		/// XN():
		///   → e
		///   ← e, ee
		///   → s, se
		/// </summary>
		public static readonly HandshakePattern XN = new HandshakePattern(
			nameof(XN),
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE),
			new MessagePattern(Token.S, Token.SE)
		);

		/// <summary>
		/// XK():
		///   ← s
		///   ...
		///   → e, es
		///   ← e, ee
		///   → s, se
		/// </summary>
		public static readonly HandshakePattern XK = new HandshakePattern(
			nameof(XK),
			PreMessagePattern.Empty,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES),
			new MessagePattern(Token.E, Token.EE),
			new MessagePattern(Token.S, Token.SE)
		);

		/// <summary>
		/// XX():
		///   → e
		///   ← e, ee, s, es
		///   → s, se
		/// </summary>
		public static readonly HandshakePattern XX = new HandshakePattern(
			nameof(XX),
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE, Token.S, Token.ES),
			new MessagePattern(Token.S, Token.SE)
		);

		/// <summary>
		/// KN():
		///   → s
		///   ...
		///   → e
		///   ← e, ee, se
		/// </summary>
		public static readonly HandshakePattern KN = new HandshakePattern(
			nameof(KN),
			PreMessagePattern.S,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE, Token.SE)
		);

		/// <summary>
		/// KK():
		///   → s
		///   ← s
		///   ...
		///   → e, es, ss
		///   ← e, ee, se
		/// </summary>
		public static readonly HandshakePattern KK = new HandshakePattern(
			nameof(KK),
			PreMessagePattern.S,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES, Token.SS),
			new MessagePattern(Token.E, Token.EE, Token.SE)
		);

		/// <summary>
		/// KX():
		///   → s
		///   ...
		///   → e
		///   ← e, ee, se, s, es
		/// </summary>
		public static readonly HandshakePattern KX = new HandshakePattern(
			nameof(KX),
			PreMessagePattern.S,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE, Token.SE, Token.S, Token.ES)
		);

		/// <summary>
		/// IN():
		///   → e, s
		///   ← e, ee, se
		/// </summary>
		public static readonly HandshakePattern IN = new HandshakePattern(
			nameof(IN),
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E, Token.S),
			new MessagePattern(Token.E, Token.EE, Token.SE)
		);

		/// <summary>
		/// IK():
		///   ← s
		///   ...
		///   → e, es, s, ss
		///   ← e, ee, se
		/// </summary>
		public static readonly HandshakePattern IK = new HandshakePattern(
			nameof(IK),
			PreMessagePattern.Empty,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES, Token.S, Token.SS),
			new MessagePattern(Token.E, Token.EE, Token.SE)
		);

		/// <summary>
		/// IX():
		///   → e, s
		///   ← e, ee, se, s, es
		/// </summary>
		public static readonly HandshakePattern IX = new HandshakePattern(
			nameof(IX),
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E, Token.S),
			new MessagePattern(Token.E, Token.EE, Token.SE, Token.S, Token.ES)
		);

		private static readonly Dictionary<string, HandshakePattern> patterns = typeof(HandshakePattern).GetFields()
			.Where(field => field.IsPublic && field.IsStatic && field.FieldType == typeof(HandshakePattern))
			.ToDictionary(field => field.Name, field => (HandshakePattern)field.GetValue(null));

		internal HandshakePattern(string name, PreMessagePattern initiator, PreMessagePattern responder, params MessagePattern[] patterns)
		{
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name of the handshake pattern must not be empty.", nameof(name));
			}

			Name = name;
			Initiator = initiator ?? throw new ArgumentNullException(nameof(initiator));
			Responder = responder ?? throw new ArgumentNullException(nameof(responder));
			Patterns = patterns ?? throw new ArgumentNullException(nameof(patterns));
		}

		/// <summary>
		/// Gets the name of the handshake pattern.
		/// </summary>
		internal string Name { get; }

		/// <summary>
		/// Gets the pre-message pattern for the initiator.
		/// </summary>
		internal PreMessagePattern Initiator { get; }

		/// <summary>
		/// Gets the pre-message pattern for the responder.
		/// </summary>
		internal PreMessagePattern Responder { get; }

		/// <summary>
		/// Gets the message patterns of the handshake pattern.
		/// </summary>
		internal IEnumerable<MessagePattern> Patterns { get; }

		/// <summary>
		/// Gets the pattern with the given name.
		/// </summary>
		public static bool TryGetValue(string key, out HandshakePattern value)
		{
			return patterns.TryGetValue(key, out value);
		}
	}
}
