using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Noise
{
	/// <summary>
	/// A <see href="https://noiseprotocol.org/noise.html#handshake-patterns">handshake pattern</see>
	/// consists of a pre-message pattern for the initiator, a pre-message pattern for the responder,
	/// and a sequence of message patterns for the actual handshake messages.
	/// </summary>
	public sealed class HandshakePattern
	{
		/// <summary>
		/// N():
		///   ← s
		///   ...
		///   → e, es
		/// </summary>
		public static readonly HandshakePattern N = new HandshakePattern(
			nameof(N),
			PreMessagePattern.Empty,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES)
		);

		/// <summary>
		/// K():
		///   → s
		///   ← s
		///   ...
		///   → e, es, ss
		/// </summary>
		public static readonly HandshakePattern K = new HandshakePattern(
			nameof(K),
			PreMessagePattern.S,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES, Token.SS)
		);

		/// <summary>
		/// X():
		///   ← s
		///   ...
		///   → e, es, s, ss
		/// </summary>
		public static readonly HandshakePattern X = new HandshakePattern(
			nameof(X),
			PreMessagePattern.Empty,
			PreMessagePattern.S,
			new MessagePattern(Token.E, Token.ES, Token.S, Token.SS)
		);

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

		internal HandshakePattern(string name, PreMessagePattern initiator, PreMessagePattern responder, params MessagePattern[] patterns)
		{
			Debug.Assert(!String.IsNullOrEmpty(name));
			Debug.Assert(initiator != null);
			Debug.Assert(responder != null);
			Debug.Assert(patterns != null);
			Debug.Assert(patterns.Length > 0);

			Name = name;
			Initiator = initiator;
			Responder = responder;
			Patterns = patterns;
		}

		internal string Name { get; }
		internal PreMessagePattern Initiator { get; }
		internal PreMessagePattern Responder { get; }
		internal IEnumerable<MessagePattern> Patterns { get; }

		internal bool LocalStaticRequired(bool initiator)
		{
			var preMessage = initiator ? Initiator : Responder;

			if (preMessage.Tokens.Contains(Token.S))
			{
				return true;
			}

			bool turnToWrite = initiator;

			foreach (var pattern in Patterns)
			{
				if (turnToWrite && pattern.Tokens.Contains(Token.S))
				{
					return true;
				}

				turnToWrite = !turnToWrite;
			}

			return false;
		}

		internal bool RemoteStaticRequired(bool initiator)
		{
			var preMessage = initiator ? Responder : Initiator;
			return preMessage.Tokens.Contains(Token.S);
		}
	}
}
