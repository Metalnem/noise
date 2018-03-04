using System;
using System.Collections.Generic;

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
			"NN",
			PreMessagePattern.Empty,
			PreMessagePattern.Empty,
			new MessagePattern(Token.E),
			new MessagePattern(Token.E, Token.EE)
		);

		/// <summary>
		/// Initializes a new HandshakePattern.
		/// </summary>
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
	}
}
