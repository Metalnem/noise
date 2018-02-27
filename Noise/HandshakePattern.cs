using System;
using System.Collections.Generic;

namespace Noise
{
	/// <summary>
	/// A handshake pattern consists of a pre-message pattern for
	/// the initiator, a pre-message pattern for the responder, and
	/// a sequence of message patterns for the actual handshake messages.
	/// </summary>
	internal sealed class HandshakePattern
	{
		/// <summary>
		/// Initializes a new HandshakePattern.
		/// </summary>
		public HandshakePattern(PreMessagePattern initiator, PreMessagePattern responder, params MessagePattern[] patterns)
		{
			Initiator = initiator ?? throw new ArgumentNullException(nameof(initiator));
			Responder = responder ?? throw new ArgumentNullException(nameof(responder));
			Patterns = patterns ?? throw new ArgumentNullException(nameof(patterns));
		}

		/// <summary>
		/// Gets the pre-message pattern for the initiator.
		/// </summary>
		public PreMessagePattern Initiator { get; }

		/// <summary>
		/// Gets the pre-message pattern for the responder.
		/// </summary>
		public PreMessagePattern Responder { get; }

		/// <summary>
		/// Gets the message patterns of the handshake pattern.
		/// </summary>
		public IEnumerable<MessagePattern> Patterns { get; }
	}
}
