using System;
using System.Collections.Generic;

namespace Noise
{
	/// <summary>
	/// A message pattern is some sequence of tokens from
	/// the set ("e", "s", "ee", "es", "se", "ss", "psk").
	/// </summary>
	internal sealed class MessagePattern
	{
		/// <summary>
		/// Initializes a new MessagePattern.
		/// </summary>
		public MessagePattern(params Token[] tokens)
		{
			if (tokens == null)
			{
				throw new ArgumentNullException(nameof(tokens));
			}

			if (tokens.Length == 0)
			{
				throw new ArgumentException("Message pattern must have at least one token.", nameof(tokens));
			}

			Tokens = tokens;
		}

		/// <summary>
		/// Gets the tokens of the message pattern.
		/// </summary>
		public IEnumerable<Token> Tokens { get; }
	}
}
