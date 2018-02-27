using System;
using System.Collections;
using System.Collections.Generic;

namespace Noise
{
	/// <summary>
	/// A message pattern is some sequence of tokens from
	/// the set ("e", "s", "ee", "es", "se", "ss", "psk").
	/// </summary>
	internal sealed class MessagePattern : IEnumerable<Token>
	{
		private readonly Token[] tokens;

		/// <summary>
		/// Initializes a new MessagePattern.
		/// </summary>
		public MessagePattern(params Token[] tokens)
		{
			this.tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
		}

		/// <summary>
		/// Returns an enumerator that iterates through the tokens of the message pattern.
		/// </summary>
		public IEnumerator<Token> GetEnumerator() => ((IEnumerable<Token>)tokens).GetEnumerator();

		/// <summary>
		/// Returns an enumerator that iterates through the tokens of the message pattern.
		/// </summary>
		IEnumerator IEnumerable.GetEnumerator() => tokens.GetEnumerator();
	}
}
