using System.Collections.Generic;
using System.Diagnostics;

namespace Noise
{
	/// <summary>
	/// A message pattern is some sequence of tokens from
	/// the set ("e", "s", "ee", "es", "se", "ss", "psk").
	/// </summary>
	internal sealed class MessagePattern
	{
		public MessagePattern(params Token[] tokens)
		{
			Debug.Assert(tokens != null);
			Debug.Assert(tokens.Length > 0);

			Tokens = tokens;
		}

		/// <summary>
		/// Gets the tokens of the message pattern.
		/// </summary>
		public IEnumerable<Token> Tokens { get; }
	}
}
