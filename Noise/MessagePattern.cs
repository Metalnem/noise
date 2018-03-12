using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

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

		public MessagePattern(IEnumerable<Token> tokens)
		{
			Debug.Assert(tokens != null);
			Debug.Assert(tokens.Any());

			Tokens = tokens;
		}

		/// <summary>
		/// Gets the tokens of the message pattern.
		/// </summary>
		public IEnumerable<Token> Tokens { get; }

		/// <summary>
		/// Prepends the PSK token to the pattern.
		/// </summary>
		public MessagePattern PrependPsk()
		{
			return new MessagePattern(Enumerable.Prepend(Tokens, Token.PSK));
		}

		/// <summary>
		/// Appends the PSK token to the pattern.
		/// </summary>
		public MessagePattern AppendPsk()
		{
			return new MessagePattern(Enumerable.Append(Tokens, Token.PSK));
		}
	}
}
