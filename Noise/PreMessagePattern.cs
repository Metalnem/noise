using System.Collections;
using System.Collections.Generic;

namespace Noise
{
	/// <summary>
	/// A pre-message pattern is one of the following
	/// sequences of tokens: "e", "s", "e, s", or empty.
	/// </summary>
	internal sealed class PreMessagePattern : IEnumerable<Token>
	{
		/// <summary>
		/// The "e" pre-message pattern.
		/// </summary>
		public static readonly PreMessagePattern E = new PreMessagePattern(Token.E);

		/// <summary>
		/// The "s" pre-message pattern.
		/// </summary>
		public static readonly PreMessagePattern S = new PreMessagePattern(Token.S);

		/// <summary>
		/// The "e, s" pre-message pattern.
		/// </summary>
		public static readonly PreMessagePattern ES = new PreMessagePattern(Token.E, Token.S);

		/// <summary>
		/// The empty pre-message pattern.
		/// </summary>
		public static readonly PreMessagePattern Empty = new PreMessagePattern();

		private readonly Token[] tokens;

		/// <summary>
		/// Initializes a new PreMessagePattern.
		/// </summary>
		private PreMessagePattern(params Token[] tokens)
		{
			this.tokens = tokens;
		}

		/// <summary>
		/// Returns an enumerator that iterates through the tokens of the pre-message pattern.
		/// </summary>
		public IEnumerator<Token> GetEnumerator() => ((IEnumerable<Token>)tokens).GetEnumerator();

		/// <summary>
		/// Returns an enumerator that iterates through the tokens of the pre-message pattern.
		/// </summary>
		IEnumerator IEnumerable.GetEnumerator() => tokens.GetEnumerator();
	}
}
