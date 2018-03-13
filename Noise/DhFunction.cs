using System;

namespace Noise
{
	/// <summary>
	/// Constants representing the available DH functions.
	/// </summary>
	public sealed class DhFunction
	{
		/// <summary>
		/// The Curve25519 DH function (aka "X25519" in
		/// <see href="https://tools.ietf.org/html/rfc7748">RFC 7748</see>).
		/// </summary>
		public static readonly DhFunction Curve25519 = new DhFunction("25519");

		private readonly string name;

		private DhFunction(string name) => this.name = name;
		public override string ToString() => name;

		internal static DhFunction Parse(ReadOnlySpan<char> dh)
		{
			if (dh.SequenceEqual(Curve25519.name.AsReadOnlySpan()))
			{
				return Curve25519;
			}
			else
			{
				throw new ArgumentException("Unknown DH function.", nameof(dh));
			}
		}
	}
}
