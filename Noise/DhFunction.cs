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

		private DhFunction(string name)
		{
			Name = name;
		}

		internal string Name { get; }
	}
}
