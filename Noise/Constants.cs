namespace Noise
{
	/// <summary>
	/// Noise protocol constants.
	/// </summary>
	internal static class Constants
	{
		/// <summary>
		/// Secret key size in bytes.
		/// </summary>
		public const int KeySize = 32;

		/// <summary>
		/// Nonce size in bytes.
		/// </summary>
		public const int NonceSize = 12;

		/// <summary>
		/// Authentication tag size in bytes.
		/// </summary>
		public const int TagSize = 16;

		/// <summary>
		/// Maximum size of the protocol name in bytes.
		/// </summary>
		public const int MaxProtocolNameLength = 255;
	}
}
