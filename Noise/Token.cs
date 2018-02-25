namespace Noise
{
	/// <summary>
	/// Tokens are arranged into message patterns.
	/// </summary>
	internal enum Token
	{
		/// <summary>
		/// The sender generates a new ephemeral key pair and stores
		/// it in the e variable, writes the ephemeral public key as
		/// cleartext into the message buffer, and hashes the public
		/// key along with the old h to derive a new h.
		/// </summary>
		E,

		/// <summary>
		/// The sender writes its static public key from the s variable
		/// into the message buffer, encrypting it if k is non-empty,
		/// and hashes the output along with the old h to derive a new h.
		/// </summary>
		S,

		/// <summary>
		/// A DH is performed between the initiator's key pair (whether
		/// static or ephemeral is determined by the first letter) and
		/// the responder's key pair (whether static or ephemeral is
		/// determined by the second letter). The result is hashed along
		/// with the old ck to derive a new ck and k, and n is set to zero.
		/// </summary>
		EE,
		SE,
		ES,
		SS
	}
}
