using System;
using System.Collections.Generic;
using System.Text;

namespace Noise
{
	/// <summary>
	/// A HandshakeState object contains a SymmetricState plus
	/// the local and remote keys (any of which may be empty),
	/// a boolean indicating the initiator or responder role, and
	/// the remaining portion of the handshake pattern.
	/// </summary>
	internal sealed class HandshakeState<CipherType, DhType, HashType> : IDisposable
		where CipherType : Cipher, new()
		where DhType : Dh, new()
		where HashType : Hash, new()
	{
		private static readonly Dictionary<Type, string> functionNames = new Dictionary<Type, string>
		{
			{typeof(Aes256Gcm), "AESGCM"},
			{typeof(ChaCha20Poly1305), "ChaChaPoly"},
			{typeof(Curve25519), "25519"},
			{typeof(Sha256), "SHA256"},
			{typeof(Sha512), "SHA512"},
			{typeof(Blake2b), "BLAKE2b"}
		};

		private readonly SymmetricState<CipherType, DhType, HashType> state;
		private bool disposed;

		/// <summary>
		/// Initializes a new HandshakeState.
		/// </summary>
		public HandshakeState(HandshakePattern handshakePattern)
		{
			var protocolName = GetProtocolName(handshakePattern.Name);
			state = new SymmetricState<CipherType, DhType, HashType>(protocolName);
		}

		private static string GetFunctionName<T>()
		{
			return functionNames[typeof(T)];
		}

		private static byte[] GetProtocolName(string handshakePatternName)
		{
			string cipher = GetFunctionName<CipherType>();
			string dh = GetFunctionName<DhType>();
			string hash = GetFunctionName<HashType>();
			string protocolName = $"Noise_{handshakePatternName}_{dh}_{cipher}_{hash}";

			if (protocolName.Length > 255)
			{
				throw new ArgumentException("The Noise protocol name is too long.");
			}

			return Encoding.ASCII.GetBytes(protocolName);
		}

		/// <summary>
		/// Disposes the object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				state.Dispose();
				disposed = true;
			}
		}
	}
}
