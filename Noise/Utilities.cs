using System;

namespace Noise
{
	/// <summary>
	/// Various utility functions.
	/// </summary>
	internal static class Utilities
	{
		/// <summary>
		/// Alignes the pointer up to the nearest alignment boundary.
		/// </summary>
		public static IntPtr Align(IntPtr ptr, int alignment)
		{
			ulong mask = (ulong)alignment - 1;
			return (IntPtr)(((ulong)ptr + mask) & ~mask);
		}
	}
}
