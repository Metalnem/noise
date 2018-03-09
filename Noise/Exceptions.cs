using System;

namespace Noise
{
	internal static class Exceptions
	{
		public static void ThrowIfNull(object value, string name)
		{
			if (value == null)
			{
				throw new ArgumentNullException(name);
			}
		}

		public static void ThrowIfOutOfRange(int value, string name, int from = 0, int to = Int32.MaxValue)
		{
			if (value < from || value >= to)
			{
				throw new ArgumentOutOfRangeException(name);
			}
		}

		public static void ThrowIfDisposed(bool disposed, string name)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(name);
			}
		}
	}
}
