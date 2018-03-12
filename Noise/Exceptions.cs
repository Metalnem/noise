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

		public static void ThrowIfDisposed(bool disposed, string name)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(name);
			}
		}

		public static void ThrowIfNotDefined(Type enumType, object value, string name)
		{
			if (!Enum.IsDefined(enumType, value))
			{
				throw new ArgumentException($"Value {value} is not part of the {enumType.Name} enum.", name);
			}
		}
	}
}
