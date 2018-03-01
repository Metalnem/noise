using System;
using System.Collections.Generic;
using Xunit;

namespace Noise.Tests
{
	public class UtilitiesTest
	{
		private const int Alignment = 64;

		private static readonly Dictionary<IntPtr, IntPtr> tests = new Dictionary<IntPtr, IntPtr>{
			{ IntPtr.Zero, IntPtr.Zero },
			{ (IntPtr)1, (IntPtr)64 },
			{ (IntPtr)1023, (IntPtr)1024 },
			{ (IntPtr)18446744073709551551, (IntPtr)18446744073709551552 },
			{ (IntPtr)18446744073709551552, (IntPtr)18446744073709551552 }
		};

		[Fact]
		public void TestAlign()
		{
			foreach (var test in tests)
			{
				var raw = test.Key;
				var aligned = Utilities.Align(raw, Alignment);

				Assert.Equal(aligned, Utilities.Align(raw, Alignment));
				Assert.InRange((ulong)aligned, (ulong)raw, (ulong)raw + Alignment - 1);
				Assert.Equal(0UL, (ulong)aligned % Alignment);
			}
		}
	}
}
