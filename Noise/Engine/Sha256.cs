using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PortableNoise.Engine
{
	/// <summary>
	/// SHA-256 from <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4</see>.
	/// </summary>
	public interface Sha256 : Hash
	{
	}
}
