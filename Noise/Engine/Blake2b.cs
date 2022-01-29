using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PortableNoise.Engine
{
    /// <summary>
    /// BLAKE2b from <see href="https://tools.ietf.org/html/rfc7693">RFC 7693</see>
    /// with digest length 64.
    /// </summary>
    public interface Blake2b : Hash
	{
	}
}
