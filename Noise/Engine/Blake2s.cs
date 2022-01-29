// Based on BlakeSharp
// by Dominik Reichl <dominik.reichl@t-online.de>
// and BLAKE2 reference source code package C# implementation
// by Christian Winnerlein <codesinchaos@gmail.com>.

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PortableNoise.Engine
{
	/// <summary>
	/// BLAKE2s from <see href="https://tools.ietf.org/html/rfc7693">RFC 7693</see>
	/// with digest length 32.
	/// </summary>
	public interface Blake2s : Hash
	{
	}
}
