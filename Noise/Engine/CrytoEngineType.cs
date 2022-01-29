using System;
using System.Collections.Generic;
using System.Text;

namespace PortableNoise.Engine
{
    /// <summary>
    /// 
    /// </summary>
    public enum CrytoEngineType
    {
        /// <summary>
        /// Use best performance lib. Suggested value
        /// </summary>
        Auto=1,

        /// <summary>
        /// use Libsodium only
        /// </summary>
        Libsodium = 2,

        /// <summary>
        /// use BouncyCastle only
        /// </summary>
        BouncyCastle = 3
    }
}
