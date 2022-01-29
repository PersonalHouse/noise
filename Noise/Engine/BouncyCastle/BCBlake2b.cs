﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using Org.BouncyCastle.Crypto.Digests;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// 
    /// </summary>
    public class BCBlake2b : Blake2b
    {
        Blake2bDigest hash;

        public BCBlake2b()
        {
            hash = new Blake2bDigest();
        }
        public int HashLen => 64;
        public int BlockLen => 128;

        public void AppendData(ReadOnlyMemory<byte> data)
        {
            if (!MemoryMarshal.TryGetArray(data, out ArraySegment<byte> adata))
            {
                throw new InvalidOperationException("Buffer backed by array was expected");
            }
            hash.BlockUpdate(adata.Array, adata.Offset, adata.Count);
        }

        public void Dispose()
        {
        }

        public void GetHashAndReset(Memory<byte> fhash)
        {
            if (!MemoryMarshal.TryGetArray(fhash, out ArraySegment<byte> adata))
            {
                throw new InvalidOperationException("Buffer backed by array was expected");
            }
            hash.DoFinal(adata.Array, adata.Offset);
            hash.Reset();
        }
    }
}
