using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using Org.BouncyCastle.Crypto.Digests;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// 
    /// </summary>
    public class BCSha256 : Sha256
    {
        Sha256Digest hash;

        public BCSha256()
        {
            hash = new Sha256Digest();
        }

        public int HashLen => 32;
        public int BlockLen => 64;

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
