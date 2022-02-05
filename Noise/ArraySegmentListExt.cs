using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PortableNoise
{
    public static class ArraySegmentListExt
    {

        public static int Total(this IList<ArraySegment<byte>> lis)
        {
            int n = 0;
            for (int i = 0; i < lis.Count; i++)
            {
                n += lis[i].Count;
            }
            return n;
        }
        public static Span<byte> MergeToSpan(this IList<ArraySegment<byte>> lis)
        {
            if (lis.Count==1)
            {
                return lis[0].AsSpan();
            }
            
            byte[] buf = new byte[lis.Total()];
            int copied = 0;

            foreach (var seg in lis)
            {
                Buffer.BlockCopy(seg.Array, seg.Offset, buf, copied, seg.Count);
                copied += seg.Count;
            }

            return buf;
        }
        public static byte[] SliceToArray(this IList<ArraySegment<byte>> lis, int off, int length)
        {
            byte[] buf = new byte[length];

            int offset = off;
            int copied = 0;
            foreach (var seg in lis)
            {
                if (offset >= seg.Count)
                {
                    offset -= seg.Count;
                    continue;
                }
                int tocopy = Math.Min(length - copied, seg.Count-offset);
                Buffer.BlockCopy(seg.Array, seg.Offset+ offset, buf, copied, tocopy);
                copied += tocopy;
                offset = 0;
            }
            if (copied == 0)
            {
                throw new InvalidOperationException("Invalid parameter ");
            }
            return buf;
        }

        public static IList<ArraySegment<byte>> Slice(this IList<ArraySegment<byte>> lis, int off)
        {
            int offset = off;
            for (int i = 0; i < lis.Count; )
            {
                var ci = lis[i];
                if (offset >= ci.Count)
                {
                    offset -= ci.Count;
                    lis[i] = ci.Slice(ci.Count);
                    continue;
                }

                lis[i] = ci.Slice(offset);
                return lis;
            }
            return lis;
        }

        public static ArraySegment<T> AsArraySegment<T>(this T[] arr, int off, int count)
        {
            return new ArraySegment<T>(arr, off,count);
        }
        public static ArraySegment<T> AsArraySegment<T>(this T[] arr)
        {
            return new ArraySegment<T>(arr);
        }


        //         public static Span<T> AsSpan<T>(this ArraySegment<T> seg)
        //         {
        //             return seg.Array.AsSpan(seg.Offset,seg.Count);
        //         }

    }
}
