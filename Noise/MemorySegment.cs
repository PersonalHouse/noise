using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace PortableNoise
{
    public class MemorySegment<T> : ReadOnlySequenceSegment<T>
    {
        public MemorySegment(ReadOnlyMemory<T> memory)
        {
            Memory = memory;
        }

        public MemorySegment(T[] memory, int offset, int lenght)
        {
            Memory = memory.AsMemory(offset, lenght);
        }

        public void Set(ReadOnlyMemory<T> memory)
        {
            RunningIndex = 0;
            Memory = memory;

            if (Next==null)
            {
                return;
            }else
            {
                var ms = Next as MemorySegment<T>;
                if (ms == null)
                {
                    throw new InvalidOperationException("MemorySegment<T>.Next is not MemorySegment<T>");
                }
                ms.RunningIndex = RunningIndex + Memory.Length;
            }
        }


        public MemorySegment<T> Append(ReadOnlyMemory<T> memory)
        {
            var segment = new MemorySegment<T>(memory) {
                RunningIndex = RunningIndex + Memory.Length
            };

            Next = segment;

            return segment;
        }

        public MemorySegment<T> Append(MemorySegment<T> n)
        {
            n.RunningIndex = RunningIndex + Memory.Length;
            Next = n;
            return n;
        }
    }
}
