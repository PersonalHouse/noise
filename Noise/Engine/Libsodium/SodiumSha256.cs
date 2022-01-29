using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PortableNoise.Engine.Libsodium
{
    /// <summary>
    /// SHA-256 from <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4</see>.
    /// </summary>
    public sealed class SodiumSha256 : Sha256
    {
        // typedef struct crypto_hash_sha256_state {
        //     uint32_t state[8];
        //     uint64_t count;
        //     uint8_t  buf[64];
        // } crypto_hash_sha256_state;

        private readonly IntPtr state = Marshal.AllocHGlobal(104);
		private bool disposed;

		public SodiumSha256() => Reset();

		public int HashLen => 32;
		public int BlockLen => 64;

		public void AppendData(ReadOnlyMemory<byte> data)
		{
			if (!data.IsEmpty)
			{
				Libsodium.crypto_hash_sha256_update(
					state,
					ref MemoryMarshal.GetReference(data.Span),
					(ulong)data.Length
				);
			}
		}

		public void GetHashAndReset(Memory<byte> hash)
		{
			Debug.Assert(hash.Length == HashLen);

			Libsodium.crypto_hash_sha256_final(
				state,
				ref MemoryMarshal.GetReference(hash.Span)
			);

			Reset();
		}

		private void Reset()
		{
			Libsodium.crypto_hash_sha256_init(state);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				Marshal.FreeHGlobal(state);
				disposed = true;
			}
		}
	}
}
