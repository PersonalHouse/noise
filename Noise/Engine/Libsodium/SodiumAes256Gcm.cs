using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using PortableNoise.Engine;
using PortableNoise.Engine.Libsodium;

namespace PortableNoise.Engine.Libsodium
{
    /// <summary>
    /// AES256 with GCM from NIST Special Publication
    /// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>
    /// with a 128-bit tag appended to the ciphertext.
    /// The 96-bit nonce is formed by encoding 32 bits
    /// of zeros followed by big-endian encoding of n.
    /// </summary>
    public sealed class SodiumAes256Gcm : Aes256Gcm
    {
		public SodiumAes256Gcm()
		{
			if (!Libsodium.IsAes256GcmAvailable)
			{
				throw new NotSupportedException("AES-GCM is not available on this CPU.");
			}
		}

        public int Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySequence<byte> plaintexts, Memory<byte> ciphertext)
        {
			Debug.Assert(k.Length == Aead.KeySize);
			Debug.Assert(ciphertext.Length >= plaintexts.Length + Aead.TagSize);

			Span<byte> nonce = stackalloc byte[Aead.NonceSize];
			BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(4), n);


            var plaintext = plaintexts.ToArray();

            int result = Libsodium.crypto_aead_aes256gcm_encrypt(
                ref MemoryMarshal.GetReference(ciphertext.Span), out long length, plaintext,
                plaintext.Length, ad, ad?.Length??0, IntPtr.Zero,
                ref MemoryMarshal.GetReference(nonce), k);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}

			Debug.Assert(length == plaintext.Length + Aead.TagSize);
			return (int)length;
		}

        public int Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySequence<byte> ciphertexts, Memory<byte> plaintext)
        {
			Debug.Assert(k.Length == Aead.KeySize);
			Debug.Assert(ciphertexts.Length >= Aead.TagSize);
			Debug.Assert(plaintext.Length >= ciphertexts.Length - Aead.TagSize);

			Span<byte> nonce = stackalloc byte[Aead.NonceSize];
			BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(4), n);

            var ciphertext = ciphertexts.ToArray();

            int result = Libsodium.crypto_aead_aes256gcm_decrypt(
                 ref MemoryMarshal.GetReference(plaintext.Span), out long length, IntPtr.Zero,
                ciphertext, ciphertext.Length, ad, ad?.Length??0,
                ref MemoryMarshal.GetReference(nonce), k);

			if (result != 0)
			{
				throw new CryptographicException("Decryption failed.");
			}

			Debug.Assert(length == ciphertext.Length - Aead.TagSize);
			return (int)length;
		}

            }
}
