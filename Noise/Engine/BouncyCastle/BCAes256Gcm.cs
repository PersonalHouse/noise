using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// AES256 with GCM from NIST Special Publication
    /// <see href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">800-38D</see>
    /// with a 128-bit tag appended to the ciphertext.
    /// The 96-bit nonce is formed by encoding 32 bits
    /// of zeros followed by big-endian encoding of n.
    /// </summary>
    public sealed class BCAes256Gcm : Aes256Gcm
    {

        GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
        public int Encrypt(byte[] k, ulong n, byte[] ad, ReadOnlySequence<byte> plaintexts, Memory<byte> ciphertext)
        {
            Debug.Assert(k.Length == Aead.KeySize);
            Debug.Assert(ciphertext.Length >= plaintexts.Length + Aead.TagSize);

            var nonce = new byte[Aead.NonceSize];
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan().Slice(4), n);

            var parameters = new AeadParameters(new KeyParameter(k), Aead.TagSize * 8, nonce, ad);
            cipher.Init(true, parameters);

            if (!MemoryMarshal.TryGetArray(ciphertext, out ArraySegment<byte> asciphertext))
            {
                throw new InvalidOperationException("Buffer backed by array was expected");
            }

            try
            {
                //Generate Cipher Text With Auth Tag            
                var t = 0;
                foreach (var plaintext in plaintexts)
                {
                    if (!MemoryMarshal.TryGetArray(plaintext, out ArraySegment<byte> arraySegment))
                    {
                        throw new InvalidOperationException("Buffer backed by array was expected");
                    }
                    var len = cipher.ProcessBytes(arraySegment.Array, arraySegment.Offset, arraySegment.Count, asciphertext.Array, t + asciphertext.Offset);
                    t += len;
                }
                t += cipher.DoFinal(asciphertext.Array, t + asciphertext.Offset);

                return t;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                throw new CryptographicException("Encrypt failed.");
            }
        }

        public int Decrypt(byte[] k, ulong n, byte[] ad, ReadOnlySequence<byte> ciphertexts, Memory<byte> plaintext)
        {
            Debug.Assert(k.Length == Aead.KeySize);
            Debug.Assert(ciphertexts.Length >= Aead.TagSize);
            Debug.Assert(plaintext.Length >= ciphertexts.Length - Aead.TagSize);


            var nonce = new byte[Aead.NonceSize];
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan().Slice(4), n);

            var parameters = new AeadParameters(new KeyParameter(k), Aead.TagSize * 8, nonce, ad);
            cipher.Init(false, parameters);


            if (!MemoryMarshal.TryGetArray(plaintext, out ArraySegment<byte> asplaintext))
            {
                throw new InvalidOperationException("Buffer backed by array was expected");
            }

            try
            {
                var t = 0;
                foreach (var ciphertext in ciphertexts)
                {
                    if (!MemoryMarshal.TryGetArray(ciphertext, out ArraySegment<byte> arraySegment))
                    {
                        throw new InvalidOperationException("Buffer backed by array was expected");
                    }
                    var len = cipher.ProcessBytes(arraySegment.Array, arraySegment.Offset, arraySegment.Count, asplaintext.Array, asplaintext.Offset + t);
                    t += len;
                }
                t += cipher.DoFinal(asplaintext.Array, t + asplaintext.Offset);

                return t;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                throw new CryptographicException("Decryption failed.");
            }
        }

    }
}
