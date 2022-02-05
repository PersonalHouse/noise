using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace PortableNoise.Engine.BouncyCastle
{
    /// <summary>
    /// AEAD_CHACHA20_POLY1305 from <see href="https://tools.ietf.org/html/rfc7539">RFC 7539</see>.
    /// The 96-bit nonce is formed by encoding 32 bits
    /// of zeros followed by little-endian encoding of n.
    /// </summary>
    public sealed class BCChaCha20Poly1305 : ChaCha20Poly1305
    {
        Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        public BCChaCha20Poly1305()
        {

        }

        public int Encrypt(byte[] k, ulong n, byte[] ad, IList<ArraySegment<byte>> plaintexts, Memory<byte> ciphertext)
        {
            Debug.Assert(k.Length == Aead.KeySize);
            Debug.Assert(ciphertext.Length >= plaintexts.Total() + Aead.TagSize);

            var nonce = new byte[Aead.NonceSize];
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            //var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
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
                for (var i = 0; i < plaintexts.Count; i++)
                {
                    var arraySegment = plaintexts[i];
                    var len = cipher.ProcessBytes(arraySegment.Array, arraySegment.Offset, arraySegment.Count, asciphertext.Array, t + asciphertext.Offset);
                    t += len;
                }
                t += cipher.DoFinal(asciphertext.Array, asciphertext.Offset + t);

                return t;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                throw new CryptographicException("Encrypt failed.");
            }
        }

        public int Decrypt(byte[] k, ulong n, byte[] ad, IList<ArraySegment<byte>> ciphertexts, Memory<byte> plaintext)
        {
            Debug.Assert(k.Length == Aead.KeySize);
            Debug.Assert(ciphertexts.Total() >= Aead.TagSize);
            Debug.Assert(plaintext.Length >= ciphertexts.Total() - Aead.TagSize);


            var nonce = new byte[Aead.NonceSize];
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan().Slice(4), n);

            //var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(k), Aead.TagSize * 8, nonce, ad);
            cipher.Init(false, parameters);


            if (!MemoryMarshal.TryGetArray(plaintext, out ArraySegment<byte> asplaintext))
            {
                throw new InvalidOperationException("Buffer backed by array was expected");
            }

            try
            {
                var t = 0;
                for (var i = 0; i < ciphertexts.Count; i++)
                {
                    var arraySegment = ciphertexts[i];
                    var len = cipher.ProcessBytes(arraySegment.Array, arraySegment.Offset, arraySegment.Count, asplaintext.Array, asplaintext.Offset + t);
                    t += len;
                }
                t += cipher.DoFinal(asplaintext.Array, asplaintext.Offset + t);

                return t;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException )
            {
                throw new CryptographicException("Decryption failed.");
            }
        }

	}
}
