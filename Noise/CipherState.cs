using System;
using System.Buffers;
using System.Diagnostics;

namespace PortableNoise
{
	/// <summary>
	/// A CipherState can encrypt and decrypt data based on its variables k
	/// (a cipher key of 32 bytes) and n (an 8-byte unsigned integer nonce).
	/// </summary>
	internal sealed class CipherState<CipherType> : IDisposable where CipherType : Cipher, new()
	{
		private const ulong MaxNonce = ulong.MaxValue;

		private static readonly byte[] zeroLen = Array.Empty<byte>();
		private static readonly byte[] zeros = new byte[32];

		private readonly CipherType cipher = new CipherType();
		private byte[] k;
		private ulong n;
		private bool disposed;

		/// <summary>
		/// Sets k = key. Sets n = 0.
		/// </summary>
		public void InitializeKey(ReadOnlyMemory<byte> key)
		{
			Debug.Assert(key.Length == Aead.KeySize);

			k = k ?? new byte[Aead.KeySize];
			key.CopyTo(k);

			n = 0;
		}

		/// <summary>
		/// Returns true if k is non-empty, false otherwise.
		/// </summary>
		public bool HasKey()
		{
			return k != null;
		}

		/// <summary>
		/// Sets n = nonce. This function is used for handling out-of-order transport messages.
		/// </summary>
		public void SetNonce(ulong nonce)
		{
			n = nonce;
		}


        /// <summary>
        /// If k is non-empty returns ENCRYPT(k, n++, ad, plaintext).
        /// Otherwise copies the plaintext to the ciphertext parameter,
        /// returns the length of the plaintext and counter used in the nonce parameter.
        /// </summary>
        public int EncryptWithAd(byte[] ad, ReadOnlySequence<byte> plaintexts,Memory<byte> ciphertext, out ulong nonce)
        {
            if (n == MaxNonce)
            {
                throw new OverflowException("Nonce has reached its maximum value.");
            }

            if (k == null)
            {
                int t = 0;
                foreach (var plaintext in plaintexts)
                {
                    plaintext.CopyTo(ciphertext.Slice(t));
                    t += plaintext.Length;
                }
                nonce = n;
                return t;
            }

            nonce = n++;
            return cipher.Encrypt(k, nonce, ad, plaintexts, ciphertext);
        }

        
        /// <summary>
        /// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
        /// Otherwise copies the ciphertext to the plaintext parameter and returns
        /// the length of the ciphertext. If an authentication failure occurs
        /// then n is not incremented and an error is signaled to the caller.
        /// </summary>
        public int DecryptWithAd(byte[] ad, ReadOnlySequence<byte> ciphertexts, Memory<byte> plaintext)
		{
			if (n == MaxNonce)
			{
				throw new OverflowException("Nonce has reached its maximum value.");
			}


            if (k == null)
            {
                int t = 0;
                foreach (var ciphertext in ciphertexts)
                {
                    ciphertext.CopyTo(plaintext.Slice(t));
                    t += ciphertext.Length;
                }
                return t;
            }
            

			int bytesRead = cipher.Decrypt(k, n, ad, ciphertexts, plaintext);
			++n;

			return bytesRead;
		}

		/// <summary>
		/// If k is non-empty returns DECRYPT(k, n, ad, ciphertext).
		/// Otherwise copies the ciphertext to the plaintext parameter and returns
		/// the length of the ciphertext.
		/// </summary>
		public int DecryptWithNonceAndAd(ulong nonce, byte[] ad, ReadOnlySequence<byte> ciphertexts, Memory<byte> plaintext)
		{
			if (nonce == MaxNonce)
            {
				throw new OverflowException("Nonce has reached its maximum value.");
			}


            if (k == null)
            {
                int t = 0;
                foreach (var ciphertext in ciphertexts)
                {
                    ciphertext.CopyTo(plaintext.Slice(t));
                    t += ciphertext.Length;
                }
                return t;
            }
            

			int bytesRead = cipher.Decrypt(k, nonce, ad, ciphertexts, plaintext);

			return bytesRead;
		}

		/// <summary>
		/// Sets k = REKEY(k).
		/// </summary>
		public void Rekey()
		{
			Debug.Assert(HasKey());

            var key = new byte[Aead.KeySize + Aead.TagSize];

            cipher.Encrypt(k, MaxNonce, zeroLen, new ReadOnlySequence<byte>(zeros), key);

			k = k ?? new byte[Aead.KeySize];
            Buffer.BlockCopy(key, Aead.KeySize, k, 0, Aead.TagSize);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				Utilities.ZeroMemory(k);
				disposed = true;
			}
		}
	}
}
