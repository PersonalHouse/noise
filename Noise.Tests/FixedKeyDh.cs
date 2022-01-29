using System;

using PortableNoise.Engine;

namespace PortableNoise.Tests
{
	internal class FixedKeyDh<DhType> : Dh
                where DhType : Dh, new()
    {
		private static readonly DhType dh = new DhType();
		private readonly byte[] privateKey;

		public FixedKeyDh()
		{
		} 

		public FixedKeyDh(byte[] privateKey)
		{
			this.privateKey = privateKey;
		}

		public int DhLen => dh.DhLen;

		public KeyPair GenerateKeyPair()
		{
			var publicKey = new byte[DhLen];
            Engine.Libsodium.Libsodium.crypto_scalarmult_curve25519_base(publicKey, privateKey);

			return new KeyPair(privateKey, publicKey);
		}

		public KeyPair GenerateKeyPair(ReadOnlyMemory<byte> privateKey)
		{
			return dh.GenerateKeyPair(privateKey);
		}

		public void Dh(KeyPair keyPair, ReadOnlyMemory<byte> publicKey, Span<byte> sharedKey)
		{
			dh.Dh(keyPair, publicKey, sharedKey);
		}
	}
}
