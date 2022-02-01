using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

using BenchmarkDotNet.Attributes;

namespace BCvsSodium
{
    public class TestNoisenet
    {
        List<string> messages;
        public TestNoisenet()
        {
            messages = new List<string>
                {
                    "Now that the party is jumping",
                    "With the bass kicked in, the fingers are pumpin'",
                    "Quick to the point, to the point no faking",
                    "I'm cooking MC's like a pound of bacon"
                };
            for (int i = 0; i < 100000; i++)
            {
                messages.Add("With the bass kicked in, the fingers are pumpin'");
            }
        }
        [Benchmark]
        public void Noisenet()
        {
            var protocol = new Noise.Protocol(
            Noise.HandshakePattern.IK,
            Noise.CipherFunction.ChaChaPoly,
            Noise.HashFunction.Blake2b,
            Noise.PatternModifiers.Psk2);


            // Generate static keys for the client and the server.
            using (var clientStatic = Noise.KeyPair.Generate())
            using (var serverStatic = Noise.KeyPair.Generate())
            {
                var psk = new byte[32];

                // Generate a random 32-byte pre-shared secret key.
                using (var random = RandomNumberGenerator.Create())
                {
                    random.GetBytes(psk);
                }
                using (var handshakeStatec = protocol.Create(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.Create(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[Noise.Protocol.MaxMessageLength];
                    var buffers = new byte[Noise.Protocol.MaxMessageLength];
                    var buffert = new byte[Noise.Protocol.MaxMessageLength];

                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsSpan(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            Memory<byte> request = Encoding.UTF8.GetBytes(message);

                            // Send the message to the server.
                            bytesWrittenc = transportc.WriteMessage(request.Span, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsSpan(0, bytesWrittenc), buffers);
                            bytesWrittens = transports.WriteMessage(buffers.AsSpan(0, bytesReads), buffert);


                            var bytesReadc = transportc.ReadMessage(buffert.AsSpan(0, bytesWrittens), bufferc);
                            if (!request.Span.SequenceEqual(bufferc.AsSpan(0, bytesReadc)))
                            {
                                throw new Exception("failed");
                            }


                        }
                    }
                }
            }
        }


        [Benchmark]
        public void PortableNoiseLibsodium()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.Libsodium.SodiumChaCha20Poly1305,
            PortableNoise.Engine.Libsodium.SodiumCurve25519, PortableNoise.Engine.Libsodium.SodiumBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            // Generate static keys for the client and the server.
            using (var clientStatic = Noise.KeyPair.Generate())
            using (var serverStatic = Noise.KeyPair.Generate())
            {
                var psk = new byte[32];

                // Generate a random 32-byte pre-shared secret key.
                using (var random = RandomNumberGenerator.Create())
                {
                    random.GetBytes(psk);
                }
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[Noise.Protocol.MaxMessageLength];
                    var buffers = new byte[Noise.Protocol.MaxMessageLength];
                    var buffert = new byte[Noise.Protocol.MaxMessageLength];

                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsMemory(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsMemory(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            Memory<byte> request = Encoding.UTF8.GetBytes(message);

                            // Send the message to the server.
                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsMemory(0, bytesWrittenc), buffers);
                            bytesWrittens = transports.WriteMessage(buffers.AsMemory(0, bytesReads), buffert);


                            var bytesReadc = transportc.ReadMessage(buffert.AsMemory(0, bytesWrittens), bufferc);
                            if (!request.Span.SequenceEqual(bufferc.AsSpan(0, bytesReadc)))
                            {
                                throw new Exception("failed");
                            }


                        }
                    }
                }
            }
        }



        [Benchmark]
        public void PortableNoiseBouncyCastle()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.BouncyCastle.BCChaCha20Poly1305,
            PortableNoise.Engine.BouncyCastle.BCCurve25519, PortableNoise.Engine.BouncyCastle.BCBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            // Generate static keys for the client and the server.
            using (var clientStatic = Noise.KeyPair.Generate())
            using (var serverStatic = Noise.KeyPair.Generate())
            {
                var psk = new byte[32];

                // Generate a random 32-byte pre-shared secret key.
                using (var random = RandomNumberGenerator.Create())
                {
                    random.GetBytes(psk);
                }
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[Noise.Protocol.MaxMessageLength];
                    var buffers = new byte[Noise.Protocol.MaxMessageLength];
                    var buffert = new byte[Noise.Protocol.MaxMessageLength];

                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsMemory(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsMemory(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            Memory<byte> request = Encoding.UTF8.GetBytes(message);

                            // Send the message to the server.
                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsMemory(0, bytesWrittenc), buffers);
                            bytesWrittens = transports.WriteMessage(buffers.AsMemory(0, bytesReads), buffert);


                            var bytesReadc = transportc.ReadMessage(buffert.AsMemory(0, bytesWrittens), bufferc);
                            if (!request.Span.SequenceEqual(bufferc.AsSpan(0, bytesReadc)))
                            {
                                throw new Exception("failed");
                            }


                        }
                    }
                }
            }
        }

        [Benchmark]
        public void PortableNoiseBouncyCastle448()
        {
            var protocol = new PortableNoise.Protocol<PortableNoise.Engine.BouncyCastle.BCChaCha20Poly1305,
            PortableNoise.Engine.BouncyCastle.BCCurve25519, PortableNoise.Engine.BouncyCastle.BCBlake2b>(
            PortableNoise.HandshakePattern.IK, PortableNoise.PatternModifiers.Psk2);


            // Generate static keys for the client and the server.
            using (var clientStatic = Noise.KeyPair.Generate())
            using (var serverStatic = Noise.KeyPair.Generate())
            {
                var psk = new byte[32];

                // Generate a random 32-byte pre-shared secret key.
                using (var random = RandomNumberGenerator.Create())
                {
                    random.GetBytes(psk);
                }
                using (var handshakeStatec = protocol.CreateHandshakeState(true, s: clientStatic.PrivateKey, rs: serverStatic.PublicKey, psks: new[] { psk }))
                using (var handshakeStates = protocol.CreateHandshakeState(false, s: serverStatic.PrivateKey, psks: new[] { psk }))
                {
                    var bufferc = new byte[Noise.Protocol.MaxMessageLength];
                    var buffers = new byte[Noise.Protocol.MaxMessageLength];
                    var buffert = new byte[Noise.Protocol.MaxMessageLength];

                    // Send the first handshake message to the server.
                    var (bytesWrittenc, _, _) = handshakeStatec.WriteMessage(null, bufferc);

                    handshakeStates.ReadMessage(bufferc.AsMemory(0, bytesWrittenc), buffers);
                    var (bytesWrittens, _, transports) = handshakeStates.WriteMessage(null, buffers);

                    var (_, _, transportc) = handshakeStatec.ReadMessage(buffers.AsMemory(0, bytesWrittens), bufferc);

                    // Handshake complete, switch to transport mode.
                    using (transportc)
                    using (transports)
                    {
                        foreach (var message in messages)
                        {
                            Memory<byte> request = Encoding.UTF8.GetBytes(message);

                            // Send the message to the server.
                            bytesWrittenc = transportc.WriteMessage(request, bufferc);


                            var bytesReads = transports.ReadMessage(bufferc.AsMemory(0, bytesWrittenc), buffers);
                            bytesWrittens = transports.WriteMessage(buffers.AsMemory(0, bytesReads), buffert);


                            var bytesReadc = transportc.ReadMessage(buffert.AsMemory(0, bytesWrittens), bufferc);
                            if (!request.Span.SequenceEqual(bufferc.AsSpan(0, bytesReadc)))
                            {
                                throw new Exception("failed");
                            }


                        }
                    }
                }
            }
        }

    }
}
