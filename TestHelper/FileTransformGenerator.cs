using System;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace TestHelper
{


    [Generator]
    public class FileTransformGenerator : ISourceGenerator
    {
        public void Initialize(GeneratorInitializationContext context)
        {

        }

        public void Execute(GeneratorExecutionContext context)
        {
            context.AnalyzerConfigOptions.GlobalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out var projectDirectory);
            if (projectDirectory == null)
            {
                projectDirectory = "";
            }
            if (!File.Exists(Path.Combine(projectDirectory, "Vectors/cacophony.txt")))
            {
                var mainSyntaxTree = context.Compilation.SyntaxTrees
                        .First(x => x.HasCompilationUnitRoot);
                var projectDirectory2 = Path.GetDirectoryName(mainSyntaxTree.FilePath);

                while (true)
                {
                    if (File.Exists(Path.Combine(projectDirectory2, "Vectors/cacophony.txt")))
                    {
                        break;
                    }
                    if (projectDirectory2.Length < 3)
                    {
                        throw new Exception($"No {projectDirectory} and {projectDirectory2}");
                    }
                    projectDirectory2 = Path.GetDirectoryName(projectDirectory2);
                }
                projectDirectory = projectDirectory2;
            }


            StringBuilder sb = new StringBuilder();
            sb.Append($@"
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using TestAllianceCommunicator;

using Xunit;

namespace PortableNoise.Tests
{{
	public partial class NoiseTest
	{{

");


            var s = File.ReadAllText(Path.Combine(projectDirectory, "Vectors/cacophony.txt"));
            GenerateTests(s, sb, "_cacophony", "CoreTest");

            s = File.ReadAllText(Path.Combine(projectDirectory, "Vectors/snow-multipsk.txt"));
            GenerateTests(s, sb, "_multipsk", "CoreTest");

            s = File.ReadAllText(Path.Combine(projectDirectory, "Vectors/noise-c-fallback.txt"));
            GenerateTests(s, sb, "_fb", "CoreTestFallback");

            s = File.ReadAllText(Path.Combine(projectDirectory, "Vectors/c/cacophony.txt"));
            GenerateTests(s, sb, "_ncacophony", "CoreTest");

            s = File.ReadAllText(Path.Combine(projectDirectory, "Vectors/c/noise-c-basic.txt"));
            GenerateTests(s, sb, "_ncb", "CoreTest");

            sb.Append("/*");
            sb.Append("*/");

            sb.Append($@"

    }}
}}");
            context.AddSource("NoiseTest.Generated.cs", sb.ToString());
        }

        private static void GenerateTests(string s, StringBuilder sb,string postfix,string testfunc)
        {
            var json = JObject.Parse(s);
            if (true)
            {
                foreach (var vector in json["vectors"])
                {
                    var protocolName = GetString(vector, "protocol_name");

                    var protarr = protocolName.Split('_');


                    var next = protarr[1];
                    var pattern = next.Length > 1 && char.IsUpper(next[1]) ? next.Substring(0, 2) : next.Substring(0, 1);
                    string fmodifiers = null;
                    var modifiers = next.Substring(pattern.Length).Split(new[] { '+' },StringSplitOptions.RemoveEmptyEntries);
                    foreach (var modifier in modifiers)
                    {
                        var m = modifier.Trim();
                        if (string.IsNullOrWhiteSpace(modifier))
                        {
                            m = "PatternModifiers.None";
                        }
                        else
                        {
                            m = m.Replace("psk", "Psk").Replace("fallback", "Fallback");
                            m = "PatternModifiers." + m;
                        }
                        if(string.IsNullOrWhiteSpace(fmodifiers))
                        {
                            fmodifiers = m;
                        }else
                        {
                            fmodifiers += $"|{m}";
                        }
                    }
                    if (string.IsNullOrWhiteSpace(fmodifiers))
                    {
                        fmodifiers = "PatternModifiers.None";
                    }
                    string ec = protarr[2];


                    string cipher = protarr[3];
                    if (string.Compare(cipher, "ChaChaPoly", true) == 0)
                    {
                        cipher = "ChaCha20Poly1305";
                    }
                    else if (string.Compare(cipher, "AESGCM", true) == 0)
                    {
                        cipher = "Aes256Gcm";
                    }
                    else
                    {
                        throw new Exception($"Get cipher {cipher} {protocolName}");
                    }


                    string hash = protarr[4];
                    string pre = "Engine.Libsodium.Sodium";
                    if (string.Compare(hash, "BLAKE2b", true) == 0)
                    {
                        hash = pre + "Blake2b";
                    }
                    else if (string.Compare(hash, "BLAKE2S", true) == 0)
                    {
                        hash = "Engine.InProject.InProjectBlake2s";
                    }
                    else if (string.Compare(hash, "Sha256", true) == 0)
                    {
                        hash = pre + "Sha256";
                    }
                    else if (string.Compare(hash, "Sha512", true) == 0)
                    {
                        hash = pre + "Sha512";
                    }
                    else
                    {
                        throw new Exception($"Get hash {hash} {protocolName}");
                    }


                    var scontent = vector.ToString();
                    scontent = scontent.Replace("\"", "\"\"");
                    if (ec != "448")
                    {

                        sb.Append($@"
    [Fact]
    private void Test{protocolName.Replace("+", "")}Sodium{postfix}()
    {{
        var s=@""{scontent}"";
        {testfunc}<{pre}{cipher},Engine.Libsodium.SodiumCurve{ec}, {hash}>(HandshakePattern.{pattern},{fmodifiers},s);

    }}
");
                    }
                    hash = protarr[4];
                    pre = "Engine.BouncyCastle.BC";
                    if (string.Compare(hash, "BLAKE2b", true) == 0)
                    {
                        hash = pre + "Blake2b";
                    }
                    else if (string.Compare(hash, "BLAKE2S", true) == 0)
                    {
                        hash = "Engine.InProject.InProjectBlake2s";
                    }
                    else if (string.Compare(hash, "Sha256", true) == 0)
                    {
                        hash = pre + "Sha256";
                    }
                    else if (string.Compare(hash, "Sha512", true) == 0)
                    {
                        hash = pre + "Sha512";
                    }
                    else
                    {
                        throw new Exception($"Get hash {hash} {protocolName}");
                    }
                    sb.Append($@"
    [Fact]
    private void Test{protocolName.Replace("+","")}BC{postfix}()
    {{

        var s=@""{scontent}"";
        {testfunc}<{pre}{cipher},Engine.BouncyCastle.BCCurve{ec}, {hash}>(HandshakePattern.{pattern},{fmodifiers},s);

    }}
");


                }
            }
        }

        private static string GetString(JToken token, string property)
        {
            return (string) token[property] ?? string.Empty;
        }
    }
}
