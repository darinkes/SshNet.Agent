using System;
using System.IO;
using System.Linq;
using Renci.SshNet;
using Renci.SshNet.Security;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// Throwaway keys generated for these tests. The .ppk keys were generated with
    /// PuTTYgen, the others with ssh-keygen. ed25519_zerolead's public key starts
    /// with a 0x00 byte, an edge case for the SSH wire encoding.
    /// </summary>
    internal static class TestKeys
    {
        public const string Ed25519Puttygen = "ed25519_puttygen";
        public const string Ed25519ZeroLead = "ed25519_zerolead";
        public const string Rsa = "rsa_a";
        public const string Ecdsa = "ecdsa_256";
        public const string RsaUnauthorizedB = "rsa_b";
        public const string RsaUnauthorizedC = "rsa_c";

        /// <summary>Certificates signed by the checked-in throwaway CA (test_ca), principal "test".</summary>
        public const string Ed25519Cert = "ed25519_puttygen-cert";
        public const string RsaCert = "rsa_a-cert";

        /// <summary>The keys the test SSH server accepts (see SshServerFixture).</summary>
        public static readonly string[] Authorized = { Ed25519Puttygen, Ed25519ZeroLead, Rsa, Ecdsa };

        public static string Dir => Path.Combine(AppContext.BaseDirectory, "TestKeys");

        public static string PrivateKeyPath(string name) => Path.Combine(Dir, name + ".key");

        public static string PuttyKeyPath(string name) => Path.Combine(Dir, name + ".ppk");

        public static string PublicKeyPath(string name) => Path.Combine(Dir, name + ".pub");

        public static byte[] PublicKeyBlob(string name) =>
            Convert.FromBase64String(File.ReadAllText(PublicKeyPath(name)).Split(' ')[1]);

        public static PrivateKeyFile PrivateKey(string name)
        {
            // "<key>-cert" loads the private key of <key> together with its certificate
            var keyFile = name.EndsWith("-cert")
                ? new PrivateKeyFile(PrivateKeyPath(name.Substring(0, name.Length - 5)), null, PublicKeyPath(name))
                : new PrivateKeyFile(PrivateKeyPath(name));
            Key(keyFile).Comment = "sshnet-agent-test-" + name;
            return keyFile;
        }

        private static Key Key(PrivateKeyFile keyFile)
        {
            return keyFile.HostKeyAlgorithms.First() switch
            {
                CertificateHostAlgorithm certificateAlgorithm => certificateAlgorithm.Key,
                var algorithm => ((KeyHostAlgorithm)algorithm).Key,
            };
        }

        public static SshAgentPrivateKey? Find(SshAgentPrivateKey[] identities, string name)
        {
            var blob = PublicKeyBlob(name);
            return identities.FirstOrDefault(identity =>
                ((KeyHostAlgorithm)identity.HostKeyAlgorithms.First()).Data.SequenceEqual(blob));
        }
    }
}
