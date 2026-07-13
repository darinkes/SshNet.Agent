using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using Xunit;

namespace SshNet.Agent.Tests
{
    public enum AgentKind
    {
        OpenSsh,
        Pageant,
    }

    internal static class TestEnvironment
    {
        /// <summary>
        /// Skips the test, or fails it when the component is listed in
        /// SSHNET_AGENT_TESTS_REQUIRED (comma-separated: OpenSsh, Pageant,
        /// Server). CI sets that variable so missing components cannot turn the
        /// pipeline silently green by skipping.
        /// </summary>
        public static void Unavailable(string component, string reason)
        {
            var required = Environment.GetEnvironmentVariable("SSHNET_AGENT_TESTS_REQUIRED") ?? "";
            if (required.Split(',').Select(part => part.Trim()).Contains(component))
                Assert.Fail($"{component} is required on this machine but not available: {reason}");
            Assert.Skip(reason);
        }
    }

    /// <summary>
    /// A real, running key agent loaded with the requested test keys. Skips the
    /// test when the agent is not available on this machine. On dispose the test
    /// keys are removed again and any process we started is stopped.
    /// </summary>
    public sealed class TestAgent : IDisposable
    {
        private readonly string[] _keys;
        private Process? _agentProcess;
        private bool _stopPageant;
        private string? _tempDir;

        public SshAgent Agent { get; private set; } = null!;

        public static TestAgent Start(AgentKind kind, params string[] keys)
        {
            var testAgent = new TestAgent(keys);
            try
            {
                if (kind == AgentKind.Pageant)
                    testAgent.StartPageant();
                else
                    testAgent.StartOpenSsh();
            }
            catch
            {
                testAgent.Dispose();
                throw;
            }
            return testAgent;
        }

        public SshAgentPrivateKey Identity(string name)
        {
            var identity = TestKeys.Find(Agent.RequestIdentities(), name);
            Assert.NotNull(identity);
            return identity;
        }

        private TestAgent(string[] keys)
        {
            _keys = keys;
        }

        private void StartOpenSsh()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (!File.Exists(@"\\.\pipe\openssh-ssh-agent"))
                    TestEnvironment.Unavailable("OpenSsh", "the OpenSSH agent service is not running");
                Agent = new SshAgent("openssh-ssh-agent", null);
            }
            else
            {
                _tempDir = Directory.CreateTempSubdirectory("sshnet-agent-test-").FullName;
                var socket = Path.Combine(_tempDir, "agent.sock");
                _agentProcess = Process.Start(new ProcessStartInfo("ssh-agent", $"-D -a {socket}")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });
                WaitUntil(() => File.Exists(socket), "the ssh-agent socket");
                Agent = new SshAgent(socket, null);
            }

            foreach (var key in _keys)
                Agent.AddIdentity(TestKeys.PrivateKey(key));
        }

        private void StartPageant()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                StartUnixPageant();
                return;
            }

            var pageantExe = FindPageant();
            if (pageantExe is null)
                TestEnvironment.Unavailable("Pageant", "pageant.exe not found");

            _stopPageant = !Process.GetProcessesByName("pageant").Any();

            // Load .ppk keys the way an interactive PuTTY user would. If a Pageant
            // is already running, this hands the keys to the running instance.
            var puttyKeys = _keys.Where(key => File.Exists(TestKeys.PuttyKeyPath(key))).ToArray();
            if (puttyKeys.Length > 0 || _stopPageant)
            {
                var arguments = string.Join(" ", puttyKeys.Select(key => $"\"{TestKeys.PuttyKeyPath(key)}\""));
                Process.Start(new ProcessStartInfo(pageantExe, arguments))?.Dispose();
            }

            Agent = new Pageant();
            WaitUntil(() =>
            {
                try
                {
                    Agent.RequestIdentities();
                    return true;
                }
                catch
                {
                    return false;
                }
            }, "Pageant");

            foreach (var key in _keys.Except(puttyKeys))
                Agent.AddIdentity(TestKeys.PrivateKey(key));
            foreach (var key in puttyKeys)
                WaitUntil(() => TestKeys.Find(Agent.RequestIdentities(), key) is not null, $"key {key} in Pageant");
        }

        /// <summary>
        /// Unix Pageant (putty-tools) serves the standard agent protocol on a unix
        /// socket, so it is used through SshAgent; the Pageant class (WM_COPYDATA)
        /// is Windows-only.
        /// </summary>
        private void StartUnixPageant()
        {
            if (!ExistsInPath("pageant"))
                TestEnvironment.Unavailable("Pageant", "pageant not found, install PuTTY");

            var puttyKeys = _keys.Where(key => File.Exists(TestKeys.PuttyKeyPath(key))).ToArray();
            var arguments = string.Join(" ", puttyKeys.Select(key => $"\"{TestKeys.PuttyKeyPath(key)}\""));
            // stdbuf: pageant --debug only line-buffers its socket announcement on a tty
            _agentProcess = Process.Start(new ProcessStartInfo("stdbuf", $"-oL pageant --debug {arguments}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            string? socket = null;
            for (var i = 0; i < 10 && socket is null; i++)
            {
                var line = _agentProcess!.StandardOutput.ReadLine();
                if (line is null)
                    break;
                var match = Regex.Match(line, "SSH_AUTH_SOCK=([^;]+)");
                if (match.Success)
                    socket = match.Groups[1].Value;
            }
            if (socket is null)
                throw new TimeoutException("pageant --debug did not announce its socket");

            Agent = new SshAgent(socket, null);
            foreach (var key in _keys.Except(puttyKeys))
                Agent.AddIdentity(TestKeys.PrivateKey(key));
            foreach (var key in puttyKeys)
                WaitUntil(() => TestKeys.Find(Agent.RequestIdentities(), key) is not null, $"key {key} in Pageant");
        }

        private static bool ExistsInPath(string name)
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            return path.Split(Path.PathSeparator).Any(dir => File.Exists(Path.Combine(dir.Trim(), name)));
        }

        public void Dispose()
        {
            if (Agent is not null)
            {
                try
                {
                    var identities = Agent.RequestIdentities();
                    Agent.RemoveIdentities(_keys.Select(key => TestKeys.Find(identities, key)).Where(identity => identity is not null)!);
                }
                catch
                {
                    // agent already gone
                }
            }

            if (_stopPageant)
            {
                foreach (var process in Process.GetProcessesByName("pageant"))
                {
                    // Wait for the exit: the next test must not mistake a dying
                    // Pageant for a running one, or it would never start its own.
                    try
                    {
                        process.Kill();
                        process.WaitForExit(5000);
                    }
                    catch
                    {
                        // already gone
                    }
                    process.Dispose();
                }
            }
            if (_agentProcess is not null)
            {
                try { _agentProcess.Kill(); } catch { /* already gone */ }
                _agentProcess.Dispose();
            }
            if (_tempDir is not null)
            {
                try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
            }
        }

        private static void WaitUntil(Func<bool> condition, string what)
        {
            for (var i = 0; i < 150; i++)
            {
                if (condition())
                    return;
                Thread.Sleep(200);
            }
            throw new TimeoutException($"{what} did not become ready");
        }

        private static string? FindPageant()
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            var candidates = path.Split(Path.PathSeparator).Select(dir => Path.Combine(dir.Trim(), "pageant.exe")).ToList();
            foreach (var programFiles in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
                candidates.Add(Path.Combine(Environment.GetFolderPath(programFiles), "PuTTY", "pageant.exe"));
            return candidates.FirstOrDefault(File.Exists);
        }
    }
}
