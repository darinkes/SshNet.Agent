using System;
using System.Collections.Generic;
using System.CommandLine;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Renci.SshNet;

// The public keys of the embedded sample keys, ready to paste into
// ~/.ssh/authorized_keys on the demo server for the host/user login:
//
// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE5W6BcNnMuNgLYuUa18F/Ci8dzPqeIO/H333n0yv4o6
// ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEqKSQ9hDmbqz04emjXekb3wRuP1SIhGC+kRd8VjbjSfZA/av6nTU7d2wkxO0IFIjeC7x95tvtVvxXQqNa8VRXE=
// ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBEccBcSqsk28fdeLH8FBKG2AbcLslKl8DoJACAK3QoVMz1Mj/0gY/FOkqMbYgR6fAlxM06YJI8GmFO6jbcqX9P0MvyUfAXN1Tt4ljbn0/7fAP08HP+gzGSHZsTj1l0MGjA==
// ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGSBZ1QmMPoa+TX9TSG4/4x8W7hrmZGVc6x2sKVNoJOHeVQq8mqGMZAn9zVbnZWmjG0aPhO+mxoWdt9VrU6K+eKJgESXrr8mcGb2ih7KOAzpNLfOewN0NPpHMnKdBTEmdAmQV/wc/dFp2KLqz2f4SHvoRRHHHeowbE4eqpp/7/pwJREFg==
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiaXVVTDcj5AAa9ssAdojp7N0rVCTFDQxrhY6sjc1WL2l9wvK4weotRKAQh26emTxBFPHumzj1Ootob0E4xVsapmkb494c+1QLvsDDJkJMNSDGcsNmISov/rAs/GG97yNsVB0dT2S7WY+yuO6a1S5G4lrcnCIiWgg5/ZyNUGHh1+NIp/tMIrVfQ+k/rYnlG8nWv9wt9Si9cuVbOKZR7LBFmsiqv2IucaliwIrRjihlKHxJNTdBRGoCazBM3w4hFMWxThY3nUaNpX4GPylFM3NYGmzWBx/duz/oLqf+tKWCzPbDKYIwQfL9Sidhf7QgSjMl9AWe0GIVr1TBSDOBd0sn
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrN37/I7nxjUVPxPEjZXBhINxwcvjVwnBdM878EIr3UN/Bo42RtwMiyXdSGDV+CZksSzqMteyzJR5WNGJ/bW/WVYKIlzc/kwv/LdQTLynKJMZXDJSbit9FhGBc3LHif86wvihHh2TJc1muB5uUfJr7IBefvTd0UGC5HpIlZ+nQruhpcNGRrekFDIRfFVycesAw6mxy4LTv1M2rqABN2vO8qY/M6Q47Gw3ntxCfaUZAoOKNBYhAjp4jpDsUWQlRRCpu5MEfMIj08o0XjWXAqJxBZFNa2/2WM7ZHLu1tabGWFJo49EzH2aYopsi7gEnwJairIbS+FWXQjq/mEy+oJKDBEHHHvErE+Pt/BeNnnBrMm8ON5PLQsreg+nO9oq0RKq/sjvKlstQrpzDx3Ltc6iIDyiEp7XYwuIWu1xsaq+pKg5UH5KnaqjWlVOasfRs6Wgd/nE/mrmbGRQYM+j66McY7Qk79/sLj5wCiDG5NuCzNcDdtc6cxRuLln+32EhvWW0U=
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcykQr1J8RLl40RoCWw12dWbBPtuX0qMzFEjA+Au2Z4WYvrjYhC+TwjqW6MsDS6ZYZ+wlbN7wvsWOPIVeZX3Ze8zq2KG4ZFA32w0hiYh59Rn3lox1KV0ZJCGhEYZkgQco+NSazwLqYOLXUTvzgr/4jeg3NmDPRXup+wv5UPt1/KujTUUYB7QmcXQOcXEsKWCj+OiqjsUcU1Yvnazj00fsD0iaK0TMhYAftT/tvAMBzt4Gtph0q8s0FKbloIeY3Ma2IzBWd52S6rYQz9jC7STazJTiVUI1xd2N+UqSlA6dnCcUnBz6A5un5zuTurpDbsDatl/nxTm8gO+wi8KTS51g6duzIfSDrY6c9DLtinitLf/+eLYkitwQOXGNdfxhZ2YB7s9uJpzXSILzXwr1t5bx+8zZKMP9NflDKA++lvoRwPZCie/Gr49zANVffIzJTsY74gaQmHAm6dLnhySHnotbFrVh3VW451UBpgYJsY9CER4t1KfAyawbmZVu9aNvmtxoyXgzGdgycByWp9cydK0Cg2EsaQ8MQe9stIXa0cJCe1yv2cjBQFbA5aBPIL87DDss0AeLmCir3qq/VU76CDBRbUrscpK1VE9PP8+YG6qFBA2aXutvAXMxQ6lu7mOiqxbXCW1iaX3+qYj1Hi0fz1Q/n+GsIOKxqiHix20Z1FHzuew==
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAEAQDB7KyYGbKQoS7Z4CJ7JFmWA8cXHYJtVrqUCaZ44BFmmvzBP82yygSkamFwtUuEyAVUvVoOzt+NcZzMrEV70zTwi3vsRJ1p68fyQ5UNdRX4sl/O8tgbUhwWJyJXB3hcx3awh8r/Ay5lgesJflecI6YcZTJBDbt2iQxQUsCxEwfY5xql1A9zGgO1FRQQ5YwzvaxbOUrutIIY4BGjwva5ZwqwYAGbLOhyJIj87I3l3mE2uNGgenPWd+CekRvY4KOgyI9SCgDtgym+/IaLdEa3qNlLj8/D9uLpdl+HizPgR13xREmRBtBS7BT3o6PSv3RH6U/DFsqfl0nuqJ6Z75CjOpL9A+7qgHmJiIL1OU/RPJhivhQF/fEJ4qgiDi9OtaowlKQvTMGVShDgF8e3qu/P77tPNUjFI9Zsp8V6Qy2pALRrTJVXuhdisdHlzIjpzRIbZ9OENMZNkQ7kVlVHxzsSJ1jHiNevY6QWJGGhEMY4e7N6LAqJbdu7xO1h52TE9TP/NxwazmFGvo8j8YZ6j9r+ZCZGRTglMK9dIPDelz/j8LYR5D6XRobdl8iBdUNxM6jtcRLtV4zJNJ8uHUWnLxQ7NlNgsFAaZWSgCMZJMo93Xjh9z3yL8GmcQ5OJ/2su5Fx+cOhccx3oQMb8Wkz0jEqh/tXvZeuW7jZX7EBIoypJCFigTK2hLbWTY7A7H1VHlpajdyC2s9lKSS31LxIqTWLge6sDu++m6/feY5zippHskwSRrULYmgIwTw6Lzuq0bBYXMiTlmW9uQubo7+RFiVHDv1Vhj4spwEa+27vJaC8UjMhjQZlGSsYZEyXSFXg3ctvSCvOpEwR7Umxa7AFMBvA6/KkKb/J99wisJLD/zChenvQKUp/o5rz4MA0B2vuKR9YrRlGzzg8MxUsRUhyDP4hIyUiuh5A3f4RFjuc3OpxNkUQig4DA2KFXEtqjptM9vkB3hqhWfp8w+goKdUdHJ8JnEVkP7k3Jnhf0iDJvrAcECw2fMLdDf54EIOvg3/ooSMEGWJ1Z6DvniXZ03hdmCd9NQilkOWWSVVgvRwZyy3CWsWWnGgcxkg6qd9HOwrsX+1cu2iz17e1nFslfwm37pkKeyw8cL6UiZVkS/CQSBFZVyfD7AfFyzbudo/3bqD1MSKbdZDLxPzJJc2oz5Kkv3fLDDKlCOMVgyPyjLnDMTUg1et2+uLdCYEB6W/hHBnaJSP9NmhcaaZE04/v6mBW2LYrr35dDYAUAw2MHK+WUDt3Q7Uz1MbEDzXgKLc2ZhL69045//GK8DN8o6g32BLBTecgD8GiGXcVrIuPTcObtG2KEknoYfvcYHMbPDCaWBw3i+jQl6OH50CiPhoElYj6xNG+FrgRZ

namespace SshNet.Agent.Sample
{
    /// <summary>
    /// Demonstrates SshNet.Agent against a running key agent. The sample only
    /// removes the keys it added itself; identities already in the agent are
    /// left alone. See --help for the options.
    /// </summary>
    internal static class Program
    {
        private static readonly string[] SampleKeys =
        {
            "ed25519", "ecdsa256", "ecdsa384", "ecdsa521", "rsa2048", "rsa3072", "rsa4096", "rsa8192"
        };

        private static Task<int> Main(string[] args)
        {
            var pageantOption = new Option<bool>("--pageant")
            {
                Description = "Talk to PuTTY's Pageant instead of the OpenSSH agent"
            };
            var verboseOption = new Option<bool>("--verbose", "-v")
            {
                Description = "Print the raw messages exchanged with the agent"
            };
            var hostArgument = new Argument<string?>("host")
            {
                Description = "SSH server to authenticate against with the agent identities",
                Arity = ArgumentArity.ZeroOrOne
            };
            var userArgument = new Argument<string?>("user")
            {
                Description = "User to authenticate as",
                Arity = ArgumentArity.ZeroOrOne
            };

            var command = new RootCommand("Demonstrates SshNet.Agent against a running key agent")
            {
                pageantOption,
                verboseOption,
                hostArgument,
                userArgument
            };
            command.Validators.Add(result =>
            {
                if (result.GetValue(hostArgument) is not null && result.GetValue(userArgument) is null)
                    result.AddError("A host also needs a user.");
            });
            command.SetAction((result, _) =>
            {
                SshAgent agent = result.GetValue(pageantOption) ? new Pageant() : new SshAgent();
                if (result.GetValue(verboseOption))
                    agent.Logger = new HexDumpLogger();
                return RunDemo(agent, result.GetValue(hostArgument), result.GetValue(userArgument));
            });

            return command.Parse(args).InvokeAsync();
        }

        /// <summary>
        /// The library logs each raw agent message as SshAgentTraceMessage
        /// state and leaves the representation to the attached logger; this
        /// one hex-dumps the traffic, like a tiny Wireshark.
        /// </summary>
        private sealed class HexDumpLogger : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (state is not SshAgentTraceMessage message)
                {
                    Console.WriteLine(formatter(state, exception));
                    return;
                }

                Console.WriteLine($"{(message.Direction == SshAgentTraceDirection.Request ? "->" : "<-")} {message.Data.Length} bytes");
                for (var offset = 0; offset < message.Data.Length; offset += 16)
                {
                    var chunk = message.Data.Skip(offset).Take(16).ToArray();
                    var hex = string.Join(" ", chunk.Select(value => value.ToString("x2"))).PadRight(47);
                    var ascii = new string(chunk.Select(value => value is >= 0x20 and < 0x7f ? (char)value : '.').ToArray());
                    Console.WriteLine($"   {offset:x4}  {hex}  {ascii}");
                }
            }
        }

        private static async Task<int> RunDemo(SshAgent agent, string? host, string? user)
        {
            var before = ListedBlobs(await agent.RequestIdentitiesAsync());
            Console.WriteLine($"The agent holds {before.Count} identities.");

            try
            {
                Console.WriteLine("Adding the sample keys ...");
                foreach (var name in SampleKeys)
                    await agent.AddIdentityAsync(new PrivateKeyFile(GetKey(name)));

                foreach (var identity in await agent.RequestIdentitiesAsync())
                    Console.WriteLine($"  {string.Join(", ", identity.HostKeyAlgorithms.Select(algorithm => algorithm.Name))}");

                await LifetimeDemo(agent);
                await LockDemo(agent);

                if (host is not null && user is not null)
                    Login(agent, host, user);
            }
            finally
            {
                foreach (var identity in await agent.RequestIdentitiesAsync())
                {
                    if (!before.Contains(Blob(identity)))
                        await agent.RemoveIdentityAsync(identity);
                }
                Console.WriteLine("Sample keys removed again.");
            }

            return 0;
        }

        /// <summary>A key with a lifetime (ssh-add -t) expires from the agent by itself.</summary>
        private static async Task LifetimeDemo(SshAgent agent)
        {
            Console.WriteLine("Re-adding the ed25519 key with a 2s lifetime (ssh-add -t) ...");
            try
            {
                agent.AddIdentity(new PrivateKeyFile(GetKey("ed25519")), TimeSpan.FromSeconds(2));
            }
            catch (Exception e)
            {
                Console.WriteLine($"  this agent does not support constraints ({e.Message})");
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(3));
            var count = (await agent.RequestIdentitiesAsync()).Length;
            Console.WriteLine($"  after 3s the agent lists {count} identities, the key expired");
        }

        /// <summary>A locked agent (ssh-add -x) hides its identities until unlocked.</summary>
        private static async Task LockDemo(SshAgent agent)
        {
            Console.WriteLine("Locking the agent (ssh-add -x) ...");
            try
            {
                agent.Lock("passphrase");
            }
            catch (Exception e)
            {
                Console.WriteLine($"  this agent does not support locking ({e.Message})");
                return;
            }

            Console.WriteLine($"  locked: the agent lists {(await agent.RequestIdentitiesAsync()).Length} identities");
            agent.Unlock("passphrase");
            Console.WriteLine($"  unlocked: the agent lists {(await agent.RequestIdentitiesAsync()).Length} identities again");
        }

        private static void Login(SshAgent agent, string host, string user)
        {
            Console.WriteLine($"Authenticating as {user}@{host} with the agent identities ...");
            var keys = agent.RequestIdentities();
            using var client = new SshClient(new ConnectionInfo(host, user,
                new PrivateKeyAuthenticationMethod(user, keys)));
            client.Connect();
            Console.WriteLine($"  {client.RunCommand("hostname").Result.Trim()}");
        }

        private static HashSet<string> ListedBlobs(IEnumerable<SshAgentPrivateKey> identities)
        {
            return new HashSet<string>(identities.Select(Blob));
        }

        private static string Blob(SshAgentPrivateKey identity)
        {
            return Convert.ToBase64String(identity.HostKeyAlgorithms.First().Data);
        }

        private static Stream GetKey(string name)
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.Agent.Sample.TestKeys.{name}")!;
        }
    }
}
