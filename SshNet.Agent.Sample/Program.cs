using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Renci.SshNet;
using SshNet.Agent.Extensions;

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
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // var agent = new SshAgent();
                var agent = new Pageant();

                agent.RemoveAllIdentities();

                var testKeys = new[]
                {
                    "ed25519", "ecdsa256", "ecdsa384", "ecdsa521", "rsa2048", "rsa3072", "rsa4096", "rsa8192"
                };

                foreach (var testKey in testKeys)
                {
                    Console.WriteLine($"Testing Key {testKey}");
                    var keyFile = new PrivateKeyFile(GetKey(testKey));
                    agent.AddIdentity(keyFile);

                    var keys = agent.RequestIdentities().Select(i => i.Key).ToArray();

                    try
                    {
                        using var client = new SshClient("schwanensee", "root", keys);
                        client.Connect();
#if NET5_0
                        client.RunCommand("rm -f /tmp/test-agent.sock");
                        var forwardedAgent = client.ForwardAgent(agent, "/tmp/test-agent.sock");

                        Console.WriteLine($"Agent forwarded to {forwardedAgent.RemotePath}, Enter to continue...");
                        Console.ReadLine();

                        client.RemoveForwardedPort(forwardedAgent.ForwardedPort);
                        forwardedAgent.Stop();
#endif
                        Console.WriteLine(client.RunCommand("hostname").Result.Trim());
                        Console.WriteLine($"Key {testKey} worked!");
                        Console.WriteLine();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        Console.ReadLine();
                    }
                    agent.RemoveIdentities(keys.ToList());

                    if (agent.RequestIdentities().Any())
                        throw new Exception("There should be no keys!");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            Console.WriteLine("Done");
            Console.ReadLine();
        }

        private static Stream GetKey(string keyname)
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.Agent.Sample.TestKeys.{keyname}");
        }
    }
}