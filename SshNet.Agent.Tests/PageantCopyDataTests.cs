using System.IO;
using System.Runtime.InteropServices;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// The legacy WM_COPYDATA transport hands messages over in a fixed 8 KB
    /// memory-mapped file, so both directions must be bounded by that size.
    /// </summary>
    public class PageantCopyDataTests
    {
        [Fact]
        public void OversizedRequest_IsRefusedBeforeSending()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Skip("Pageant is Windows only");

            // the size check happens before any hand-off, so no Pageant is needed
            var pageant = new Pageant((string?)null, null);

            var exception = Assert.Throws<SshAgentException>(() => pageant.Lock(new string('x', 9000)));
            Assert.Contains("WM_COPYDATA", exception.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(8192 - 3)] // one byte more than the map can frame
        public void InvalidResponseLength_IsRejected(int length)
        {
            Assert.Throws<InvalidDataException>(() => Pageant.ValidateResponseLength(length));
        }

        [Fact]
        public void LargestFramableResponseLength_IsAccepted()
        {
            Pageant.ValidateResponseLength(8192 - 4);
        }
    }
}
