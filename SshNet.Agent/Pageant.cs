using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using SshNet.Agent.AgentMessage;

namespace SshNet.Agent
{
    public class Pageant : Agent
    {
        private const int AgentMaxMsglen = 8192;
        private const long AgentCopydataId = 0x804e50ba;
        private const int WmCopydata = 0x004A;

        private struct Copydatastruct {
            public IntPtr DwData;
            public int CbData;
            public IntPtr LpData;
        }

        [DllImport ("user32.dll")]
        private static extern IntPtr SendMessage (IntPtr hWnd, uint dwMsg, IntPtr wParam, IntPtr lParam);

        [DllImportAttribute ("user32.dll", EntryPoint = "FindWindowA", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
        private static extern IntPtr FindWindow ([MarshalAsAttribute (UnmanagedType.LPStr)] string lpClassName, [MarshalAsAttribute (UnmanagedType.LPStr)] string lpWindowName);

        public static bool Available()
        {
            return PageantWindow() != IntPtr.Zero;
        }

        public Pageant()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new Exception("Pageant is Windows only");
            }
        }

        private static IntPtr PageantWindow()
        {
            return FindWindow("Pageant", "Pageant");
        }

        internal override object Send(IAgentMessage message)
        {
            var hWnd = PageantWindow();
            if (hWnd == IntPtr.Zero)
                throw new Exception("Pageant Window not found");

            var randomFileName = Path.GetRandomFileName();
            using var memoryMappedFile = MemoryMappedFile.CreateNew(randomFileName, AgentMaxMsglen);

            using var memoryMappedStream = memoryMappedFile.CreateViewStream();
            using var writer = new AgentWriter(memoryMappedStream);
            using var reader = new AgentReader(memoryMappedStream);

            message.To(writer);

            var copyData = new Copydatastruct
            {
                DwData = (IntPtr.Size == 4)
                    ? new IntPtr(unchecked((int) AgentCopydataId))
                    : new IntPtr(AgentCopydataId),
                CbData = randomFileName.Length + 1,
                LpData = Marshal.StringToCoTaskMemAnsi(randomFileName)
            };

            var copyDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(copyData));
            Marshal.StructureToPtr(copyData, copyDataPtr, false);

            var resultPtr = SendMessage(hWnd, WmCopydata, IntPtr.Zero, copyDataPtr);

            Marshal.FreeHGlobal (copyData.LpData);
            Marshal.FreeHGlobal (copyDataPtr);

            if (resultPtr == IntPtr.Zero)
                throw new Exception("Unable to send data to Pageant");

            memoryMappedStream.Position = 0;
            return message.From(reader);
        }
    }
}