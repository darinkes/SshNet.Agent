using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace SshNet.Agent
{
    public class PageantSocketStream : Stream, IDisposable
    {
        private const int AgentMaxMsglen = 8192;
        private const long AgentCopydataId = 0x804e50ba;
        private const int WmCopydata = 0x004A;

        private readonly string _tempFile;
        private readonly MemoryMappedFile _memoryMappedFile;
        private readonly Stream _stream;
        private readonly Copydatastruct _copyData;
        private readonly IntPtr _copyDataPtr;

        private struct Copydatastruct {
            public IntPtr DwData;
            public int CbData;
            public IntPtr LpData;
        }

        [DllImport ("user32.dll")]
        private static extern IntPtr SendMessage (IntPtr hWnd, uint dwMsg, IntPtr wParam, IntPtr lParam);

        [DllImportAttribute ("user32.dll", EntryPoint = "FindWindowA", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
        private static extern IntPtr FindWindow ([MarshalAsAttribute (UnmanagedType.LPStr)] string lpClassName, [MarshalAsAttribute (UnmanagedType.LPStr)] string lpWindowName);

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _stream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _stream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            _stream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _stream.Write(buffer, offset, count);
        }

        public override bool CanRead => _stream.CanRead;
        public override bool CanSeek => _stream.CanSeek;
        public override bool CanWrite => _stream.CanWrite;
        public override long Length => _stream.Length;
        public override long Position
        {
            get => _stream.Position;
            set => _stream.Position = value;
        }

        public PageantSocketStream()
        {
            _tempFile = Path.GetRandomFileName();
            _memoryMappedFile = MemoryMappedFile.CreateNew(_tempFile, AgentMaxMsglen);
            _stream = _memoryMappedFile.CreateViewStream();

            _copyData = new Copydatastruct
            {
                DwData = IntPtr.Size == 4
                    ? new IntPtr(unchecked((int) AgentCopydataId))
                    : new IntPtr(AgentCopydataId),
                CbData = _tempFile.Length + 1,
                LpData = Marshal.StringToCoTaskMemAnsi(_tempFile)
            };

            _copyDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(_copyData));
            Marshal.StructureToPtr(_copyData, _copyDataPtr, false);
        }

        public void Send()
        {
            var hWnd = PageantWindow();
            if (hWnd == IntPtr.Zero)
                throw new Exception("Pageant Window not found");

            var resultPtr = SendMessage(hWnd, WmCopydata, IntPtr.Zero, _copyDataPtr);
            if (resultPtr == IntPtr.Zero)
                throw new Exception("Unable to send data to Pageant");
            Position = 0; // pageant overwrites, so reset the stream to zero
        }

        private static IntPtr PageantWindow()
        {
            return FindWindow("Pageant", "Pageant");
        }

        #region IDisposable
        private bool _disposed;
        public new void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private new void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _stream.Dispose();
                _memoryMappedFile.Dispose();
                Marshal.FreeHGlobal(_copyData.LpData);
                Marshal.FreeHGlobal(_copyDataPtr);
                if (File.Exists(_tempFile))
                    File.Delete(_tempFile);
            }

            _disposed = true;
        }
        #endregion
    }
}