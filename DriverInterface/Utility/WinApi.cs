using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace KsDumper11.Utility
{
	public static class WinApi
	{
        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
		public static extern IntPtr CreateFileA([MarshalAs(UnmanagedType.LPStr)] string filename, [MarshalAs(UnmanagedType.U4)] FileAccess access, [MarshalAs(UnmanagedType.U4)] FileShare share, IntPtr securityAttributes, [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition, [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes, IntPtr templateFile);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
		public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, int nInBufferSize, IntPtr lpOutBuffer, int nOutBufferSize, IntPtr lpBytesReturned, IntPtr lpOverlapped);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
		public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer, int nInBufferSize, byte[] lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, IntPtr lpOverlapped);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualLock(IntPtr lpAddress, uint dwSize);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualUnlock(IntPtr lpAddress, uint dwSize);

		[DllImport("kernel32.dll")]
		public static extern int GetLongPathName(string path, StringBuilder pszPath, int cchPath);

		public static readonly int FILE_DEVICE_UNKNOWN = 34;

		public static readonly int METHOD_BUFFERED = 0;

		public static readonly int FILE_ANY_ACCESS = 0;

		public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

		// Memory allocation constants
		public const uint MEM_COMMIT = 0x1000;
		public const uint MEM_RESERVE = 0x2000;
		public const uint MEM_RELEASE = 0x8000;
		public const uint PAGE_READWRITE = 0x04;


		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

		[DllImport("ntdll.dll")]
		internal static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, out IntPtr ProcessInformation, int ProcessInformationLength, out int ReturnLength);


    }
}
