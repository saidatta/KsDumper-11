using System;
using System.Runtime.InteropServices;
using KsDumper11.Utility;
using static KsDumper11.Utility.WinApi;

namespace KsDumper11.Driver
{
	public static class Operations
	{
		private static uint CTL_CODE(int deviceType, int function, int method, int access)
		{
			return (uint)((deviceType << 16) | (access << 14) | (function << 2) | method);
		}

		public static readonly uint IO_GET_PROCESS_LIST = Operations.CTL_CODE(WinApi.FILE_DEVICE_UNKNOWN, 5924, WinApi.METHOD_BUFFERED, WinApi.FILE_ANY_ACCESS);

		public static readonly uint IO_COPY_MEMORY = Operations.CTL_CODE(WinApi.FILE_DEVICE_UNKNOWN, 5925, WinApi.METHOD_BUFFERED, WinApi.FILE_ANY_ACCESS);

        public static readonly uint IO_UNLOAD_DRIVER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public static readonly uint IO_GET_PROCESS_PEB = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1727, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public static readonly uint IO_GET_PROCESS_MODULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public struct KERNEL_PROCESS_LIST_OPERATION
		{
			public ulong bufferAddress;

			public int bufferSize;

			public int processCount;
		}

		public struct KERNEL_COPY_MEMORY_OPERATION
		{
			public int targetProcessId;

			public ulong targetAddress;

			public ulong bufferAddress;

			public int bufferSize;
		}

		public struct KERNEL_GET_PEB_OPERATION
		{
			public int targetProcessId;
			public ulong pebAddress;
			public int status;
		}

		public struct KERNEL_MODULE_INFO
		{
			public ulong baseAddress;
			public uint sizeOfImage;
			public bool isWow64Process;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
			public string moduleName;
		}

		// FIXED: Separate input and output structures for cleaner buffer layout
		public struct KERNEL_GET_MODULES_INPUT
		{
			public int targetProcessId;
			public int maxModules;
		}

		public struct KERNEL_GET_MODULES_OUTPUT
		{
			public int moduleCount;
			public int status;
			// modules array follows this structure
		}
	}
}
