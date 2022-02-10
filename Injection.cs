using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UR_NAMESPACE_NAME
{
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Text;

    internal class BetterInjector
    {
        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, UIntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool FreeLibrary(IntPtr hModule);
        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern UIntPtr GetProcAddress(IntPtr hModule, string procName);
        public bool InjectDLL(string dllname)
        {
            bool flag2;
            if (Process.GetProcessesByName("target").Length == 0)
            {
                flag2 = false;
            }
            else
            {
                Process process = Process.GetProcessesByName("target")[0];
                byte[] bytes = Encoding.GetEncoding("Windows-1251").GetBytes(AppDomain.CurrentDomain.BaseDirectory + dllname);
                IntPtr hModule = LoadLibraryA("kernel32.dll");
                UIntPtr procAddress = GetProcAddress(hModule, "LoadLibraryA");
                FreeLibrary(hModule);
                if (procAddress == UIntPtr.Zero)
                {
                    flag2 = false;
                }
                else
                {
                    IntPtr hProcess = OpenProcess(ProcessAccess.AllAccess, false, process.Id);
                    if (hProcess == IntPtr.Zero)
                    {
                        flag2 = false;
                    }
                    else
                    {
                        UIntPtr ptr5;
                        IntPtr ptr6;
                        IntPtr lpBaseAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)bytes.Length, 0x3000, 4);
                        flag2 = ((lpBaseAddress != IntPtr.Zero) && WriteProcessMemory(hProcess, lpBaseAddress, bytes, (uint)bytes.Length, out ptr5)) && !(CreateRemoteThread(hProcess, IntPtr.Zero, 0, procAddress, lpBaseAddress, 0, out ptr6) == IntPtr.Zero);
                    }
                }
            }
            return flag2;
        }

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr LoadLibraryA(string lpFileName);
        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [Flags]
        public enum ProcessAccess
        {
            AllAccess = 0x10067b,
            CreateThread = 2,
            DuplicateHandle = 0x40,
            QueryInformation = 0x400,
            SetInformation = 0x200,
            Terminate = 1,
            VMOperation = 8,
            VMRead = 0x10,
            VMWrite = 0x20,
            Synchronize = 0x100000
        }
    }
}

