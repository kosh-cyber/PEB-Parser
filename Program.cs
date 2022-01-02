using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.IO;

namespace PEB_parser
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public short Length;
            public short MaximumLength;
            public IntPtr Buffer;
        }

        //Kernel32
        public static class Kernel32
        {
            [DllImport("kernel32.dll")]
            public static extern UInt32 GetLastError();
            [DllImport("kernel32.dll")]
            public static extern Boolean VirtualProtectEx(
                IntPtr hProcess,
                IntPtr lpAddress,
                UInt32 dwSize,
                UInt32 flNewProtect,
                ref UInt32 lpflOldProtect);
            [DllImport("kernel32.dll")]
            public static extern Boolean WriteProcessMemory(
                IntPtr hProcess,
                IntPtr lpBaseAddress,
                IntPtr lpBuffer,
                UInt32 nSize,
                ref UInt32 lpNumberOfBytesWritten);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref IntPtr lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref UNICODE_STRING lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.LPWStr)] string lpBuffer, IntPtr dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();
        }
        //Ntdll
        public static class Ntdll
        {
            [DllImport("ntdll.dll")]
            public static extern int NtQueryInformationProcess(
                IntPtr processHandle,
                int processInformationClass,
                ref PROCESS_BASIC_INFORMATION processInformation,
                int processInformationLength,
                ref int returnLength);

            [DllImport("ntdll.dll")]
            public static extern void RtlEnterCriticalSection(
                IntPtr lpCriticalSection);

            [DllImport("ntdll.dll")]
            public static extern void RtlLeaveCriticalSection(
                IntPtr lpCriticalSection);

        
    }

        static void Main(string[] args)
        {
            int processParametersOffset = Environment.Is64BitOperatingSystem && Environment.Is64BitProcess ? 0x20 : 0x10;

            if (Environment.Is64BitOperatingSystem && Environment.Is64BitProcess) // 64bit on 64bit
            {
                PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
                int PROCESS_BASIC_INFORMATION_SIZE = Marshal.SizeOf(bi);
                int returnLengths = 0;
                Int32 Status = Ntdll.NtQueryInformationProcess(Kernel32.GetCurrentProcess(), 0, ref bi, PROCESS_BASIC_INFORMATION_SIZE, ref returnLengths);
                Console.WriteLine("[+] ProcessId:" + bi.UniqueProcessId);
                if (Status == (Int32)NtStatus.Success)
                {
                    Console.WriteLine("[+] PebBaseAddress:" + bi.PebBaseAddress.ToString("X"));
                    foreach (var status in Enum.GetValues(typeof(NtStatus)))
                    {
                        if (Status == Convert.ToInt32(status.GetHashCode()))
                        {
                            Console.WriteLine("[+] NtStatus:" + status);
                        }
                    }
                    //ReadMemory from and ProcessParameter
                    IntPtr pp = new IntPtr();
                    Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), bi.PebBaseAddress + processParametersOffset, ref pp, new IntPtr(Marshal.SizeOf(pp)), IntPtr.Zero);
                    UNICODE_STRING us = new UNICODE_STRING();
                    Console.WriteLine("[+] CurrentProcessParameter");
                    foreach (var Parameter in Enum.GetValues(typeof(ProcessParametersx64)))
                    {
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), pp + Parameter.GetHashCode(), ref us, new IntPtr(Marshal.SizeOf(us)), IntPtr.Zero);
                        string s = new string('\0', us.Length / 2);
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), us.Buffer, s, new IntPtr(us.Length), IntPtr.Zero);
                        Console.WriteLine("  [-] " + Parameter.ToString() + ":" + s);
                    }
                }
                else
                {
                    Console.WriteLine("[+] NtStatus:" + Status);
                }

            }
            else // 32bit on 64bit
            {
                PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
                int PROCESS_BASIC_INFORMATION_SIZE = Marshal.SizeOf(bi);
                int returnLengths = 0;
                Int32 Status = Ntdll.NtQueryInformationProcess(Kernel32.GetCurrentProcess(), 0, ref bi, PROCESS_BASIC_INFORMATION_SIZE, ref returnLengths);
                Console.WriteLine("[+] ProcessId:" + bi.UniqueProcessId);
                if (Status == (Int32)NtStatus.Success)
                {
                    Console.WriteLine("[+] PebBaseAddress:" + bi.PebBaseAddress.ToString("X"));
                    foreach (var status in Enum.GetValues(typeof(NtStatus)))
                    {
                        if (Status == Convert.ToInt32(status.GetHashCode()))
                        {
                            Console.WriteLine("[+] NtStatus:" + status);
                        }
                    }
                    //ReadMemory from and ProcessParameter
                    IntPtr pp = new IntPtr();
                    Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), bi.PebBaseAddress + processParametersOffset, ref pp, new IntPtr(Marshal.SizeOf(pp)), IntPtr.Zero);
                    UNICODE_STRING us = new UNICODE_STRING();
                    Console.WriteLine("[+] CurrentProcessParameter");
                    foreach (var Parameter in Enum.GetValues(typeof(ProcessParametersx86)))
                    {
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), pp + Parameter.GetHashCode(), ref us, new IntPtr(Marshal.SizeOf(us)), IntPtr.Zero);
                        string s = new string('\0', us.Length / 2);
                        Kernel32.ReadProcessMemory(Kernel32.GetCurrentProcess(), us.Buffer, s, new IntPtr(us.Length), IntPtr.Zero);
                        Console.WriteLine("  [-] " + Parameter.ToString() + ":" + s);
                    }
                }
                else
                {
                    Console.WriteLine("[+] NtStatus:" + Status);
                }
            }

            Console.ReadLine();
            Environment.Exit(0);
        }
    }
}
