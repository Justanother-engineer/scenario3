using System;
using System.Runtime.InteropServices;

public static class Spoof
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr attribute,
        IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    private const uint PROC_CREATE_PROCESS = 0x0080;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private static readonly IntPtr ProcThreadAttributeParentProcess = new IntPtr(0x00020000);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    public static int SpawnWithParent(string cmdLine, int parentPid)
    {
        IntPtr hParent = OpenProcess(PROC_CREATE_PROCESS, false, parentPid);
        if (hParent == IntPtr.Zero) return -1;

        IntPtr attrListSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrListSize);

        IntPtr attrList = Marshal.AllocHGlobal(attrListSize);
        if (attrList == IntPtr.Zero) { CloseHandle(hParent); return -1; }

        if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrListSize))
        {
            Marshal.FreeHGlobal(attrList); CloseHandle(hParent); return -1;
        }

        IntPtr parentPtr = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(parentPtr, hParent);
        UpdateProcThreadAttribute(attrList, 0, ProcThreadAttributeParentProcess,
            parentPtr, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        STARTUPINFOEX siEx = new STARTUPINFOEX();
        siEx.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        siEx.lpAttributeList = attrList;

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool created = CreateProcess(null, cmdLine,
            IntPtr.Zero, IntPtr.Zero, false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            IntPtr.Zero, null, ref siEx, out pi);

        DeleteProcThreadAttributeList(attrList);
        Marshal.FreeHGlobal(attrList);
        Marshal.FreeHGlobal(parentPtr);
        CloseHandle(hParent);

        if (created) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return pi.dwProcessId; }
        return -1;
    }
}
