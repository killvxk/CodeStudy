#include <conio.h>
#include <stdio.h>
#include <windows.h>
#include "phnt.h"

// This is only stalemate antidebug example, as by the time oskrnl on behalf of attaching debugger attempts to
// open the file, all our threads are already suspended. Thus both our process and debugger are deadlocked.
//
// That won't be true for opening main exe image file and ntdll, as only the very first process thread is suspended
// at that point. Now consider that filename changes are not tracked, so you can rename image or stream, and put
// other file in its place. This means non-deadlocking variant of this is possible.
//
// To continue running while having debugger blocked, we need threadX (other than 0) to put oplock on our main
// image file (or at least on the file where our image file originally was).
// Oplock break request would then arrive with only thread0 suspended; threadX will be woken up for oplock break,
// and can inspect situation and resume thread0. Resumed thread0 shall put oplock on some new PEB.Ldr module,
// and once oplock break on that requested, thread0 can resume other threads (including threadX). And threadX
// should break main image oplock and reestablish it, possible with a "new" main image file.

int __cdecl wmain()
{
    // load rare module, so it'll be in our PEB.Ldr list;
    // no one shall molest it; but to let honest apps touch it, use some own module in ads instead
    HMODULE hauLib = LoadLibraryExW(L"KBDHAU.DLL", {}, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hauLib)
        return printf("[-] failed to load kbdhau.dll\n"), STATUS_NO_SUCH_FILE;
    printf("[+] loaded kbdhau.dll\n");

    // open rare file and request oplock; we don't intend to break it
    HANDLE hauFile; // ~
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtOpenFile(&hauFile, SYNCHRONIZE,         // whatever rights
        ObjAttr(L"\\SystemRoot\\System32\\KBDHAU.DLL"),
        &iosb, FILE_SHARE_RWD, FILE_OPEN_REQUIRING_OPLOCK|FILE_NON_DIRECTORY_FILE);
    if (FAILED(st))
        return printf("[-] file open failed: %08X\n", st), st;

    // let sysmon/procmon/whatever do the job (yes... not the scope right now)
    printf("[ ] waiting a bit so as not to block more than we want...\n");
    LARGE_INTEGER timeout{.QuadPart = -10'000'000*3};
    NtDelayExecution(true, &timeout);

    REQUEST_OPLOCK_INPUT_BUFFER inp
    {
        .StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION,
        .StructureLength = sizeof(inp),
        .RequestedOplockLevel =     // sort of batch oplock
            OPLOCK_LEVEL_CACHE_READ|OPLOCK_LEVEL_CACHE_HANDLE|OPLOCK_LEVEL_CACHE_WRITE,
        .Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST
    };
    REQUEST_OPLOCK_OUTPUT_BUFFER out{};
    iosb.Status = STATUS_PENDING;   // for manual check, as we don't use event for ioctl here
    st = NtFsControlFile(hauFile, {}, {}, {}, &iosb, FSCTL_REQUEST_OPLOCK,
        &inp, sizeof(inp), &out, sizeof(out));
    if (FAILED(st))
        return printf("[-] oplock request failed: %08X\n", st), st;
    printf("[+] oplock request granted\n");

    // add console handler for better experience
    static bool s_shouldRundown;
    SetConsoleCtrlHandler([](ULONG) -> BOOL
    {
        s_shouldRundown = true;
        HANDLE thread0{};
        NtGetNextThread(NtCurrentProcess(), {}, THREAD_ALERT, 0, 0, &thread0);
        NtAlertThread(thread0);
        NtClose(thread0);
        return true;
    }, TRUE);

    for (ULONG count = 0;; ++count)
    {
        NtDelayExecution(true, &timeout);
        if (s_shouldRundown)
            break;
        if (iosb.Status == STATUS_PENDING)
            printf("[ ] %05u: nothing happened\n", count);
        else
        {
            // we won't ack/break oplock though, so this is one-time message
            printf("[*] %05u: someone tried to open kbdhau.dll:\n"
                "    orig oplock level: %u, new level: %u, flags: %08X,\n"
                "    access: %08X, share mode: %u, iosb: %08X/%016I64X\n",
                count, out.OriginalOplockLevel, out.NewOplockLevel, out.Flags,
                out.AccessMode, out.ShareMode, iosb.Status, iosb.Information);
            iosb.Status = STATUS_PENDING;
            continue;
        }
    }
    printf("running down...\n");
    NtCancelIoFileEx(hauFile, &iosb, &iosb);
    NtClose(hauFile);

    ULONG dummy;
    if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &dummy) && GetConsoleProcessList(&dummy, 1) <= 1)
    {
        printf("press any key to continue...\n");
        _flushall();
        int c = _getch();
        if (!c || c == 0xE0)    // arrow or function key, need to read one more
            (void)_getch();
    }

    return 0;
}
