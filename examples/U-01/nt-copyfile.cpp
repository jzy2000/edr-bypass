// This code demo how calling Nt routines and syscalls bypasses API hooking relying on high level API such as KernelBase!CopyFileExW
#include <windows.h>
#include <winternl.h>
#include <algorithm>
#include <vector>
#include <string>
#include <cstdio>

#pragma comment(lib, "ntdll.lib") // resolves RtlInitUnicodeString, RtlNtStatusToDosError

// Nt function pointer typedefs
typedef NTSTATUS(NTAPI* PFN_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG
    );

typedef NTSTATUS(NTAPI* PFN_NtReadFile)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
    PVOID, ULONG, PLARGE_INTEGER, PULONG
    );

typedef NTSTATUS(NTAPI* PFN_NtWriteFile)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
    PVOID, ULONG, PLARGE_INTEGER, PULONG
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);

// CopyFileExW-style progress routine typedef
typedef DWORD(WINAPI* PROGRESS_ROUTINE)(
    LARGE_INTEGER TotalFileSize,
    LARGE_INTEGER TotalBytesTransferred,
    LARGE_INTEGER StreamSize,
    LARGE_INTEGER StreamBytesTransferred,
    DWORD dwStreamNumber,
    DWORD dwCallbackReason,
    HANDLE hSourceFile,
    HANDLE hDestinationFile,
    LPVOID lpData
    );

// Convert DOS or \\?\ path to native \??\ path
static std::wstring ToNativePath(const std::wstring& dosPath) {
    if (dosPath.rfind(L"\\\\?\\", 0) == 0) {
        return L"\\??\\" + dosPath.substr(4);
    }
    return L"\\??\\" + dosPath;
}

// Nt API loader
struct NtApi {
    PFN_NtCreateFile NtCreateFile = nullptr;
    PFN_NtReadFile   NtReadFile = nullptr;
    PFN_NtWriteFile  NtWriteFile = nullptr;
    PFN_NtClose      NtClose = nullptr;

    bool Load() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) ntdll = LoadLibraryW(L"ntdll.dll");
        if (!ntdll) return false;

        NtCreateFile = reinterpret_cast<PFN_NtCreateFile>(GetProcAddress(ntdll, "NtCreateFile"));
        NtReadFile = reinterpret_cast<PFN_NtReadFile>(GetProcAddress(ntdll, "NtReadFile"));
        NtWriteFile = reinterpret_cast<PFN_NtWriteFile>(GetProcAddress(ntdll, "NtWriteFile"));
        NtClose = reinterpret_cast<PFN_NtClose>(GetProcAddress(ntdll, "NtClose"));

        return NtCreateFile && NtReadFile && NtWriteFile && NtClose;
    }
};

// Minimal CopyFileExW-like function
BOOL CopyFileNtExW(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    PROGRESS_ROUTINE lpProgressRoutine, // optional
    LPVOID lpData,                      // optional
    LPBOOL pbCancel,                    // optional
    DWORD dwCopyFlags                   // supports COPY_FILE_FAIL_IF_EXISTS (0x00000001)
) {
    if (!lpExistingFileName || !lpNewFileName) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    NtApi nt;
    if (!nt.Load()) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    const bool failIfExists = (dwCopyFlags & 0x00000001) != 0; // COPY_FILE_FAIL_IF_EXISTS

    // Build native paths for NtCreateFile
    std::wstring srcNative = ToNativePath(lpExistingFileName);
    std::wstring dstNative = ToNativePath(lpNewFileName);

    UNICODE_STRING srcUS, dstUS;
    RtlInitUnicodeString(&srcUS, srcNative.c_str());
    RtlInitUnicodeString(&dstUS, dstNative.c_str());

    OBJECT_ATTRIBUTES srcOA;
    InitializeObjectAttributes(&srcOA, &srcUS, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    OBJECT_ATTRIBUTES dstOA;
    InitializeObjectAttributes(&dstOA, &dstUS, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    IO_STATUS_BLOCK iosSrc = {}, iosDst = {};
    HANDLE hSrc = nullptr, hDst = nullptr;

    // Open source
    NTSTATUS st = nt.NtCreateFile(
        &hSrc,
        FILE_GENERIC_READ | SYNCHRONIZE,
        &srcOA,
        &iosSrc,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr,
        0
    );
    if (st < 0) {
        SetLastError(RtlNtStatusToDosError(st));
        return FALSE;
    }

    // Create/overwrite destination
    ULONG createDisp = failIfExists ? FILE_CREATE : FILE_OVERWRITE_IF;
    st = nt.NtCreateFile(
        &hDst,
        FILE_GENERIC_WRITE | SYNCHRONIZE,
        &dstOA,
        &iosDst,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        0, // no share
        createDisp,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr,
        0
    );
    if (st < 0) {
        nt.NtClose(hSrc);
        SetLastError(RtlNtStatusToDosError(st));
        return FALSE;
    }

    // File size via Win32 (avoids NtQueryInformationFile portability issues)
    LARGE_INTEGER totalSize = {};
    if (!GetFileSizeEx(hSrc, &totalSize)) {
        nt.NtClose(hDst);
        nt.NtClose(hSrc);
        return FALSE;
    }

    const ULONG kChunk = 1 << 20; // 1MB
    std::vector<BYTE> buf(kChunk);
    LARGE_INTEGER offset = {};
    LARGE_INTEGER bytesTransferred = {};

    while (offset.QuadPart < totalSize.QuadPart) {
        if (pbCancel && *pbCancel) {
            FILE_END_OF_FILE_INFO info = {};
            info.EndOfFile = bytesTransferred;
            SetFileInformationByHandle(hDst, FileEndOfFileInfo, &info, sizeof(info));
            nt.NtClose(hDst);
            nt.NtClose(hSrc);
            SetLastError(ERROR_OPERATION_ABORTED);
            return FALSE;
        }

        const ULONG toRead = static_cast<ULONG>(
            std::min<ULONGLONG>(kChunk, totalSize.QuadPart - offset.QuadPart)
            );

        IO_STATUS_BLOCK iosR = {};
        st = nt.NtReadFile(hSrc, nullptr, nullptr, nullptr, &iosR, buf.data(), toRead, &offset, nullptr);
        if (st < 0) {
            nt.NtClose(hDst);
            nt.NtClose(hSrc);
            SetLastError(RtlNtStatusToDosError(st));
            return FALSE;
        }

        const ULONG read = static_cast<ULONG>(iosR.Information);
        if (read == 0) break;

        IO_STATUS_BLOCK iosW = {};
        st = nt.NtWriteFile(hDst, nullptr, nullptr, nullptr, &iosW, buf.data(), read, &offset, nullptr);
        if (st < 0) {
            nt.NtClose(hDst);
            nt.NtClose(hSrc);
            SetLastError(RtlNtStatusToDosError(st));
            return FALSE;
        }

        const ULONG written = static_cast<ULONG>(iosW.Information);
        offset.QuadPart += static_cast<LONGLONG>(written);
        bytesTransferred.QuadPart += static_cast<LONGLONG>(written);

        if (lpProgressRoutine) {
            DWORD res = lpProgressRoutine(
                totalSize,
                bytesTransferred,
                totalSize,
                bytesTransferred,
                1,
                CALLBACK_CHUNK_FINISHED, // from winbase.h
                hSrc,
                hDst,
                lpData
            );
            if (res == PROGRESS_CANCEL) { // from winbase.h
                FILE_END_OF_FILE_INFO info2 = {};
                info2.EndOfFile = bytesTransferred;
                SetFileInformationByHandle(hDst, FileEndOfFileInfo, &info2, sizeof(info2));
                nt.NtClose(hDst);
                nt.NtClose(hSrc);
                SetLastError(ERROR_OPERATION_ABORTED);
                return FALSE;
            }
        }
    }

    // Ensure EOF = bytes written
    FILE_END_OF_FILE_INFO infoFinal = {};
    infoFinal.EndOfFile = bytesTransferred;
    SetFileInformationByHandle(hDst, FileEndOfFileInfo, &infoFinal, sizeof(infoFinal));

    nt.NtClose(hDst);
    nt.NtClose(hSrc);
    return TRUE;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        wprintf(L"Usage: copy_nt_min <src> <dst>\n");
        return 1;
    }

    BOOL cancel = FALSE;

    auto cb = [](LARGE_INTEGER total, LARGE_INTEGER done,
        LARGE_INTEGER streamSize, LARGE_INTEGER streamDone,
        DWORD streamNumber, DWORD reason,
        HANDLE hSrc, HANDLE hDst, LPVOID data) -> DWORD {
            const double pct = (total.QuadPart != 0)
                ? (100.0 * static_cast<double>(done.QuadPart) / static_cast<double>(total.QuadPart))
                : 100.0;
            wprintf(L"Progress: %.1f%%\n", pct);
            return 0; // continue
    };

    if (!CopyFileNtExW(argv[1], argv[2], cb, nullptr, &cancel, 0)) {
        wprintf(L"Copy failed: %lu\n", GetLastError());
        return 2;
    }
    wprintf(L"Copy completed.\n");
    return 0;
}
