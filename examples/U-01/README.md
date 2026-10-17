# U-01 worked episode

Compare a Win32 copy with a native-API copy of the same bytes. [nt-copyfile.cpp](nt-copyfile.cpp) is the native half. The Win32 half is `CopyFileExW` on the same source and a second destination.

Build `nt-copyfile.cpp` with the Windows SDK as a console program:

```
cl /EHsc /W4 /nologo nt-copyfile.cpp /link ntdll.lib /OUT:copy_nt_min.exe
```

Or with MinGW: `x86_64-w64-mingw32-g++ -o copy_nt_min.exe nt-copyfile.cpp -lntdll`.

Point both copies at files under a directory the sensor watches, using paths from `lab/local.yaml`. Do not commit those paths.

Score the run from the product log:

- Hold: both copies are logged or blocked.
- Miss: only the Win32 copy is visible.
- Inconclusive: the file sensor is off, or the process token is SYSTEM.

Delete both destination files before the next card.
