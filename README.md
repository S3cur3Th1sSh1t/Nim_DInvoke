# Nim_DInvoke
D/Invoke via Nim

All Nim binaries typically expose the same 58-60 Windows API functions:

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Nim_DInvoke/main/images/ExposedFunctions.PNG)

All other Windows API functions are typically resolved on runtime via `GetProcAddress` and `LoadLibraryA` as mentioned in [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim#opsec-considerations) or [this blog post](https://web.archive.org/web/20210117002945/https://secbytes.net/implant-roulette-part-1:-nimplant/).

So, it's not possible to hide API imports (completely) via DInvoke in Nim, unless someone for example uses e.g. this DInvoke implementaion to modify the Nim compiler for DInvoke usage instead of Dynlib.

Manually parsing the functions from PEB instead of using `GetProcAddress` and `LoadLibraryA` is still stealthier than the default Nim behaviour. To also avoid inline hooking for example manual mapping of a fresh DLL copy would be needed as mentioned in [TheWovers DInvoke blog post](https://thewover.github.io/Dynamic-Invoke/):

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Nim_DInvoke/main/images/ExposedFunctions.PNG)

This is - however - not implemented here `yet`. I'm currently only using `LdrLoadDll` to load new DLL's into memory.

This project was heavily inspired by the [NanoDump](https://github.com/helpsystems/nanodump/blob/main/source/dinvoke.c) D/Invoke code.

The function can than be used like this:

```cpp
const
  KERNEL32_DLL* = "kernel32.dll"
const
  OpenProcess_FuncName * = "OpenProcess"
type
  OpenProcess_t* = proc (dwDesiredAccess: DWORD, bInheritHandle: WINBOOL, dwProcessId: DWORD): HANDLE {.stdcall.}

MyOpenProcess = cast[OpenProcess_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(KERNEL32_DLL, FALSE)), OpenProcess_FuncName, 0)))

echo "[*] Calling OpenProcess via D/Invoke"
let pHandle = MyOpenProcess(
    PROCESS_ALL_ACCESS, 
    false, 
    cast[DWORD](processID)
)
```

In my testings I faced strange behaviours for some API functions, which need special cases to find the correct relative address. My confusion can be found in the comments. Maybe that's also just my trash coding style - who knows.

The example, when successfully looks like the following:

![alt text](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Nim_DInvoke/main/images/Example.PNG)