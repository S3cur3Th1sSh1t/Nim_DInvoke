import winim
import strformat
import DInvoke

const
  KERNEL32_DLL* = "kernel32.dll"
  SSPICLI_DLL* = "sspicli.dll"
  NTDLL_DLL* = "ntdll.dll"

type
  OpenProcess_t* = proc (dwDesiredAccess: DWORD, bInheritHandle: WINBOOL, dwProcessId: DWORD): HANDLE {.stdcall.}
  VirtualAllocEx_t* = proc (hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.}
  LsaGetLogonSessionData_t* = proc (LogonId: PLUID, ppLogonSessionData: ptr PSECURITY_LOGON_SESSION_DATA): BOOL {.stdcall.}
  NtOpenProcess_t* = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.stdcall.}
  NtAllocateVirtualMemory_t* = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall.}


const
  OpenProcess_FuncName * = "OpenProcess"
  VirtualAllocEx_FuncName * = "VirtualAllocEx"
  LsaGetLogonSessionData_FuncName * = "LsaGetLogonSessionData"
  NtOpenProcess_FuncName * = "NtOpenProcess"
  NtAllocateVirtualMemory_FuncName * = "NtAllocateVirtualMemory"

var MyOpenProcess*: OpenProcess_t
var MyVirtualAllocEx*: VirtualAllocEx_t
var MyLsaGetLogonSessionData*: LsaGetLogonSessionData_t
var MyNtOpenProcess*: NtOpenProcess_t
var MyNtAllocateVirtualMemory*: NtAllocateVirtualMemory_t

# Just one example to load a DLL from disk before fetching the function. Kernel32.dll and ntdll.dll are always loaded in Nim binaries. get_library_address(DLLName, TRUE)
MyLsaGetLogonSessionData = cast[LsaGetLogonSessionData_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(SSPICLI_DLL, TRUE)), LsaGetLogonSessionData_FuncName, 0, FALSE)))

if MyLsaGetLogonSessionData == nil:
  echo "[-] Failed to grab LsaGetLogonSessionData"

var newPHandle: HANDLE
var cid: CLIENT_ID
var oa: OBJECT_ATTRIBUTES
var ds: LPVOID
var sc_size: SIZE_T = cast[SIZE_T](1024)
var status: NTSTATUS
cid.UniqueProcess = GetCurrentProcessId()

MyNtOpenProcess = cast[NtOpenProcess_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(NTDLL_DLL, FALSE)), NtOpenProcess_FuncName, 0, TRUE)))

status = MyNtOpenProcess(
    &newPHandle,
    PROCESS_ALL_ACCESS, 
    &oa, &cid         
)

echo fmt"NtOpenProcess: {status}"

MyNtAllocateVirtualMemory = cast[NtAllocateVirtualMemory_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(NTDLL_DLL, FALSE)), NtAllocateVirtualMemory_FuncName, 0, TRUE)))

status = MyNtAllocateVirtualMemory(
    newPHandle, &ds, 0, &sc_size, 
    MEM_COMMIT, 
    PAGE_EXECUTE_READWRITE)

echo fmt"NtAllocateVirtualMemory: {status}"


MyOpenProcess = cast[OpenProcess_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(KERNEL32_DLL, FALSE)), OpenProcess_FuncName, 0, FALSE)))

# search by ordinal test (the ordinal number may be different on your system)
MyOpenProcess = cast[OpenProcess_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(KERNEL32_DLL, FALSE)), "", 1034, FALSE)))


if MyOpenProcess == nil:
  echo "[-] Failed to grab OpenProcess"

let processID = GetCurrentProcessId()
echo "[*] Current Process ID"
echo processID

echo "[*] Calling OpenProcess via D/Invoke"
var pHandle = MyOpenProcess(
    PROCESS_ALL_ACCESS, 
    false, 
    cast[DWORD](processID)
)

echo "[*] pHandle: ", pHandle

MyVirtualAllocEx = cast[VirtualAllocEx_t](get_function_address(cast[HMODULE](get_library_address(KERNEL32_DLL, FALSE)), VirtualAllocEx_FuncName, 0, FALSE))


echo "[*] Calling VirtualAllocEx via D/Invoke"
let rPtr = MyVirtualAllocEx(
    pHandle,
    NULL,
    cast[SIZE_T](5012),
    MEM_COMMIT,
    PAGE_EXECUTE_READ_WRITE
)
echo "[*] pHandle: ", repr(rPtr)
