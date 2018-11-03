#include <stdio.h>
#include <Windows.h>


typedef DWORD(WINAPI *PFNTCREATETHREADEX) (
	PHANDLE					ThreadHandle,
	ACCESS_MASK				DesiredAccess,
	LPVOID					ObjectAttributes,
	HANDLE					ProcessHandle,
	LPTHREAD_START_ROUTINE	lpStartAddress,
	LPVOID					lpParameter,
	BOOL					CreateSuspended,
	DWORD					dwStackSize,
	DWORD					dw1,
	DWORD					dw2,
	LPVOID					Unknown
);


int set_privileges(void) {

	TOKEN_PRIVILEGES tPriv = { 0 };
	HANDLE hToken = NULL;
	
	LUID luid = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			tPriv.PrivilegeCount = 1;
			tPriv.Privileges[0].Luid = luid;
			tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			
			if (AdjustTokenPrivileges(hToken, FALSE, &tPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL) == 0) {
				printf("[!] AdjustTokenPrivileges Error. [%d]\n", GetLastError());
				return -1;
			}
		}
	}

	return 1;
}


int main(int argc, char *argv[]) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    

	DWORD dwPID				= NULL;

	LPCSTR szDLL			= NULL;
	LPVOID pRemoteAddr		= NULL;	
	LPVOID libAddr			= NULL;

	FARPROC	pFunc			= NULL;
		
	HANDLE hThread			= INVALID_HANDLE_VALUE;
	HANDLE hProcess			= INVALID_HANDLE_VALUE;


	if(argc < 2) {
		printf("[+] usage: Injects.exe [PID] [PATH]\n");
		return -1;
	}

	dwPID = atoi(argv[1]);
	szDLL = argv[2];

	if (!set_privileges()) {
		printf("[-] failed get privileges\n");
		return -1;
	}
	
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwPID);
	if (hProcess) {
		
		pRemoteAddr = VirtualAllocEx(hProcess, NULL, strlen(szDLL) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pRemoteAddr == NULL) {
			puts("[-] failed VirtualAllocEx function");
			return -1;
		}

		puts("[+] Initialized Memory Allocation");

		if (WriteProcessMemory(hProcess, pRemoteAddr, (LPVOID)szDLL, strlen(szDLL) + 1, NULL) == 0) {
			puts("[-] failed WriteProcessMemory function");
			return -1;
		}
		
		puts("[+] Written DLL_FULL_PATH to Memory");

		libAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (libAddr == NULL) {
			puts("[-] failed GetProcAddress function");
			return -1;
		}
		
		printf("[+] LoadLibraryA() Addr = 0x%p\n", libAddr);

		// NtCreateThreadEx Function
		pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		if (pFunc == NULL) {
			puts("failed GetProcAddress Function");
			return -1;
		}

		((PFNTCREATETHREADEX)pFunc)(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)libAddr, pRemoteAddr, FALSE, NULL, NULL, NULL, NULL);
		if (hThread == NULL) {
			puts("[!] failed NtCreateThreadEx function");
			return -1;
		}

		puts("[*] Success DLL Injection"); 

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);
		CloseHandle(hProcess);
	}

	return 0;
}