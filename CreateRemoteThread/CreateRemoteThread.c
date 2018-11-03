#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    

	DWORD dwPID				= NULL;

	LPCSTR szDLL			= NULL;
	LPVOID pRemoteAddr		= NULL;	
	LPVOID libAddr			= NULL;
		
	HANDLE hThread			= INVALID_HANDLE_VALUE;
	HANDLE hProcess			= INVALID_HANDLE_VALUE;

	if(argc < 2) {
		printf("[+] usage: Injects.exe [PID] [PATH]\n");
		return -1;
	}

	dwPID = atoi(argv[1]);
	szDLL = argv[2];
	
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

		hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)libAddr, pRemoteAddr, 0, NULL);
		if (hThread == NULL) {
			puts("failed CreateRemoteThread function");
			return -1;
		}

		puts("[*] Success DLL Injection...!"); 

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);
		CloseHandle(hProcess);
	}

	return 0;
}