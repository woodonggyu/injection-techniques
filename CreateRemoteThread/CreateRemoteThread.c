#include "stdio.h"
#include "windows.h"


int main(int argc, char *argv[]) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    

	DWORD dwPID				= NULL;

	LPCSTR szDLL			= NULL;
	LPVOID pRemoteAddr		= NULL;	
	LPVOID libAddr			= NULL;
		
	HANDLE hThread			= INVALID_HANDLE_VALUE;
	HANDLE hProcess			= INVALID_HANDLE_VALUE;

	if(argv[1] == NULL || argv[2] == NULL) {
		printf("[+] usage: Injects.exe [PID] [PATH]\n");
		return 1;
	}

	dwPID = atoi(argv[1]);
	szDLL = argv[2];
	
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwPID);
	if (hProcess) {
		
		pRemoteAddr = VirtualAllocEx(hProcess, NULL, strlen(szDLL) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		puts("[+] Initialized Memory Allocation");

		WriteProcessMemory(hProcess, pRemoteAddr, (LPVOID)szDLL, strlen(szDLL) + 1, NULL);
		puts("[+] Written DLL_FULL_PATH to Memory");

		libAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		printf("[+] LoadLibraryA() Addr = 0x%p\n", libAddr);

		hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)libAddr, pRemoteAddr, 0, NULL);
		puts("[*] Create Remote Thread...!");
		puts("[*] Success DLL Injection...!"); 

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
}