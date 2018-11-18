#include <Windows.h>

typedef NTSTATUS(WINAPI* fnNtUnmapViewOfSection) (
	HANDLE	ProcessHandle,
	PVOID	BaseAddress
);

typedef struct _MAPPEDFILE {
	HANDLE	hFile;
	HANDLE	hMapfile;
	DWORD	dwFileSize;
	LPVOID	lpView;
} MAPPEDFILE, *PMAPPEDFILE;


