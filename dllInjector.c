#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#define MAX_INPUT_SIZE 32
#define MAX_PATH_SIZE 128

DWORD GetProcId(CHAR[MAX_INPUT_SIZE]);
HANDLE GetKernel32Base(DWORD);

int main(void){
	CHAR processName[MAX_INPUT_SIZE];
	CHAR dllName[MAX_INPUT_SIZE];
	CHAR fullFilePath[MAX_PATH_SIZE];
	DWORD ID = -1;

	printf_s("Input process name: ");
	scanf_s("%s", processName, MAX_INPUT_SIZE);
	printf_s("Your dll name: ");
	scanf_s("%s", dllName, MAX_INPUT_SIZE);

	GetFullPathNameA(dllName, MAX_PATH_SIZE, fullFilePath, NULL);

	printf_s("[+] Got full dll path: %s\n", fullFilePath);

	ID = GetProcId(processName);

	if (ID == -1){
		puts("[-] Failed getting process ID. Exiting.");
		return 1;
	} else {
		printf_s("[+] Got process ID: %lu\n", ID);
	}
	
	HANDLE Kernel32Base = GetKernel32Base(ID);
	
	if (!Kernel32Base){
		puts("[-] Failed to get handle of target kernel32.dll. Exiting.");
		return 1;
	} else {
		puts("[+] Successfully got handle of target kernel32.dll");
	}
	
	FARPROC func = GetProcAddress(Kernel32Base, "LoadLibraryA");

	if (!func){
		puts("[-] Failed to get LoadLibraryA address. Exiting.");
		return 1;
	} else {
		printf_s("[+] Successfully found LoadLibraryA at: 0x%p\n", func);
	}
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ID);

	if (!hProcess){
		puts("[-] Failed to open target process. Exiting.");
		return 1;
	} else {
		puts("[+] Successfully opened target process");
	}
	
	LPVOID remotePath = VirtualAllocEx(hProcess, NULL, MAX_PATH_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!remotePath){
		puts("[-] Failed to allocate virtual memory in target process. Exiting.");
		CloseHandle(hProcess);
		return 1;
	} else {
		printf_s("[+] Successfully allocated virtual memory at: 0x%p\n", remotePath);
	}

	if (!WriteProcessMemory(hProcess, remotePath, fullFilePath, MAX_PATH_SIZE, NULL)){
		puts("[-] Failed to write dll path to target process memory. Exiting.");
		CloseHandle(hProcess);
		VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
		return 1;
	} else {
		puts("[+] Successfully written dll path to target memory");
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) func, remotePath, 0, NULL);

	if (!hThread){
		puts("[-] Failed to create remote thread. Exiting.");
		CloseHandle(hProcess);
		VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
		return 1;
	} else {
		puts("[+] Successfully created remote thread");
	}

	puts("Dll loaded successfully!");
	
	VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}

DWORD GetProcId(CHAR name[MAX_INPUT_SIZE]){
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = {0};
	DWORD ID = -1;
	
	pe.dwSize = sizeof(PROCESSENTRY32);
	
	Process32First(hSnap, &pe);

	do {
		if (strcmp(name, pe.szExeFile) == 0){
			ID = pe.th32ProcessID;
			break;
		}
	} while(Process32Next(hSnap, &pe));
	
	CloseHandle(hSnap);

	return ID;
}

HANDLE GetKernel32Base(DWORD PID){
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID);
	MODULEENTRY32 me = {0};

	me.dwSize = sizeof(MODULEENTRY32);
	
	Module32First(hSnap, &me);

	do{
		if (strcmp(me.szModule, "KERNEL32.DLL") == 0){
			CloseHandle(hSnap);
			return me.hModule;
		}
	} while(Module32Next(hSnap, &me));

	return NULL;
}
