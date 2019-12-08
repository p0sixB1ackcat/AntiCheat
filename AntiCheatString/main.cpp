#include "ntdll.h"
#include "util.h"
#include <ntstatus.h>
#include <strings.h>
#include "parser.h"

typedef UNICODE_STRING StringType; // Set to either ANSI_STRING or UNICODE_STRING; don't mix different string types in one run.

static constexpr const ULONG64 StartNonce = 0x58cb67fa57e51c39; // Set this to (last used nonce + 1) prior to running this
/*
static constexpr const StringType InputStrings[] = // Input strings to encrypt. First string will have nonce == StartNonce, the next will have StartNonce + 1... etc.
{
	RTL_CONSTANT_ANSI_STRING("EtwpCreateEtwThread"),
	RTL_CONSTANT_ANSI_STRING("RtlActivateActivationContextEx"),
	RTL_CONSTANT_ANSI_STRING("RtlCreateActivationContext"),
	RTL_CONSTANT_ANSI_STRING("RtlQueryActivationContextApplicationSettings"),
	RTL_CONSTANT_ANSI_STRING("RtlValidateHeap"),
	RTL_CONSTANT_ANSI_STRING("TpStartAsyncIoOperation"),
	RTL_CONSTANT_ANSI_STRING("TpWaitForWork"),
	RTL_CONSTANT_ANSI_STRING("WinSqmEventWrite")
};
*/
static constexpr const StringType UniStrings[] =
{
    RTL_CONSTANT_STRING(L"\\device\\Anti-Cheat"),
    RTL_CONSTANT_STRING(L"\\DosDevices\\Anti-Cheat"),
    RTL_CONSTANT_STRING(L"lsass.exe"),
    RTL_CONSTANT_STRING(L"System"),
    RTL_CONSTANT_STRING(L"csrss.exe"),
    RTL_CONSTANT_STRING(L"svchost.exe"),
    RTL_CONSTANT_STRING(L"explorer.exe"),
    RTL_CONSTANT_STRING(L"BlackBoneDrv10.sys"),
    RTL_CONSTANT_STRING(L"Extreme Injector v3.exe"),
};

int wmain()
{
    const char* pIniFilePath = TEXT("H:\\Soft\\x64dbg\\release\\x64\\x64dbg.ini");
    char pBuffer[MAX_PATH] = { 0x00 };
    int dwError = 0;
    int dwFileSize = 0;
    unsigned char* pFileStream = NULL;

    FILE* pFile = fopen(pIniFilePath, "rb");
    if (pFile)
    {
        fseek(pFile, 0, SEEK_END);
        dwFileSize = ftell(pFile);
        fseek(pFile, 0, SEEK_SET);

        pFileStream = (unsigned char*)malloc(dwFileSize);
        if (pFileStream)
        {
            memset(pFileStream, 0x00, dwFileSize);
            fread(pFileStream,dwFileSize,1,pFile);
            IniParserInit((char*)pFileStream, dwFileSize);
            dwError = GetIniString((PCHAR)"TabOrder", pBuffer, sizeof(pBuffer) / sizeof(pBuffer[0]));
        }
    }

    

	NTSTATUS Status = STATUS_SUCCESS;
	ULONG64 Nonce = StartNonce;

	for (ULONG i = 0; i < ARRAYSIZE(UniStrings); ++i)
	{
		const ULONG Length = static_cast<ULONG>(UniStrings[i].MaximumLength); // sizeof() for both CHAR and WCHAR, i.e. size in bytes incl. null terminator
		const PUCHAR PlainTextBuffer = reinterpret_cast<PUCHAR>(UniStrings[i].Buffer);
		const PUCHAR Encrypted = static_cast<PUCHAR>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Length));
		RtlCopyMemory(Encrypted, PlainTextBuffer, Length);

		if (s20_crypt(const_cast<PUCHAR>(EncryptionKey),
					S20_KEYLEN_128,
					PUCHAR(&Nonce),
					0,
					Encrypted,
					Length) != S20_SUCCESS)
		{
			Printf(L"Encryption failure\n");
			__debugbreak();
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		// Print C++ declaration for easy copy/pasting
		if constexpr (sizeof(StringType::Buffer[0]) == sizeof(WCHAR))
			// ReSharper disable once CppUnreachableCode // What the fuck do you think constexpr stands for Resharper
			Printf(L"CONSTEXPR CONST ENCRYPTED_STRING<sizeof(L\"%ls\")> Encrypted%lsString =\n",
				reinterpret_cast<PWCHAR>(PlainTextBuffer), reinterpret_cast<PWCHAR>(PlainTextBuffer));
		else
			// ReSharper disable once CppUnreachableCode
			Printf(L"CONSTEXPR CONST ENCRYPTED_STRING<sizeof(\"%hs\")> Encrypted%hsString =\n",
				reinterpret_cast<PCHAR>(PlainTextBuffer), reinterpret_cast<PCHAR>(PlainTextBuffer));
		Printf(L"{\n\t0x%p,\n\t{ ", reinterpret_cast<PVOID>(Nonce));
		for (ULONG j = 0; j < Length; ++j)
			Printf(L"0x%02X%ls", Encrypted[j], j < Length - 1 ? L", " : L" ");
		Printf(L"}\n};\n\n");

		// Free buffer and increment nonce by 1 for next string
		RtlFreeHeap(RtlProcessHeap(), 0, Encrypted);
		Nonce++;
	}

	Printf(L"\nPress any key to exit.\n");
	WaitForKey();
	return NtTerminateProcess(NtCurrentProcess, Status);
}
