#pragma once

#include "salsa20.h"

constexpr UCHAR EncryptionKey[] = { 0x48, 0x7a, 0x65, 0x90, 0xd3, 0x44, 0x5e, 0x81, 0xda, 0xf1, 0x22, 0xd7, 0xf6, 0x90, 0xce, 0x5e };

template<SIZE_T N>
struct ENCRYPTED_STRING
{
	static_assert(N <= MAX_PATH * sizeof(WCHAR), "Maximum length exceeded");
	static constexpr ULONG32 Length = N;
	ULONG64 Nonce;
	const UCHAR EncryptedData[N];

	ENCRYPTED_STRING() = default;
};

constexpr ENCRYPTED_STRING<sizeof(L"\\device\\Anti-Cheat")> EncryptedDeviceAntiyCheatString =
{
        0x58CB67FA57E51C39,
        { 0xD3, 0x63, 0xE0, 0x6E, 0xAE, 0x56, 0x49, 0xA7, 0x66, 0x2E, 0xA8, 0x36, 0x14, 0xB9, 0x88, 0x11, 0xD4, 0x43, 0x5B, 0x15, 0x01, 0x98, 0xA8, 0xDA, 0x7C, 0xBE, 0x40, 0xE6, 0x63, 0xA3, 0x68, 0x8B, 0x05, 0xBA, 0xD4, 0x67, 0x9F, 0x57 }
};

constexpr ENCRYPTED_STRING<sizeof(L"\\DosDevices\\Anti-Cheat")> EncryptedDosDevicesAntiyCheatString =
{
        0x58CB67FA57E51C3A,
        { 0xF8, 0x10, 0x66, 0xE2, 0x08, 0xAE, 0x7D, 0x7F, 0xE5, 0xAB, 0x4C, 0x55, 0x6D, 0x08, 0x73, 0x10, 0x8D, 0x76, 0x48, 0xD5, 0x7F, 0x9E, 0x20, 0x83, 0x76, 0xE7, 0xE6, 0x90, 0xD5, 0x93, 0x2E, 0xAB, 0xC4, 0x7C, 0x9F, 0xFB, 0x58, 0x6D, 0x4F, 0xD5, 0x3B, 0x8E, 0x3D, 0xE3, 0xC0, 0x2A }
};

constexpr ENCRYPTED_STRING<sizeof(L"lsass.exe")> EncryptedLsassString =
{
        0x58CB67FA57E51C3B,
        { 0x66, 0x07, 0x84, 0x78, 0xA7, 0x0A, 0x84, 0xFD, 0x5E, 0x0B, 0xBC, 0xE5, 0x3B, 0x03, 0xFA, 0x0E, 0x0F, 0xF3, 0xC2, 0xDE }
};

//Start Whitelist
constexpr ENCRYPTED_STRING<sizeof(L"System")> EncryptedSystemExeString =
{
        0x58CB67FA57E51C3C,
        { 0x8D, 0x22, 0x89, 0xBD, 0x5A, 0xBC, 0x3E, 0x74, 0xD1, 0x00, 0x4F, 0xF0, 0x47, 0xE5 }
};

constexpr ENCRYPTED_STRING<sizeof(L"csrss.exe")> EncryptedcsrssExeString =
{
        0x58CB67FA57E51C3D,
        { 0x61, 0x78, 0xB5, 0x56, 0x38, 0x96, 0x31, 0x23, 0xC0, 0x41, 0xBD, 0x75, 0x82, 0xD0, 0x1E, 0x3B, 0x5C, 0xD9, 0x7A, 0xBF }
};

constexpr ENCRYPTED_STRING<sizeof(L"svchost.exe")> EncryptedsvchostExeString =
{
        0x58CB67FA57E51C3E,
        { 0x6A, 0xF4, 0xE4, 0x34, 0x50, 0x99, 0x88, 0x5F, 0x8C, 0xF6, 0x58, 0xBB, 0x25, 0x6F, 0x6E, 0x84, 0xBD, 0x76, 0x05, 0xE4, 0x52, 0x7A, 0xB3, 0x3A }
};

constexpr ENCRYPTED_STRING<sizeof(L"explorer.exe")> EncryptedexplorerExeString =
{
        0x58CB67FA57E51C3F,
        { 0x3F, 0xAB, 0xAA, 0x34, 0x78, 0xB9, 0x95, 0xE7, 0x2D, 0xA3, 0xEB, 0xEC, 0xB2, 0x45, 0x76, 0x73, 0x0B, 0xAA, 0xA5, 0x8F, 0x3F, 0x91, 0xC6, 0x95, 0x80, 0xB9 }
};
//End WhiteList


/**
  Start BlackList
*/
constexpr CONST ENCRYPTED_STRING<sizeof(L"BlackBoneDrv10.sys")> EncryptedBlackBoneDrv10SysString =
{
        0x58CB67FA57E51C40,
        { 0xCF, 0x08, 0x07, 0xA9, 0xCD, 0x83, 0xB9, 0x28, 0xB2, 0xE4, 0x3F, 0x3C, 0xBF, 0xC1, 0xAF, 0x64, 0xE5, 0x61, 0x34, 0x47, 0x82, 0xA2, 0xD5, 0x93, 0x4D, 0x6D, 0xF8, 0x8E, 0x32, 0x0F, 0x06, 0x11, 0xA8, 0x33, 0x9B, 0xA9, 0x37, 0xD8 }
};

constexpr ENCRYPTED_STRING<sizeof(L"Extreme Injector v3.exe")> EncryptedExtremeInjectorv3ExeString =
{
        0x58CB67FA57E51C41,
        { 0xD9, 0xFC, 0xA2, 0xDA, 0xA6, 0x5C, 0xAE, 0xA8, 0x54, 0x70, 0x15, 0x40, 0x7E, 0x74, 0x4D, 0x24, 0x9F, 0x83, 0x68, 0xBC, 0x9B, 0x78, 0x77, 0xFE, 0x0B, 0x76, 0xDD, 0xDD, 0x49, 0xF1, 0xA8, 0xEB, 0xD0, 0xF6, 0x2C, 0xCB, 0x06, 0x56, 0x29, 0xAF, 0xCB, 0x28, 0xC9, 0x66, 0x59, 0x35, 0x44, 0x40 }
};

//End BlackList

//...

template<SIZE_T N>
FORCEINLINE
VOID
DecryptString(
	_In_ CONST ENCRYPTED_STRING<N>& Encrypted,
	_Out_ PCHAR Decrypted
	)
{
	constexpr ULONG32 Length = Encrypted.Length;
	PUCHAR Buffer[Length];

	RtlCopyMemory(Buffer, Encrypted.EncryptedData, Length);

	if (s20_crypt(const_cast<PUCHAR>(EncryptionKey),
		S20_KEYLEN_128,
		PUCHAR(&Encrypted.Nonce),
		0,
		reinterpret_cast<PUCHAR>(Buffer),
		Length) != S20_SUCCESS)
	{
		NT_ASSERT(FALSE);
	}

	RtlCopyMemory(Decrypted, Buffer, Length);
	RtlSecureZeroMemory(Buffer, Length); // Prevent stack leakage
}

template<SIZE_T N>
FORCEINLINE
VOID
DecryptString(
	_In_ CONST ENCRYPTED_STRING<N>& Encrypted,
	_Out_ PWCHAR Decrypted
	)
{
	DecryptString(Encrypted, reinterpret_cast<PCHAR>(Decrypted));
}
