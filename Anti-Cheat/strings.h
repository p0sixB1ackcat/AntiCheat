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

//Start Whitelist
constexpr ENCRYPTED_STRING<sizeof(L"steam.exe")> EncryptedsteamExeString =
{
        0x58CB67FA57E51C3B,
        { 0x79, 0x07, 0x83, 0x78, 0xA3, 0x0A, 0x96, 0xFD, 0x40, 0x0B, 0xBC, 0xE5, 0x3B, 0x03, 0xFA, 0x0E, 0x0F, 0xF3, 0xC2, 0xDE }
};

constexpr ENCRYPTED_STRING<sizeof(L"akros.exe")> EncryptedakrosExeString =
{
        0x58CB67FA57E51C3C,
        { 0xBF, 0x22, 0x9B, 0xBD, 0x5B, 0xBC, 0x25, 0x74, 0xC7, 0x00, 0x0C, 0xF0, 0x22, 0xE5, 0xA5, 0x02, 0x33, 0x64, 0x08, 0x58 }
};

constexpr ENCRYPTED_STRING<sizeof(L"akroslauncher.exe")> EncryptedakroslauncherExeString =
{
        0x58CB67FA57E51C3D,
        { 0x63, 0x78, 0xAD, 0x56, 0x38, 0x96, 0x2D, 0x23, 0xC0, 0x41, 0xFF, 0x75, 0x86, 0xD0, 0x13, 0x3B, 0x57, 0xD9, 0x19, 0xBF, 0xCC, 0xF0, 0xE6, 0xC8, 0xF3, 0xB5, 0x49, 0x94, 0xA3, 0xD4, 0x82, 0x1A, 0xD8, 0x02, 0xF6, 0x7C }
};

constexpr ENCRYPTED_STRING<sizeof(L"csrss.exe")> EncryptedcsrssExeString =
{
        0x58CB67FA57E51C3E,
        { 0x7A, 0xF4, 0xE1, 0x34, 0x41, 0x99, 0x93, 0x5F, 0x90, 0xF6, 0x05, 0xBB, 0x34, 0x6F, 0x38, 0x84, 0xBD, 0x76, 0x7D, 0xE4 }
};

//End WhiteList


/**
  Start BlackList
*/
constexpr ENCRYPTED_STRING<sizeof(L"BlackBoneDrv10.sys")> EncryptedBlackBoneDrv10SysString =
{
        0x58CB67FA57E51C3F,
        { 0x18, 0xAB, 0xBE, 0x34, 0x69, 0xB9, 0x9A, 0xE7, 0x29, 0xA3, 0xDB, 0xEC, 0xB8, 0x45, 0x6A, 0x73, 0x40, 0xAA, 0x84, 0x8F, 0x35, 0x91, 0xD5, 0x95, 0xB1, 0xB9, 0x12, 0xEE, 0xC2, 0x58, 0xAF, 0xBA, 0x33, 0xBD, 0x92, 0xCA, 0xB1, 0x8D }
};

constexpr ENCRYPTED_STRING<sizeof(L"x64dbg.exe")> Encryptedx64dbgExeString =
{
        0x58CB67FA57E51C40,
        { 0xF5, 0x08, 0x5D, 0xA9, 0x98, 0x83, 0xBE, 0x28, 0xBB, 0xE4, 0x1A, 0x3C, 0xFE, 0xC1, 0xA4, 0x64, 0xF8, 0x61, 0x15, 0x47, 0xF0, 0xA2 }
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
