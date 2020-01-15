#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// PTE protection values
//
#define MM_ZERO_ACCESS				0
#define MM_READONLY					1
#define MM_EXECUTE					2
#define MM_EXECUTE_READ				3
#define MM_READWRITE				4
#define MM_WRITECOPY				5
#define MM_EXECUTE_READWRITE		6
#define MM_EXECUTE_WRITECOPY		7

#define MM_NOCACHE					0x8
#define MM_GUARD_PAGE				0x10
#define MM_DECOMMIT					0x10 // NO_ACCESS, Guard page
#define MM_NOACCESS					0x18 // NO_ACCESS, Guard_page, nocache

#define MM_PTE_VALID_MASK			0x1
#define MM_PTE_WRITE_MASK			0x800
#define MM_PTE_OWNER_MASK			0x4
#define MM_PTE_WRITE_THROUGH_MASK	0x8
#define MM_PTE_CACHE_DISABLE_MASK	0x10
#define MM_PTE_ACCESS_MASK			0x20
#define MM_PTE_DIRTY_MASK			0x42
#define MM_PTE_LARGE_PAGE_MASK		0x80
#define MM_PTE_GLOBAL_MASK			0x100
#define MM_PTE_COPY_ON_WRITE_MASK	0x200
#define MM_PTE_PROTOTYPE_MASK		0x400
#define MM_PTE_TRANSITION_MASK		0x800

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED		0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH		0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER		0x00000004

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#ifndef KI_USER_SHARED_DATA
#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64
#endif

#ifndef SharedUserData
#define SharedUserData ((KUSER_SHARED_DATA *const)KI_USER_SHARED_DATA)
#endif

#ifndef PTE_SHIFT
#define PTE_SHIFT 3
#endif
#ifndef PTI_SHIFT
#define PTI_SHIFT 12
#endif
#ifndef PDI_SHIFT
#define PDI_SHIFT 21
#endif
#ifndef PPI_SHIFT
#define PPI_SHIFT 30
#endif
#ifndef PXI_SHIFT
#define PXI_SHIFT 39
#endif

#ifdef _WIN64
#ifndef PXE_BASE
#define PXE_BASE 0xFFFFF6FB7DBED000UI64
#endif
#ifndef PXE_SELFMAP
#define PXE_SELFMAP 0xFFFFF6FB7DBEDF68UI64
#endif
#ifndef PPE_BASE
#define PPE_BASE 0xFFFFF6FB7DA00000UI64
#endif
#endif
#ifndef PDE_BASE
#ifdef _WIN64
#define PDE_BASE 0xFFFFF6FB40000000UI64
#else
#define PDE_BASE 0xC0600000 // 0xc0300000 for x86 without PAE
#endif
#endif
#ifndef PTE_BASE
#ifdef _WIN64
#define PTE_BASE 0xFFFFF68000000000UI64
#else
#define PTE_BASE 0xC0000000
#endif
#endif

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define MiGetPxeOffset(va) \
	((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))

#ifdef _WIN64
#define MiGetPxeAddress(va) \
	((PMMPTE)PXE_BASE + MiGetPxeOffset(va))

#define MiGetPpeAddress(va) \
	((PMMPTE)(((((ULONG_PTR)(va)&VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + PPE_BASE)) // PPE_BASE is probably also relocated, and we don't have it
#endif

#define MiGetPdeAddress(va) \
	((PMMPTE)(((((ULONG_PTR)(va)&VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + DynData.DYN_PDE_BASE))

#define MiGetPteAddress(va) \
	((PMMPTE)(((((ULONG_PTR)(va)&VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + DynData.DYN_PTE_BASE))

// Obsolete/incorrect for Windows 10 >= RS1
#ifdef _WIN64
#define MI_IS_PHYSICAL_ADDRESS(Va)							\
	((MiGetPxeAddress(Va)->u.Hard.Valid == 1) &&			\
		(MiGetPpeAddress(Va)->u.Hard.Valid == 1) &&			\
		((MiGetPdeAddress(Va)->u.Long & 0x81) == 0x81) ||	\
	(MiGetPteAddress(Va)->u.Hard.Valid == 1))
#else
#define MI_IS_PHYSICAL_ADDRESS(Va)							\
	((MiGetPdeAddress(Va)->u.Long & 0x81) == 0x81 ||		\
	(MiGetPteAddress(Va)->u.Hard.Valid == 1))
#endif

typedef ULONG WIN32_PROTECTION_MASK;
typedef PULONG PWIN32_PROTECTION_MASK;

typedef struct _UNLOADED_DRIVER
{
	UNICODE_STRING Name;
	PVOID StartAddress;
	PVOID EndAddress;
	LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVER, *PUNLOADED_DRIVER;

typedef struct _PIDDBCACHE_ENTRY
{
	LIST_ENTRY List;
	UNICODE_STRING DriverName;
	ULONG TimeDateStamp;
	NTSTATUS LoadStatus;
	CHAR Data[16];
} PIDDBCACHE_ENTRY, *PPIDDBCACHE_ENTRY;

typedef enum _WinVer
{
	WINVER_7		= 0x0610,
	WINVER_7_SP1	= 0x0611,
	WINVER_8		= 0x0620, // Unsupported
	WINVER_81		= 0x0630,
	WINVER_10		= 0x0A00, // 10.0.10240.0 - RTM (Unsupported)
	WINVER_10_RS1	= 0x0A01, // 10.0.14393.0 - Anniversary update (Unsupported)
	WINVER_10_RS2	= 0x0A02, // 10.0.15063.0 - Creator's update (Unsupported)
	WINVER_10_RS3	= 0x0A03, // 10.0.16299.0 - Fall creator's update
	WINVER_10_RS4	= 0x0A04, // 10.0.17134.0 - Spring creator's update
	WINVER_10_RS5	= 0x0A05, // 10.0.17763.0 - October 2018 update
	WINVER_10_19H1	= 0x0A06, // 10.0.18362.0 - May 2019 update
	WINVER_10_19H2  = 0x0A07, // 10.0.18363.0 - Fall creator's update
} WinVer;

// Version dependent offsets
typedef struct _DYNAMIC_DATA
{
	WinVer Version; // OS version

	ULONG ProtectionOffset;					// EPROCESS::Protection
	ULONG ObjectTableOffset;				// EPROCESS::ObjectTable
	ULONG EProcessFlagsOffset;				// EPROCESS::Flags
	ULONG EProcessFlags2Offset;				// EPROCESS::Flags2
	
} SYSTEM_DYNAMIC_DATA, *PSYSTEM_DYNAMIC_DATA;

NTSTATUS
InitDynamicData(
	_Out_ PSYSTEM_DYNAMIC_DATA pData
	);

#ifdef __cplusplus
}
#endif
