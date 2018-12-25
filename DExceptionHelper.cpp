#include <string.h>
#include <iostream>
#include "DExceptionHelper.h"

#pragma warning(push)
#pragma warning(disable : 4311 4312 4313)
#pragma message("Disabled warnings for C4311 C4312 C4313")

#ifdef _DEBUG
#define MAX_STACKFRAME -1
#else
#define MAX_STACKFRAME 1024
#endif

#if defined(_MT) //&& !defined(_DLL)
extern "C"
{
	// merged from VC 6 and .NET internal headers in CRT source code
#pragma pack(push)
#pragma pack(4)

#if _MSC_VER >= 1300
	#define MAX_LANG_LEN        64  /* max language name length */
	#define MAX_CTRY_LEN        64  /* max country name length */
	#define MAX_MODIFIER_LEN    0   /* max modifier name length - n/a */
	#define MAX_LC_LEN          (MAX_LANG_LEN+MAX_CTRY_LEN+MAX_MODIFIER_LEN+3)
	                                /* max entire locale string length */
	#define MAX_CP_LEN          16  /* max code page name length */
	#define CATNAMES_LEN        57  /* "LC_COLLATE=;LC_CTYPE=;..." length */

	#define LC_INT_TYPE         0
	#define LC_STR_TYPE         1

	#ifndef _SETLOC_STRUCT_DEFINED
	struct _is_ctype_compatible {
	        unsigned long id;
	        int is_clike;
	};
	typedef struct setloc_struct {
	    /* getqloc static variables */
	    char *pchLanguage;
	    char *pchCountry;
	    int iLcidState;
	    int iPrimaryLen;
	    BOOL bAbbrevLanguage;
	    BOOL bAbbrevCountry;
	    LCID lcidLanguage;
	    LCID lcidCountry;
	    /* expand_locale static variables */
	    LC_ID       _cacheid;
	    UINT        _cachecp;
	    char        _cachein[MAX_LC_LEN];
	    char        _cacheout[MAX_LC_LEN];
	    /* _setlocale_set_cat (LC_CTYPE) static variable */
	    struct _is_ctype_compatible _Lcid_c[5];
	} _setloc_struct, *_psetloc_struct;
	#define _SETLOC_STRUCT_DEFINED
	#endif  /* _SETLOC_STRUCT_DEFINED */
#endif

	struct _tiddata
	{
		unsigned long   _tid;       /* thread ID */


		unsigned long   _thandle;   /* thread handle */

		int     _terrno;            /* errno value */
		unsigned long   _tdoserrno; /* _doserrno value */
		unsigned int    _fpds;      /* Floating Point data segment */
		unsigned long   _holdrand;  /* rand() seed value */
		char *      _token;         /* ptr to strtok() token */
		wchar_t *   _wtoken;        /* ptr to wcstok() token */
		unsigned char * _mtoken;    /* ptr to _mbstok() token */

		/* following pointers get malloc'd at runtime */
		char *      _errmsg;        /* ptr to strerror()/_strerror()  buff */
#if _MSC_VER >= 1300
		wchar_t *   _werrmsg;       /* ptr to _wcserror()/__wcserror() buff */
#endif
		char *      _namebuf0;      /* ptr to tmpnam() buffer */
		wchar_t *   _wnamebuf0;     /* ptr to _wtmpnam() buffer */
		char *      _namebuf1;      /* ptr to tmpfile() buffer */
		wchar_t *   _wnamebuf1;     /* ptr to _wtmpfile() buffer */
		char *      _asctimebuf;    /* ptr to asctime() buffer */
		wchar_t *   _wasctimebuf;   /* ptr to _wasctime() buffer */
		void *      _gmtimebuf;     /* ptr to gmtime() structure */
		char *      _cvtbuf;        /* ptr to ecvt()/fcvt buffer */

#if _MSC_VER >= 1300
		unsigned char _con_ch_buf[MB_LEN_MAX];
									/* ptr to putch() buffer */
		unsigned short _ch_buf_used;/* if the _con_ch_buf is used */
#endif

		/* following fields are needed by _beginthread code */
		void *      _initaddr;      /* initial user thread address */
		void *      _initarg;       /* initial user thread argument */

		/* following three fields are needed to support signal handling and
		 * runtime errors */
		void *      _pxcptacttab;   /* ptr to exception-action table */
		void *      _tpxcptinfoptrs; /* ptr to exception info pointers*/
		int         _tfpecode;      /* float point exception code */

#if _MSC_VER >= 1300
		/* pointer to the copy of the multibyte character information used by the thread */
		/*pthreadmbcinfo*/ void *  ptmbcinfo;

		/* pointer to the copy of the locale informaton used by the thead */
		/*pthreadlocinfo*/ void *  ptlocinfo;
		int         _ownlocale;     /* if 1, this thread owns its own locale */
#endif

		/* following field is needed by NLG routines */
		unsigned long   _NLG_dwCode;

		/*
		 * Per-Thread data needed by C++ Exception Handling
		 */
		void *      _terminate;     /* terminate() routine */
		void *      _unexpected;    /* unexpected() routine */
		void *      _translator;    /* S.E. translator */
#if _MSC_VER >= 1300
		void *      _purecall;      /* called when pure virtual happens */
#endif
		void *      _curexception;  /* current exception */
		void *      _curcontext;    /* current exception context */
#if _MSC_VER >= 1300
		int         _ProcessingThrow; /* for uncaught_exception */
		void *      _curexcspec;    /* for handling exceptions thrown from std::unexpected */
#endif
#if defined (_M_IA64) || defined (_M_AMD64)
		void *      _pExitContext;
		void *      _pUnwindContext;
		void *      _pFrameInfoChain;
		unsigned __int64     _ImageBase;
#if defined (_M_IA64)
		unsigned __int64     _TargetGp;
#endif
		unsigned __int64     _ThrowImageBase;
#elif defined (_M_IX86)
		void *      _pFrameInfoChain;
#endif  /* defined (_M_IX86) */

	    _setloc_struct _setloc_data;

	    void *      _encode_ptr;    /* EncodePointer() routine */
	    void *      _decode_ptr;    /* DecodePointer() routine */

	    void *      _reserved1;     /* nothing */
	    void *      _reserved2;     /* nothing */
	    void *      _reserved3;     /* nothing */

	    int _cxxReThrow;        /* Set to True if it's a rethrown C++ Exception */

	    unsigned long __initDomain;     /* initial domain used by _beginthread[ex] for managed function */
	};
#pragma pack(pop)

	typedef struct _tiddata * _ptiddata;
	_ptiddata __cdecl _getptd();
}

inline PEXCEPTION_RECORD GetCurrentExceptionRecord()
{
	_ptiddata p = _getptd();
	return (PEXCEPTION_RECORD)p->_curexception;
}

inline PCONTEXT GetCurrentExceptionContext()
{
	_ptiddata p = _getptd();
	return (PCONTEXT)p->_curcontext;
}

#elif !defined(_MT)

extern struct PEXCEPTION_RECORD   _pCurrentException;
extern        PCONTEXT            _pCurrentExContext;

inline PEXCEPTION_RECORD GetCurrentExceptionRecord()
{
	return (PEXCEPTION_RECORD)_pCurrentException;
}

const PCONTEXT GetCurrentExceptionContext()
{
	return _pCurrentExContext;
}

#endif //_MT



//---------------------------------------------------------------------
// class DExceptionHelper

unsigned         DExceptionHelper::instanceCounter;
CRITICAL_SECTION DExceptionHelper::criticalSection;

DExceptionHelper::DExceptionHelper(const char* symbolPath)
{
	m_hImage = NULL;
	m_symbolPath = (symbolPath && *symbolPath ? _strdup(symbolPath) : NULL);

	if (!instanceCounter++)
		InitializeCriticalSection(&criticalSection);
}

DExceptionHelper::~DExceptionHelper()
{
	if (m_hImage && m_hImage != (HMODULE)INVALID_HANDLE_VALUE)
		FreeLibrary(m_hImage);

	if (m_symbolPath)
		free(m_symbolPath);

	if (!--instanceCounter)
		DeleteCriticalSection(&criticalSection);
}

bool DExceptionHelper::InitImageFunctions()
{
	if (m_hImage)
		return (m_hImage == INVALID_HANDLE_VALUE ? false : true);

    m_hImage = LoadLibrary("DBGHELP.DLL");
    if (!m_hImage)
		m_hImage = LoadLibrary("IMAGEHLP.DLL");
    if (!m_hImage)
	{
		m_hImage = (HMODULE)INVALID_HANDLE_VALUE;
        return false;
	}

    m_pSymInitialize = (SymInitializeProc)GetProcAddress(m_hImage, "SymInitialize");
    m_pSymCleanup = (SymCleanupProc)GetProcAddress(m_hImage, "SymCleanup");

    m_pStackWalk64 = (StackWalk64Proc)GetProcAddress(m_hImage, "StackWalk64");
	m_pSymFromAddr = (SymFromAddrProc)GetProcAddress(m_hImage, "SymFromAddr");

    m_pSymGetModuleBase64 = (SymGetModuleBase64Proc)GetProcAddress(m_hImage, "SymGetModuleBase64");
    m_pSymGetSymFromAddr64 = (SymGetSymFromAddr64Proc)GetProcAddress(m_hImage, "SymGetSymFromAddr64" );
	m_pSymGetLineFromAddr64 = (SymGetLineFromAddr64Proc)GetProcAddress(m_hImage, "SymGetLineFromAddrW64" );
    m_pSymFunctionTableAccess64 = (SymFunctionTableAccess64Proc)GetProcAddress(m_hImage, "SymFunctionTableAccess64");

	if (!m_pSymInitialize || !m_pSymCleanup 
		|| !m_pStackWalk64 || !m_pSymFromAddr 
		|| !m_pSymGetModuleBase64 || !m_pSymGetSymFromAddr64 
		|| !m_pSymGetLineFromAddr64 || !m_pSymFunctionTableAccess64
		)
	{
		FreeLibrary(m_hImage);

		m_hImage = (HMODULE)INVALID_HANDLE_VALUE;
        return false;
	}
	return true;
}

#ifdef _M_IX86
void DExceptionHelper::IntelRegisterReport(std::ostream& os, PCONTEXT pCtx)
{
	char buf[256];
	int rc = sprintf_s(buf, sizeof(buf),
			"EAX:%08X\tEBX:%08X\n"
			"ECX:%08X\tEDX:%08X\n"
			"ESI:%08X\tEDI:%08X\n"
			"\n"
			"CS:EIP:%04X:%08X\n"
			"SS:ESP:%04X:%08X\tEBP:%08X\n"
			"\n"
			"DS:%04X\tES:%04X\tFS:%04X\tGS:%04X\n"
			"Flags:%08X\n",
			pCtx->Eax, pCtx->Ebx, 
			pCtx->Ecx, pCtx->Edx, 
			pCtx->Esi, pCtx->Edi,
			pCtx->SegCs, pCtx->Eip,
			pCtx->SegSs, pCtx->Esp, pCtx->Ebp,
			pCtx->SegDs, pCtx->SegEs, pCtx->SegFs, pCtx->SegGs,
			pCtx->EFlags
			);
	if (rc != -1)
	{
		os << "Registers:" << std::endl;
		os << buf;
	}
}

void DExceptionHelper::IntelStackReport(std::ostream& os, PCONTEXT pCtx)
{
	os << "Call stack:" << std::endl;
	os << "Address    Frame      Logical addr  Module" << std::endl;

	DWORD pc = pCtx->Eip;
	PDWORD pFrame, pPrevFrame;

	pFrame = (PDWORD)pCtx->Ebp;

	for (unsigned i = 0; i < MAX_STACKFRAME; i++)
	{
		char path[MAX_PATH] = {0};
		DWORD section = 0, offset = 0;

		GetLogicalAddress((PVOID)pc, path, sizeof(path), &section, &offset);

		char buf[64] = {0};
		sprintf_s(buf, sizeof(buf), "%08X   %08X   %04X:%08X ",
					pc, pFrame, section, offset);

		os << buf << path << std::endl;

		pc = pFrame[1];
		pPrevFrame = pFrame;
		pFrame = (PDWORD)pFrame[0]; // precede to next higher frame on stack

		if ((DWORD)pFrame & 3)      // Frame pointer must be aligned on a
			break;                  // DWORD boundary.  Bail if not so.

		if (pFrame <= pPrevFrame)
			break;

		// Can two DWORDs be read from the supposed frame address?          
		if (IsBadWritePtr(pFrame, sizeof(PVOID)*2))
			break;
	}
}
#endif

bool DExceptionHelper::ImageStackReport(std::ostream& os, PCONTEXT pCtx)
{
	bool bResult = false;
	EnterCriticalSection(&criticalSection);

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = GetCurrentThread();

	if (m_pSymInitialize(hProcess, m_symbolPath, TRUE))
	{
		os << "Call stack:" << std::endl;
		os << "Address    Frame" << std::endl;

		// Could use SymSetOptions here to add the SYMOPT_DEFERRED_LOADS flag

		STACKFRAME64 sf = {0};

		// Initialize the STACKFRAME structure for the first call.  This is only
		// necessary for Intel CPUs, and isn't mentioned in the documentation.
		sf.AddrPC.Offset       = pCtx->Eip;
		sf.AddrPC.Mode         = AddrModeFlat;
		sf.AddrStack.Offset    = pCtx->Esp;
		sf.AddrStack.Mode      = AddrModeFlat;
		sf.AddrFrame.Offset    = pCtx->Ebp;
		sf.AddrFrame.Mode      = AddrModeFlat;

		for (unsigned i = 0; i < MAX_STACKFRAME; i++)
		{
			if (!m_pStackWalk64(IMAGE_FILE_MACHINE_I386,
								hProcess,
								hThread,
								&sf,
								pCtx,
								0,
								m_pSymFunctionTableAccess64,
								m_pSymGetModuleBase64,
								0))
				break;

			// Basic sanity check to make sure
			// the frame is OK.  Bail if not.
			if (sf.AddrPC.Offset == 0 || sf.AddrFrame.Offset == 0)
				break;

#ifdef _OLD_CALLSTACK_DUMP
			// IMAGEHLP is wacky, and requires you to pass in a pointer to a
			// IMAGEHLP_SYMBOL structure.  The problem is that this structure is
			// variable length.  That is, you determine how big the structure is
			// at runtime.  This means that you can't use sizeof(struct).
			// So...make a buffer that's big enough, and make a pointer
			// to the buffer.  We also need to initialize not one, but TWO
			// members of the structure before it can be used.

			BYTE symbolBuffer[ sizeof(IMAGEHLP_SYMBOL) + _MAX_PATH ];
			PIMAGEHLP_SYMBOL pSymbol = (PIMAGEHLP_SYMBOL)symbolBuffer;
			pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
			pSymbol->MaxNameLength = _MAX_PATH;
							
			DWORD	symDisplacement = 0;	// Displacement of the input address,
			//DWORD64	symDisplacement64 = 0;  // relative to the start of the symbol

			if (m_pSymGetSymFromAddr64(hProcess, sf.AddrPC.Offset, &symDisplacement, pSymbol))
			{
				char buf[64] = {0};
				sprintf_s(buf, sizeof(buf), "%08X   %08X   ",
						sf.AddrPC.Offset, sf.AddrFrame.Offset);

				os << buf << pSymbol->Name;

				sprintf_s(buf, sizeof(buf), "+%d", symDisplacement);
				os << buf << std::endl;
			}
			else    // No symbol found.  Print out the logical address instead.
			{
				char path[MAX_PATH] = {0};
				DWORD section = 0, offset = 0;

				GetLogicalAddress((PVOID)sf.AddrPC.Offset, path, sizeof(path), &section, &offset);

				char buf[64] = {0};
				sprintf_s(buf, sizeof(buf), "%08X   %08X   %04X:%08X ",
							sf.AddrPC.Offset, sf.AddrFrame.Offset, section, offset);

				os << buf << path << std::endl;
			}
#else
			IMAGEHLP_LINE64 sourceInfo = { 0 };
			BYTE            symbolBuffer [sizeof(SYMBOL_INFO) + (_MAX_PATH * sizeof(CHAR)) - 1] = { 0 };
			LPSTR           functionName;

			DWORD	symDisplacement = 0;	// Displacement of the input address,
			DWORD64	symDisplacement64 = 0;  // relative to the start of the symbol

			// Initialize structures passed to the symbol handler.
			SYMBOL_INFO   & functionInfo = *(SYMBOL_INFO*)&symbolBuffer;
			functionInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
			functionInfo.MaxNameLen = _MAX_PATH;
			sourceInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

			BOOL bFound = m_pSymGetLineFromAddr64(hProcess, sf.AddrPC.Offset, &symDisplacement, &sourceInfo);

			// Try to get the name of the function containing this program
			// counter address.
			if (m_pSymFromAddr(hProcess, sf.AddrPC.Offset, &symDisplacement64, &functionInfo))
			{
			    functionName = functionInfo.Name;
			}
			else
			{
			    functionName = "(unavailable)";
			}

	        // Display the current stack frame's information.
			if (bFound)
			{
				os << sourceInfo.FileName << " (" << sourceInfo.LineNumber << "): " << functionName << std::endl;
			}
			else 
			{
				char buf[64] = {0};
#ifdef _WIN64
				sprintf_s(buf, sizeof(buf), "0x%.16X", sf.AddrPC.Offset);
#else
				sprintf_s(buf, sizeof(buf), "0x%.8X", sf.AddrPC.Offset);
#endif // _WIN64
				os << buf << std::endl;
			}
#endif
		}

		m_pSymCleanup(hProcess);
		bResult = true;
	}

	LeaveCriticalSection(&criticalSection);
	return bResult;
}

bool DExceptionHelper::GetExceptionPointer(PEXCEPTION_POINTERS pExceptionInfo)
{
	pExceptionInfo->ContextRecord = GetCurrentExceptionContext();
	pExceptionInfo->ExceptionRecord = GetCurrentExceptionRecord();

	if (!pExceptionInfo->ContextRecord || !pExceptionInfo->ExceptionRecord)
		return false;

	return true;
}

void DExceptionHelper::GenerateExceptionReport(std::ostream& os)
{
	EXCEPTION_POINTERS exceptionInfo;
	if (!GetExceptionPointer(&exceptionInfo))
		return;

	GenerateExceptionReport(os, &exceptionInfo);
}

void DExceptionHelper::GenerateExceptionReport(std::ostream& os, PEXCEPTION_POINTERS pExceptionInfo)
{
	try
	{
		// set general options
		os << std::hex << std::uppercase;

		char buf[_MAX_PATH];

		PCONTEXT pCtx = pExceptionInfo->ContextRecord;
		PEXCEPTION_RECORD pExceptionRecord = pExceptionInfo->ExceptionRecord;

		// Exception at 0x00123456 in <ModulePath>
		os << "Exception at 0x" << pExceptionRecord->ExceptionAddress;
		os << " in " << GetModuleName(buf, sizeof(buf)) << std::endl;

		if (pExceptionRecord->ExceptionCode == CPP_EXCEPTION)
				//&& pExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE)
		{
			os << "Microsoft C++ exception" << std::endl;
		}
		else
		{
		// 0xC0000005: Access violation...
			os << "0x" << pExceptionRecord->ExceptionCode;
			os << ": " << GetExceptionString(pExceptionRecord, buf, sizeof(buf)) << std::endl;
		}

		// Show the registers
#ifdef _M_IX86 // Intel Only!
		os << std::endl;
		IntelRegisterReport(os, pCtx);
#endif

		if (!InitImageFunctions())
		{
			OutputDebugString("DBGHELP.DLL (or IMAGEHLP.DLL) or its exported procs not found");

#ifdef _M_IX86  // Intel Only!
			os << std::endl;
			// Walk the stack using x86 specific code
			IntelStackReport(os, pCtx);
#endif
		}
		else
		{
			os << std::endl;
			// Walk the stack using image library
			if (!ImageStackReport(os, pCtx))
			{
#ifdef _M_IX86  // Intel Only!
				// Walk the stack using x86 specific code
				IntelStackReport(os, pCtx);
#endif
			}
		}
	}
	catch (...)
	{
	}
}

void DExceptionHelper::GenerateCallstackReport(std::ostream& os)
{
	HANDLE   hThread  = GetCurrentThread();
	CONTEXT  context = {0};

	// get the context
	context.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(hThread, &context))
	{
		GenerateCallstackReport(os, &context);
	}
}

void DExceptionHelper::GenerateCallstackReport(std::ostream& os, PCONTEXT pCtx)
{
	try
	{
		// set general options
		os << std::hex << std::uppercase;

		if (!InitImageFunctions())
		{
			OutputDebugString("DBGHELP.DLL (or IMAGEHLP.DLL) or its exported procs not found");

#ifdef _M_IX86  // Intel Only!
			// Walk the stack using x86 specific code
			IntelStackReport(os, pCtx);
#endif
		}
		else
		{
			// Walk the stack using image library
			ImageStackReport(os, pCtx);
		}
	}
	catch (...)
	{
	}
}

const char* DExceptionHelper::GetModuleName(char* buf, int bufsize)
{
	if (GetModuleFileName(NULL, buf, bufsize))
		return buf;

	return "Unknown module";
}

const char* DExceptionHelper::GetExceptionString(PEXCEPTION_RECORD pExceptionRecord, char* buf, int bufsize)
{
	//#define EXCEPTION_ITEM( x ) case EXCEPTION_##x: return (#x);

	//switch(pExceptionRecord->ExceptionCode)
	//{
	//EXCEPTION_ITEM(ACCESS_VIOLATION)
	//EXCEPTION_ITEM(DATATYPE_MISALIGNMENT)
	//EXCEPTION_ITEM(BREAKPOINT)
	//EXCEPTION_ITEM(SINGLE_STEP)
	//EXCEPTION_ITEM(ARRAY_BOUNDS_EXCEEDED)
	//EXCEPTION_ITEM(FLT_DENORMAL_OPERAND)
	//EXCEPTION_ITEM(FLT_DIVIDE_BY_ZERO)
	//EXCEPTION_ITEM(FLT_INEXACT_RESULT)
	//EXCEPTION_ITEM(FLT_INVALID_OPERATION)
	//EXCEPTION_ITEM(FLT_OVERFLOW)
	//EXCEPTION_ITEM(FLT_STACK_CHECK)
	//EXCEPTION_ITEM(FLT_UNDERFLOW)
	//EXCEPTION_ITEM(INT_DIVIDE_BY_ZERO)
	//EXCEPTION_ITEM(INT_OVERFLOW)
	//EXCEPTION_ITEM(PRIV_INSTRUCTION)
	//EXCEPTION_ITEM(IN_PAGE_ERROR)
	//EXCEPTION_ITEM(ILLEGAL_INSTRUCTION)
	//EXCEPTION_ITEM(NONCONTINUABLE_EXCEPTION)
	//EXCEPTION_ITEM(STACK_OVERFLOW)
	//EXCEPTION_ITEM(INVALID_DISPOSITION)
	//EXCEPTION_ITEM(GUARD_PAGE)
	//EXCEPTION_ITEM(INVALID_HANDLE)
	//}

	try
	{
		if (pExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
		{
			sprintf_s(buf, bufsize, "Access violation %s location 0x%p",
				(pExceptionRecord->ExceptionInformation[0] ? "writing to" : "reading from"),
				pExceptionRecord->ExceptionInformation[1]);
			return buf;
		}

		if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle(NULL),
							pExceptionRecord->ExceptionCode, 0, buf, bufsize, 0))
			return buf;
		if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
							pExceptionRecord->ExceptionCode, 0, buf, bufsize, 0))
			return buf;
		// If not one of the "known" exceptions, try to get the string
		// from NTDLL.DLL's message table.
		if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle("NTDLL.DLL"),
							pExceptionRecord->ExceptionCode, 0, buf, bufsize, 0))
			return buf;
	}
	catch (...)
	{
	}
	return "Unknown exception";
}

bool DExceptionHelper::GetLogicalAddress(PVOID addr, char* module, int size, DWORD* section, DWORD* offset)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
		return false;

	DWORD hMod = (DWORD)mbi.AllocationBase;
	if (!GetModuleFileName((HMODULE)hMod, module, size))
		return false;

	// Point to the DOS header in memory
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hMod;

	// From the DOS header, find the NT (PE) header
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(hMod + pDosHdr->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);

	DWORD rva = (DWORD)addr - hMod; // RVA is offset from module load address

	// Iterate through the section table, looking for the one that encompasses
	// the linear address.
	for (unsigned i = 0;	i < pNtHdr->FileHeader.NumberOfSections;	i++, pSection++)
	{
		DWORD sectionStart = pSection->VirtualAddress;
		DWORD sectionEnd = sectionStart + max(pSection->SizeOfRawData, pSection->Misc.VirtualSize);

		// Is the address in this section???
		if ((rva >= sectionStart) && (rva <= sectionEnd))
		{
			// Yes, address is in the section.  Calculate section and offset,
			// and store in the "section" & "offset" params, which were
			// passed by reference.
			*section = i+1;
			*offset = rva - sectionStart;
			return true;
		}
	}
	return false;   // Should never get here!
}

#pragma warning(pop)
#pragma message("Restored warnings for C4311 C4312 C4313")

