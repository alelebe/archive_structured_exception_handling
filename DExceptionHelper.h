#pragma once

#include <windows.h>
#include <imagehlp.h>

#include <iosfwd>

// class DExceptionHelper
//		Helper for C++ and structured exception handling.
//		And dumping call stack at this point.
class DExceptionHelper
{
public:
	DExceptionHelper(const char* symbolPath = NULL);
	~DExceptionHelper();

	void GenerateExceptionReport(std::ostream& os);
	void GenerateExceptionReport(std::ostream& os, PEXCEPTION_POINTERS pExceptionInfo);

	void GenerateCallstackReport(std::ostream& os);
	void GenerateCallstackReport(std::ostream& os, PCONTEXT pContext);

	// Helper functions
	static const char* GetModuleName(char* buf, int bufsize);
	static const char* GetExceptionString(PEXCEPTION_RECORD pExceptionRecord, char* buf, int bufsize);
	static bool        GetLogicalAddress(PVOID addr, char* module, int size, DWORD* section, DWORD* offset);
	static bool        GetExceptionPointer(PEXCEPTION_POINTERS pExceptionInfo);

	const static DWORD MS_MAGIC        = 0x19930520;
	const static DWORD CPP_EXCEPTION   = 0xE06D7363;

private:
	bool InitImageFunctions();

#ifdef _M_IX86
	void IntelRegisterReport(std::ostream& os, PCONTEXT pContext);
	void IntelStackReport(std::ostream& os, PCONTEXT pContext);
#endif

	bool ImageStackReport(std::ostream& os, PCONTEXT pContext);

	typedef BOOL	(__stdcall * SymInitializeProc)(HANDLE, LPSTR, BOOL);
	typedef BOOL	(__stdcall * SymCleanupProc)(HANDLE);

	typedef BOOL	(__stdcall * StackWalk64Proc)(DWORD, HANDLE, HANDLE, LPSTACKFRAME64, LPVOID,
													PREAD_PROCESS_MEMORY_ROUTINE64, 
													PFUNCTION_TABLE_ACCESS_ROUTINE64, 
													PGET_MODULE_BASE_ROUTINE64, 
													PTRANSLATE_ADDRESS_ROUTINE64);

	typedef BOOL	(__stdcall * SymFromAddrProc)(HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO);
	typedef DWORD64	(__stdcall * SymGetModuleBase64Proc)(HANDLE, DWORD64);
	typedef BOOL	(__stdcall * SymGetSymFromAddr64Proc)(HANDLE, DWORD64, PDWORD64, PIMAGEHLP_SYMBOL);
	typedef BOOL	(__stdcall * SymGetLineFromAddr64Proc)(HANDLE, DWORD64, PDWORD, PIMAGEHLP_LINE64);
	typedef LPVOID	(__stdcall * SymFunctionTableAccess64Proc)(HANDLE, DWORD64);

	HMODULE m_hImage;

	SymInitializeProc				m_pSymInitialize;
	SymCleanupProc					m_pSymCleanup;

	StackWalk64Proc					m_pStackWalk64;

	SymFromAddrProc					m_pSymFromAddr;
	SymGetModuleBase64Proc			m_pSymGetModuleBase64;
	SymGetSymFromAddr64Proc			m_pSymGetSymFromAddr64;
    SymGetLineFromAddr64Proc		m_pSymGetLineFromAddr64;
	SymFunctionTableAccess64Proc	m_pSymFunctionTableAccess64;

	char* m_symbolPath;

	static unsigned         instanceCounter;
	static CRITICAL_SECTION	criticalSection;
};
