///////////////////////////////////////////////////////////////////////////////
//
// CrackMeZ3S - Bartosz Wójcik - https://www.pelock.com | http://www.secnews.pl
//
// for Zaufana Trzecia Strona - https://zaufanatrzeciastrona.pl
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <conio.h>

///////////////////////////////////////////////////////////////////////////////
//
// constants (I don't want to move it to .h)
//
///////////////////////////////////////////////////////////////////////////////

//
// number of access keys
//
const int KEYS_COUNT = 6;

const int MD5LEN = 16;

struct SPEED_TIME
{
	LARGE_INTEGER StartingTime;
	LARGE_INTEGER EndingTime;
	LARGE_INTEGER ElapsedMicroseconds;
	LARGE_INTEGER Frequency;
};

//
// colour combinations for console text
// http://stackoverflow.com/questions/17125440/c-win32-console-color
//
namespace ConsoleForeground
{
	enum {
		BLACK = 0,
		DARKBLUE = FOREGROUND_BLUE,
		DARKGREEN = FOREGROUND_GREEN,
		DARKCYAN = FOREGROUND_GREEN | FOREGROUND_BLUE,
		DARKRED = FOREGROUND_RED,
		DARKMAGENTA = FOREGROUND_RED | FOREGROUND_BLUE,
		DARKYELLOW = FOREGROUND_RED | FOREGROUND_GREEN,
		DARKGRAY = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
		GRAY = FOREGROUND_INTENSITY,
		BLUE = FOREGROUND_INTENSITY | FOREGROUND_BLUE,
		GREEN = FOREGROUND_INTENSITY | FOREGROUND_GREEN,
		CYAN = FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE,
		RED = FOREGROUND_INTENSITY | FOREGROUND_RED,
		MAGENTA = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE,
		YELLOW = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN,
		WHITE = FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	};
}

///////////////////////////////////////////////////////////////////////////////
//
// data
//
///////////////////////////////////////////////////////////////////////////////

//
// access keys threads handles
//
HANDLE hThreads[KEYS_COUNT] = { nullptr };
DWORD dwThreadIds[KEYS_COUNT] = { 0 };

//
// handle events, used to mark the correct keys
// 
HANDLE hEvents[KEYS_COUNT] = { nullptr };

// here you will find the value of the environmental variable
TCHAR wszEnvrionmentVariable[128] = { 0 };

// here you will find the contents of "CrackMeZ3S.exe:Z3S.txt" file
char szADS[128] = { 0 };

// clipboard contents
char szClipboard[128] = { 0 };

// password entered from the console windows (fake check)
char szPassword[128] = { 0 };

// OS version information
OSVERSIONINFO osvi = { 0 };

// structures for checking the execution times of specific tasks
SPEED_TIME Speed[255] = { 0 };

// a flag will be generated here
TCHAR wszFlag[128] = { 0 };

///////////////////////////////////////////////////////////////////////////////
//
// gets the start time - this function MUST be inline to prevent
// someone simply patching the function in one place
//
///////////////////////////////////////////////////////////////////////////////

void __forceinline SpeedStart(int iSpeedStructIndex)
{
	QueryPerformanceFrequency(&Speed[iSpeedStructIndex].Frequency);
	QueryPerformanceCounter(&Speed[iSpeedStructIndex].StartingTime);
}

///////////////////////////////////////////////////////////////////////////////
//
// gets the end time and checks whether execution time
// exceeds the specified limit
//
///////////////////////////////////////////////////////////////////////////////

void __forceinline SpeedEnd(int iSpeedStructIndex, int iMaxTimeInSeconds = 5)
{
	QueryPerformanceCounter(&Speed[iSpeedStructIndex].EndingTime);
	Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart = Speed[iSpeedStructIndex].EndingTime.QuadPart - Speed[iSpeedStructIndex].StartingTime.QuadPart;

	//Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart *= 1000000;
	Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart /= Speed[iSpeedStructIndex].Frequency.QuadPart;

	// check whether the time limit was exceeded
	if (Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart > iMaxTimeInSeconds)
	{
		#ifdef _DEBUG
		_tprintf(_T("[!] the limit of %i seconds was exceeded for index %c, execution time %llu"), iMaxTimeInSeconds, iSpeedStructIndex, Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart);
		#endif
		
		// in case of the time limit being exceeded, no error is
		// displayed, but we will corrupt the internal structure of
		// the CrackMe, which will cause the CrackMe to
		// malfunction or simply hang at some point
		
		// randomly decide whether to corrupt something or not
		#define LOTTO_CRASH ((rand() & 6) == 0)
		
		// decide whether to erase a thread handle
		if (LOTTO_CRASH) hThreads[rand() % _countof(hThreads)] = nullptr;
		
		// decide whether to erase an event handle
		if (LOTTO_CRASH) hEvents[rand() % _countof(hEvents)] = reinterpret_cast<HANDLE>(rand());
		
		// decide whether to reset an event (the indicator of a valid access key)
		if (LOTTO_CRASH) ResetEvent(hEvents[rand() % _countof(hEvents)]);
		
		// randomly fill text buffers
		if (LOTTO_CRASH) memset(wszEnvrionmentVariable, _countof(wszEnvrionmentVariable) * sizeof(TCHAR), rand());
		if (LOTTO_CRASH) memset(szADS, sizeof(szADS), rand());
		if (LOTTO_CRASH) memset(szClipboard, sizeof(szClipboard), rand());
		if (LOTTO_CRASH) memset(szPassword, sizeof(szPassword), rand());
		if (LOTTO_CRASH) memset(wszFlag, _countof(wszFlag) * sizeof(TCHAR), rand());
		
		// evil asm trick ;), corrupt the stack pointer
		// this is guaranteed to cause the application to crash
		if (LOTTO_CRASH) __asm inc esp
	}
}

///////////////////////////////////////////////////////////////////////////////
//
// lock the keyboard and mouse
//
// Caution!
// in order for BlockInput() function to work properly, the application must be started
// with administrator rights
//
///////////////////////////////////////////////////////////////////////////////

BOOL __forceinline Block(BOOL bBlock = TRUE)
{
	HINSTANCE hDLL = LoadLibrary(_T("USER32.dll"));

	typedef BOOL(WINAPI *BLOCKINPUT)(BOOL);
	BLOCKINPUT pBlockInput;

	// the name of the function should be encrypted so that it is not seen in the disassembler
	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// szBlockInput = "BlockInput"
	unsigned char szBlockInput[11] = { 0x24, 0xC7, 0xF8, 0x39, 0xBA, 0x99, 0xEC, 0x0E,
		0x5F, 0x50, 0x0A };

	for (unsigned int pDQay = 0, gAoQB; pDQay < 11; pDQay++)
	{
		gAoQB = szBlockInput[pDQay];
		gAoQB -= pDQay;
		gAoQB = (((gAoQB & 0xFF) >> 4) | (gAoQB << 4)) & 0xFF;
		szBlockInput[pDQay] = gAoQB;
	}

	pBlockInput = reinterpret_cast<BLOCKINPUT>(GetProcAddress(hDLL, reinterpret_cast<char *>(szBlockInput)));

	// do not even check if the wrong pointer is returned,
	// because the function is available from Windows 2000 and if so
	// would be nullptr turned back, that is, with or without something
	// DIY or sitting on antique Windows NT 4
	return pBlockInput(bBlock);
}

///////////////////////////////////////////////////////////////////////////////
//
// the function calculates MD5 hashes and checks to see if it matches the
// specified MD5 hash
//
///////////////////////////////////////////////////////////////////////////////

BOOL CheckMD5(const PVOID pbData, const DWORD dwDataLen, const char *szHash)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;

	DWORD cbHash;
	BYTE rgbHash[MD5LEN];
	char szMD5[64] = { 0 };

	if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		return FALSE;
	}

	if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash) == NULL)
	{
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	if (CryptHashData(hHash, static_cast<PBYTE>(pbData), dwDataLen, 0) == FALSE)
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return FALSE;
	}

	cbHash = MD5LEN;

	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0) == FALSE)
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return FALSE;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);

	for (DWORD i = 0; i < cbHash; i++)
	{
		sprintf_s(&szMD5[i * 2], (sizeof(szMD5) - i * 2), "%02X", rgbHash[i]);
	}

	if (strcmp(szMD5, szHash) == 0)
	{
		return TRUE;
	}

	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////
//
// Verifies the correctness of all the keys, and generates
// a flag from individual letters of the keys
//
// The correct flag:
//
// "PELock v2.0"
//  01234567890
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Check(DWORD Param)
{
	SpeedStart('C');

	// Key 0 - fake key
	if (WaitForSingleObject(hEvents[0], 1) == WAIT_OBJECT_0)
	{
		// misleading writes - the characters in this password
		// will not be used (we're writing them past the end
		// of the buffer)
		wszFlag[16] = TCHAR(szPassword[4]);
		wszFlag[12] = TCHAR(szPassword[1]);
  
		#ifdef _DEBUG
		_tprintf(_T("[i] key 0 - OK\n"));
		#endif
	}

	// Key 1 - environment variables
	if (WaitForSingleObject(hEvents[1], 1) == WAIT_OBJECT_0)
	{
		// "PELock[ ]v2.0" - "AMD64[ ]"
		wszFlag[6] = wszEnvrionmentVariable[5];

		#ifdef _DEBUG
		_tprintf(_T("[i] key 1 - OK\n"));
		#endif
	}

	// Key 2 - ADS
	if (WaitForSingleObject(hEvents[2], 1) == WAIT_OBJECT_0)
	{
		// "PELock v[2].[0]" - "[2][0]16.07"
		wszFlag[8] = TCHAR(szADS[0]);
		wszFlag[10] = TCHAR(szADS[1]);
		wszFlag[9] = TCHAR(szADS[4]);

		#ifdef _DEBUG
		_tprintf(_T("[i] key 2 - OK\n"));
		#endif
	}

	// Key 3 - clipboard contents
	if (WaitForSingleObject(hEvents[3], 1) == WAIT_OBJECT_0)
	{
		// "Boom Boom - Lip Lock - Song"
		wszFlag[4] = TCHAR(szClipboard[18]);
		wszFlag[3] = TCHAR(szClipboard[17]);
		wszFlag[2] = TCHAR(szClipboard[16]);
		wszFlag[5] = TCHAR(szClipboard[19]);

		#ifdef _DEBUG
		_tprintf(_T("[i] key 3 - OK\n"));
		#endif
	}

	// Key 4 - pressing Ctrl-C
	if (WaitForSingleObject(hEvents[4], 1) == WAIT_OBJECT_0)
	{
		// missing letter
		wszFlag[7] = TCHAR('v');

		#ifdef _DEBUG
		_tprintf(_T("[i] key 4 - OK\n"));
		#endif
	}

	// Key 5 - system version matching Windows Vista
	if (WaitForSingleObject(hEvents[5], 1) == WAIT_OBJECT_0)
	{
		// letter 'P' = 0x4A + 6
		wszFlag[0] = TCHAR(0x4A + osvi.dwMajorVersion);

		// letter 'E' = 0x45 - 0
		wszFlag[1] = TCHAR(0x45 - osvi.dwMinorVersion);

		#ifdef _DEBUG
		_tprintf(_T("[i] key 5 - OK\n"));
		#endif
	}

	SpeedEnd('C');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// handler for the Ctrl-C shortcut
//
///////////////////////////////////////////////////////////////////////////////

BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
	case CTRL_C_EVENT:

		// set the flag which indicates the user pressed Ctrl-C
		SetEvent(hEvents[5]);

		return TRUE;
	}

	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////
//
// Key 5 - check whether the user has pressed Ctrl-C
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Key5(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('5');

	// set up Ctrl-C handler
	SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(CtrlHandler), TRUE);

	SpeedEnd('5');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Key 4 - checking compatibility mode
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Key4(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('4');

	// start up the next thread (chain reaction style)
	hThreads[5] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[5])), lpKeyProc, 0, &dwThreadIds[5]);

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	// the GetVersionEx() function has been deprecated,
	// but for our CrackMe it'll do fine
	#pragma warning(disable : 4996)
	GetVersionEx(&osvi);

	// the numbering will match Windows Vista and Windows Server 2008
	// https://msdn.microsoft.com/pl-pl/library/windows/desktop/ms724833(v=vs.85).aspx
	if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
	{
		// set the flag indicating the compatibility mode is set correctly
		SetEvent(hEvents[4]);
	}

	SpeedEnd('4');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Key 3 - checking the clipboard
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Key3(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('3');

	// start up the next thread (chain reaction style)
	hThreads[4] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[4])), lpKeyProc, 0, &dwThreadIds[4]);

	// open the clipboard
	if (OpenClipboard(nullptr) == TRUE)
	{
		// get a handle to the data in CF_TEXT format
		HANDLE hData = GetClipboardData(CF_TEXT);
		
		// was any data obtained?
		if (hData != nullptr)
		{
			// lock memory
			char *pszText = static_cast<char *>(GlobalLock(hData));
			
			if (pszText != nullptr)
			{
				// hehe ;)
				if (strcmp(pszText, "Boom Boom - Lip Lock - Song") == 0)
				{
					// copy the clipboard contents to a global variable
					strcpy_s(szClipboard, sizeof(szClipboard), pszText);
					
					// set the flag for this key
					SetEvent(hEvents[3]);
				}
			}
		
			GlobalUnlock(hData);
			CloseClipboard();
		}
	}

	SpeedEnd('3');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Key 2 - checking ADS
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Key2(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('2');

	// start up the next thread (chain reaction style)
	hThreads[3] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[3])), lpKeyProc, 0, &dwThreadIds[3]);

	TCHAR wszPath[512] = { 0 };

	// get the path to the CrackMe executable
	GetModuleFileName(GetModuleHandle(nullptr), wszPath, sizeof(wszPath));

	// add the ADS suffix
	_tcscat_s(wszPath, _countof(wszPath), _T(":Z3S.txt"));

	// open the stream "CrackMeZ3S.exe:Z3S.txt"
	HANDLE hFile = CreateFile(wszPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	SpeedEnd('2');

	// check if open was successful
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	// find the file size
	DWORD dwFileSize = GetFileSize(hFile, nullptr);

	// ensure that it will fit in the buffer
	if (dwFileSize > sizeof(szADS))
	{
		CloseHandle(hFile);
		return 0;
	}

	DWORD dwReadBytes = 0;

	// read the contents of the secret stream
	if (ReadFile(hFile, &szADS, dwFileSize, &dwReadBytes, nullptr) == FALSE || dwReadBytes != dwFileSize)
	{
		CloseHandle(hFile);
		return 0;
	}

	CloseHandle(hFile);

	char szTemp[sizeof(szADS)];

	strcpy_s(szTemp, _countof(szTemp), szADS);

	// reverse the string
	_strrev(szTemp);

	if (strcmp(szTemp, "\n\r70.6102") == 0)
	{
		// set the flag which indicates the ADS key was verified
		SetEvent(hEvents[2]);
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Key 1 - checking environment variable
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Key1(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('1');

	// start up the next thread (chain reaction style)
	hThreads[2] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[2])), lpKeyProc, 0, &dwThreadIds[2]);

	// the name of the environmental variable is encrypted
	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// wszEnvironmentVariableName = "PROCESOR_ARCHITECTURE"
	wchar_t wszEnvironmentVariableName[22] = { 0xA821, 0xA8D1, 0xA829, 0xA849, 0xA879, 0xA8C9, 0xA829, 0xA8D1,
		0xA8A9, 0xA859, 0xA8D1, 0xA849, 0xA861, 0xA819, 0xA8C1, 0xA879,
		0xA849, 0xA8C1, 0xA8F9, 0xA8D1, 0xA879, 0x55A1 };

	for (unsigned int bAJFG = 0, EIMSG; bAJFG < 22; bAJFG++)
	{
		EIMSG = wszEnvironmentVariableName[bAJFG];
		EIMSG ^= 0xAA5E;
		EIMSG += bAJFG;
		EIMSG++;
		EIMSG -= bAJFG;
		EIMSG = ((EIMSG << 13) | ((EIMSG & 0xFFFF) >> 3)) & 0xFFFF;
		wszEnvironmentVariableName[bAJFG] = EIMSG;
	}

	if (GetEnvironmentVariable(wszEnvironmentVariableName, wszEnvrionmentVariable, sizeof(wszEnvrionmentVariable)) != 0)
	{
		// the expected value of the variable is "AMD64 ", it will be encrypted too
		// so that CrackMe needs to be debugged and not view in disassembler only

		// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
		// wszEnvironmentVariableValue = "AMD64 "
		wchar_t wszEnvironmentVariableValue[7] = { 0x130B, 0x530B, 0xE30B, 0xC30C, 0xE30C, 0x230D, 0x230F };

		for (unsigned int jpaCd = 0, pXESR; jpaCd < 7; jpaCd++)
		{
			pXESR = wszEnvironmentVariableValue[jpaCd];
			pXESR += 0xCCF0;
			pXESR = (((pXESR & 0xFFFF) >> 12) | (pXESR << 4)) & 0xFFFF;
			pXESR = ~pXESR;
			pXESR--;
			wszEnvironmentVariableValue[jpaCd] = pXESR;
		}

		// set event if the flag is set
		if (_tcscmp(wszEnvrionmentVariable, wszEnvironmentVariableValue) == 0)
		{
			SetEvent(hEvents[1]);
		}
	}

	SpeedEnd('1');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Fake key - to waste an attacker's time ;)
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Key0(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	// start up the next thread (chain reaction style)
	hThreads[1] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[1])), lpKeyProc, 0, &dwThreadIds[1]);

	_tprintf(_T("Enter the secret key: "));

	// read the password as an ANSI string (so that it's not too difficult
	// for an attacker to find the password e.g. using rainbow tables.
	// We'll do them a favour by choosing ANSI over UNICODE)
	gets_s(szPassword, sizeof(szPassword));

	// start measuring time here so that gets_s() doesn't
	// artificially extend the time
	SpeedStart('0');

	if (strlen(szPassword) > 0)
	{
		// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
		// szFakeHash = "144C9DEFAC04969C7BFAD8EFAA8EA194"
		unsigned char szFakeHash[33];

		szFakeHash[2] = 0xA8; szFakeHash[0] = 0xCD; szFakeHash[10] = 0xBC; szFakeHash[30] = 0x28;
		szFakeHash[16] = 0x0A; szFakeHash[13] = 0x0D; szFakeHash[29] = 0x76; szFakeHash[14] = 0x30;
		szFakeHash[12] = 0x01; szFakeHash[32] = 0xEC; szFakeHash[3] = 0xCE; szFakeHash[31] = 0x3B;
		szFakeHash[15] = 0x48; szFakeHash[1] = 0x33; szFakeHash[25] = 0x27; szFakeHash[27] = 0xD9;
		szFakeHash[9] = 0x5F; szFakeHash[17] = 0x93; szFakeHash[24] = 0x8B; szFakeHash[7] = 0x9C;
		szFakeHash[26] = 0x5A; szFakeHash[23] = 0x24; szFakeHash[18] = 0x66; szFakeHash[19] = 0x06;
		szFakeHash[5] = 0xC1; szFakeHash[28] = 0x69; szFakeHash[21] = 0xF8; szFakeHash[20] = 0x9D;
		szFakeHash[4] = 0xFC; szFakeHash[22] = 0x44; szFakeHash[6] = 0xFF; szFakeHash[11] = 0x42;
		szFakeHash[8] = 0x83;

		for (unsigned int GpjcO = 0, qeVjl; GpjcO < 33; GpjcO++)
		{
			qeVjl = szFakeHash[GpjcO];
			qeVjl = (((qeVjl & 0xFF) >> 2) | (qeVjl << 6)) & 0xFF;
			qeVjl += GpjcO;
			qeVjl = (((qeVjl & 0xFF) >> 5) | (qeVjl << 3)) & 0xFF;
			qeVjl ^= 0xF7;
			qeVjl = ~qeVjl;
			qeVjl ^= GpjcO;
			qeVjl--;
			qeVjl = ~qeVjl;
			qeVjl -= 0xDF;
			qeVjl = ((qeVjl << 6) | ((qeVjl & 0xFF) >> 2)) & 0xFF;
			qeVjl--;
			qeVjl ^= 0x76;
			qeVjl += 0xF0;
			qeVjl -= GpjcO;
			qeVjl ^= GpjcO;
			qeVjl = ~qeVjl;
			qeVjl += GpjcO;
			qeVjl = (((qeVjl & 0xFF) >> 2) | (qeVjl << 6)) & 0xFF;
			qeVjl += 0x2C;
			qeVjl = ((qeVjl << 4) | ((qeVjl & 0xFF) >> 4)) & 0xFF;
			qeVjl -= 0xFF;
			qeVjl = ((qeVjl << 1) | ((qeVjl & 0xFF) >> 7)) & 0xFF;
			qeVjl = ~qeVjl;
			qeVjl++;
			qeVjl = (((qeVjl & 0xFF) >> 4) | (qeVjl << 4)) & 0xFF;
			qeVjl -= 0xEF;
			qeVjl = (((qeVjl & 0xFF) >> 2) | (qeVjl << 6)) & 0xFF;
			qeVjl -= 0xF7;
			qeVjl = (((qeVjl & 0xFF) >> 3) | (qeVjl << 5)) & 0xFF;
			qeVjl -= 0x48;
			qeVjl = ~qeVjl;
			qeVjl -= GpjcO;
			qeVjl ^= GpjcO;
			qeVjl += 0xE6;
			qeVjl ^= 0xB4;
			qeVjl -= 0x9D;
			qeVjl = ~qeVjl;
			qeVjl--;
			qeVjl ^= GpjcO;
			qeVjl += 0x17;
			qeVjl ^= 0x55;
			qeVjl += GpjcO;
			qeVjl += 0xB3;
			qeVjl = (((qeVjl & 0xFF) >> 3) | (qeVjl << 5)) & 0xFF;
			qeVjl -= 0xCE;
			qeVjl = ~qeVjl;
			qeVjl += 0x9B;
			qeVjl ^= 0x71;
			qeVjl--;
			qeVjl = ((qeVjl << 7) | ((qeVjl & 0xFF) >> 1)) & 0xFF;
			szFakeHash[GpjcO] = qeVjl;
		}
  
		// compare with the hash of the word "fake" (https://www.pelock.com/products/hash-calculator)
		if (CheckMD5(szPassword, strlen(szPassword), reinterpret_cast<char *>(szFakeHash)) == TRUE)
		{
			SetEvent(hEvents[0]);
		}
	}

	SpeedEnd('0');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// The TLS callback mechanism allows code to be executed prior to
// the launch of a program's entry point; this is one place where
// we can hide the initialisation of a couple of things
//
// details about implementing this in C++:
// http://stackoverflow.com/questions/14538159/about-tls-callback-in-windows
//
///////////////////////////////////////////////////////////////////////////////

void NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID)
{
	// ensure the reason for calling the callback is that the application
	// process has been attached, i.e. the application has been launched
	// exactly the same as in the DllMain() in DLL libraries
	if (dwReason != DLL_PROCESS_ATTACH)
	{
		return;
	}

	// check the heap flags - in the case of a debugged application
	// they are different to an application started normally
	 // in case a debugger is detected, stop the application
	// at this point
	__asm
	{
		mov	eax, dword ptr fs:[30h]
		test	dword ptr [eax + 68h], HEAP_REALLOC_IN_PLACE_ONLY or HEAP_TAIL_CHECKING_ENABLED or HEAP_FREE_CHECKING_ENABLED
		je	_no_debugger

		_sleep_well_my_angel:

		push	1000000
		call	Sleep

		jmp	_sleep_well_my_angel

		_no_debugger:
	}
}

// additional options for the linker to activate TLS Callbacks
#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif

#ifdef _WIN64
#pragma const_seg(".CRT$XLF")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLF")
EXTERN_C
#endif
PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64

///////////////////////////////////////////////////////////////////////////////
//
// program start
//
///////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[], char* envp[])
{
	//
	// initialize the pseudo-random generator for the rand() function
	//
	srand(GetTickCount());

	SpeedStart('W');

	//
	// read console handle
	//
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	//
	// show greetings
	//

	// set green text color
	SetConsoleTextAttribute(hConsole, ConsoleForeground::GREEN);
	_tprintf(_T("\n[i] CrackMeZ3S CTF - autor Bartosz Wojcik - https://www.pelock.com\n"));

	SetConsoleTextAttribute(hConsole, ConsoleForeground::DARKGREEN);
	_tprintf(_T("[i] dla Zaufanej Trzeciej Strony - https://zaufanatrzeciastrona.pl\n\n"));

	SetConsoleTextAttribute(hConsole, ConsoleForeground::DARKGRAY);

	SpeedEnd('W');

	//
	// table of addresses of successive key verification functions
	// the pointers in this table will be encrypted, and decrypted
	// only at the moment when they are ready to be executed
	//
	// we will store the address adjusted 100 bytes forward
	// this will cause a hiccup in every disassembler, since this will
	// be treated as a function pointer
	// for further entertainment we can add extra dummy entries to this table
	//
	#define ENCRYPTED_PTR(x, y) reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(&x) + y)

	PVOID lpKeyProc[KEYS_COUNT] = {

		ENCRYPTED_PTR(Key0, 100),
		ENCRYPTED_PTR(Key1, 100),
		ENCRYPTED_PTR(Key2, 100),
		ENCRYPTED_PTR(Key3, 100),
		ENCRYPTED_PTR(Key4, 100),
		ENCRYPTED_PTR(Key5, 100),

	};

	SpeedStart('C');

	//
	// create 5 EVENT objects, which will serve as markers
	// of the validity of the access keys
	// also, encrypt the pointers to the functions which
	// check the validity of the keys
	//
	for (int i = 0; i < KEYS_COUNT; i++)
	{
		hEvents[i] = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		lpKeyProc[i] = static_cast<LPTHREAD_START_ROUTINE>(EncodePointer(reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(lpKeyProc[i]) - 100)));
	}

	//
	// fire up the first thread which will pretend to verify the serial number
	// it will start successive threads which will run successive procedures
	// to verify access keys
	//
	hThreads[0] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[0])), lpKeyProc, 0, &dwThreadIds[0]);

	SpeedEnd('C');

	// wait for all threads to be initialised (in case someone tries to skip something)
	// the threads are started in a chain reaction, so their handles will not all
	// be generated yet, and so we can't use WaitForMultipleObjects()
	for (int i = 0; i < _countof(hThreads); i++)
	{
		while (hThreads[i] == nullptr)
		{
			OutputDebugString(_T("What's up, Doc?"));
		}
	}

	// wait for all threads to finish working
	WaitForMultipleObjects(_countof(hThreads), hThreads, TRUE, INFINITE);

	SpeedStart('V');

	// check flag validity
	Check(0);

	#ifdef _DEBUG
	_tprintf(_T("[i] flaga - \"%s\"\n"), wszFlag);
	#endif

	//
	// calculate MD5 from the flag string and salt
	// (in order to thwart brute-force attacks)
	// the point of this is to guard against situations
	// where somebody bypasses some of the defences
	// (e.g. by manually setting up the EVENTs)
	//
	TCHAR wszFlagSalty[128];

	_stprintf_s(wszFlagSalty, _T("#flag4poprawna %s \n123458s3cr3t _+=-=-="), wszFlag);

	// calculate the hash from a TCHAR string; the result is an ANSI string
	BOOL bValidFlag = CheckMD5(wszFlagSalty, _tcslen(wszFlagSalty) * sizeof(TCHAR), "4ED28DA4AAE4F2D58BF52EB0FE09F40B");

	SpeedEnd('V');

	if (bValidFlag == TRUE)
	{
		SpeedStart('S');

		_tprintf(_T("\n"));

		// we will encrypt the content of the success message so that it does
		// not become visible in the disassembler

		// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
		// wszSuccess = "\n[i] poprawna flaga: %s\n"
		wchar_t wszSuccess[25] = { 0xD313, 0x9712, 0xEF12, 0x9F12, 0x8B13, 0x4B0F, 0x470F, 0x4B0F,
			0x330F, 0x8F12, 0xA70F, 0x430F, 0x8F12, 0x8B13, 0xE312, 0x5B0F,
			0x8F12, 0xE712, 0x8F12, 0x1314, 0x8B13, 0x7F13, 0x370F, 0xD313,
			0x0B15 };

		for (unsigned int hXBLn = 0, ZwWbC; hXBLn < 25; hXBLn++)
		{
			ZwWbC = wszSuccess[hXBLn];
			ZwWbC--;
			ZwWbC = ((ZwWbC << 8) | ((ZwWbC & 0xFFFF) >> 8)) & 0xFFFF;
			ZwWbC += 0x8BCF;
			ZwWbC ^= 0x463A;
			ZwWbC -= 0xD64F;
			ZwWbC ^= 0xC6B4;
			ZwWbC++;
			ZwWbC = ~ZwWbC;
			ZwWbC = ((ZwWbC << 14) | ((ZwWbC & 0xFFFF) >> 2)) & 0xFFFF;
			ZwWbC -= 0x4EB6;
			wszSuccess[hXBLn] = ZwWbC;
		}

		SetConsoleTextAttribute(hConsole, ConsoleForeground::WHITE);

		SpeedEnd('S');

		_tprintf(wszSuccess, wszFlag);
	}
	else
	{
		SetConsoleTextAttribute(hConsole, ConsoleForeground::RED);

		//
		// use https://www.deepl.com/translator#pl/en/ to translate it to english
		// if you are interested what it says hehe ;)
		//
		const TCHAR *pwszFail[] = {

			_T("\n[!] nie tym razem kolego :P"),
			_T("\n[!] tip: zapusc SoftICE i uzyj CTRL-D"),
			_T("\n[!] tip: moze uzyj dekompilatora JAD :)"),
			_T("\n[!] tip: szczerze, ale tak szczerze, zajrzyj pod offset 0xA1031DC"),
			_T("\n[!] tip: kod CrackMe lepiej wyglada w hexedytorze ;)"),
			_T("\n[!] tip: uzyj sniffera sieciowego, wiem co mowie :D"),
			_T("\n[!] tip: ja bym uzyl de4dot najpierw..."),
			_T("\n[!] tip: zdekompiluj plik Reflectorem albo DotPeekiem, zaufaj mi :)"),
			_T("\n[!] tip: tak miedzy nami, zaloz pulapke w debuggerze na funkcje ExitProcess()"),
			_T("\n[!] tip: Oaza w Biedrze jest zawsze blisko przy kasach :)"),
			_T("\n[!] tip: exek jest skompresowany UPX-em, tylko nie widac :P"),
			_T("\n[!] tip: poprawne haslo to tylko 1 litera, sprobuj zgadywac :)"),
			_T("\n[!] tip: emacsem przez sendmail bedzie latwiej :P"),
			_T("\n[!] tip: brawo, wylosowales darmowa flage! Albo nie :P"),
			_T("\n[!] tip: polecam debugger Hopper do tego CrackMe, nie oklamalbym Cie :)"),
			_T("\n[!] tip: rekomenduje deasembler W32dsm do tego CrackMe :)"),
			_T("\n[!] tip: zaszyfrowane haslo jest pod offsetem 0x01F00D ;)"),
			_T("\n[!] tip: poczytaj tutoriale o RE: na https://www.pelock.com/pl/artykuly to na serio :)"),

		};

		// show random failure text :P
		_putts(pwszFail[rand() % _countof(pwszFail)]);
	}

	// restore default console text
	SetConsoleTextAttribute(hConsole, ConsoleForeground::DARKGRAY);

	_tprintf(_T("\nNacisnij dowolny klawisz, aby kontynuowac..."));

	_getch();

	return 0;
}
