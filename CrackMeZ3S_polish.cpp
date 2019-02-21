///////////////////////////////////////////////////////////////////////////////
//
// CrackMeZ3S - Bartosz Wójcik - https://www.pelock.com | http://www.secnews.pl
//
// dla Zaufanej Trzeciej Strony - https://zaufanatrzeciastrona.pl
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
// deklaracje (nie chce mi sie tego przenosic do .h)
//
///////////////////////////////////////////////////////////////////////////////

//
// ilosc kluczy dostepowych
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
// kombinacje kolorow dla tekstu konsoli
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
// dane
//
///////////////////////////////////////////////////////////////////////////////

//
// uchwyty watkow sprawdzajacych klucze dostepowe
//
HANDLE hThreads[KEYS_COUNT] = { nullptr };
DWORD dwThreadIds[KEYS_COUNT] = { 0 };

//
// uchwyty eventow, gdzie zasygnalizowane bedzie,
// ze podany klucz jest poprawny
// 
HANDLE hEvents[KEYS_COUNT] = { nullptr };

// tu znajdzie sie wartosc zmiennej srodowiskowej 
TCHAR wszEnvrionmentVariable[128] = { 0 };

// tu znajdzie sie zawartosc pliku "CrackMeZ3S.exe:Z3S.txt"
char szADS[128] = { 0 };

// tu znajdzie sie wartosc ciagu ze schowka
char szClipboard[128] = { 0 };

// tu znajdzie sie haslo, o ktore prosimy z konsoli (fake check)
char szPassword[128] = { 0 };

// tu znajdzie sie wersja systemu operacyjnego
OSVERSIONINFO osvi = { 0 };

// struktury do sprawdzania czasow wykonywania poszczegolnych
// fragmentow kodu
SPEED_TIME Speed[255] = { 0 };

// tu wygenerowana zostanie flaga
TCHAR wszFlag[128] = { 0 };

///////////////////////////////////////////////////////////////////////////////
//
// pobieranie poczatkowego czasu, funkcja koniecznie musi byc inline
// zeby zapobiec jej prostemu spatchowaniu w 1 punkcie
//
///////////////////////////////////////////////////////////////////////////////

void __forceinline SpeedStart(int iSpeedStructIndex)
{
	QueryPerformanceFrequency(&Speed[iSpeedStructIndex].Frequency);
	QueryPerformanceCounter(&Speed[iSpeedStructIndex].StartingTime);
}

///////////////////////////////////////////////////////////////////////////////
//
// pobieranie koncowego czasu i sprawdzanie czy przekroczyl ustalony limit
//
///////////////////////////////////////////////////////////////////////////////

void __forceinline SpeedEnd(int iSpeedStructIndex, int iMaxTimeInSeconds = 5)
{
	QueryPerformanceCounter(&Speed[iSpeedStructIndex].EndingTime);
	Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart = Speed[iSpeedStructIndex].EndingTime.QuadPart - Speed[iSpeedStructIndex].StartingTime.QuadPart;
	
	//Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart *= 1000000;
	Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart /= Speed[iSpeedStructIndex].Frequency.QuadPart;

	// sprawdz czy przekroczony zostal ustalony limit czasowy
	if (Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart > iMaxTimeInSeconds)
	{
		#ifdef _DEBUG
		_tprintf(_T("[!] przekroczono ustalony limit %i sekund dla indeksu %c, czas wykonywania %llu"), iMaxTimeInSeconds, iSpeedStructIndex, Speed[iSpeedStructIndex].ElapsedMicroseconds.QuadPart);
		#endif

		// w razie przekroczenia ustalonego limitu czasowego
		// nie wyswietlany zadnych komunikatow ostrzegawczych
		// ale uszkadzamy wewnetrze struktury CrackMe, co sprawi,
		// ze CrackMe nie bedzie funkcjonowac prawidlowo lub po
		// prostu sie zawiesi w ktoryms momencie

		// losujemy czy uszkodzic jakas strukture czy nie
		#define LOTTO_CRASH ((rand() & 6) == 0)

		// losowo wymaz uchwyt watku
		if (LOTTO_CRASH) hThreads[rand() % _countof(hThreads)] = nullptr;

		// losowo zamaz uchwyt eventa
		if (LOTTO_CRASH) hEvents[rand() % _countof(hEvents)] = reinterpret_cast<HANDLE>(rand());

		// losowo resetuj event (znacznik odnalezienia klucza dostepowego)
		if (LOTTO_CRASH) ResetEvent(hEvents[rand() % _countof(hEvents)]);

		// losowo wypelnij bufory tekstowe
		if (LOTTO_CRASH) memset(wszEnvrionmentVariable, _countof(wszEnvrionmentVariable) * sizeof(TCHAR), rand());
		if (LOTTO_CRASH) memset(szADS, sizeof(szADS), rand());
		if (LOTTO_CRASH) memset(szClipboard, sizeof(szClipboard), rand());
		if (LOTTO_CRASH) memset(szPassword, sizeof(szPassword), rand());
		if (LOTTO_CRASH) memset(wszFlag, _countof(wszFlag) * sizeof(TCHAR), rand());

		// evil asm trick ;), wskaznik stosu jest ZAWSZE wyrownany do 4,
		// tutaj sprawimy, ze bedzie niewyrownany i na 200% aplikacja
		// sie zawiesi
		if (LOTTO_CRASH) __asm inc esp
	}
}

///////////////////////////////////////////////////////////////////////////////
//
// blokowanie klawiatury i myszki, zeby funkcja nie byla zbyt widoczna
// uzyjemy dynamicznego pobierania jej adresu
//
// uwaga!
// aby funkcja BlockInput() poprawnie dzialala, aplikacja musi byc uruchomiona
// z prawami administratora
//
///////////////////////////////////////////////////////////////////////////////

BOOL __forceinline Block(BOOL bBlock = TRUE)
{
	HINSTANCE hDLL = LoadLibrary(_T("USER32.dll"));

	typedef BOOL(WINAPI *BLOCKINPUT)(BOOL);
	BLOCKINPUT pBlockInput;

	// nazwe funkcji zaszyfrujmy, zeby nie bylo jej widac w deasemblerze
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

	// nie sprawdzamy nawet czy jest zwrocony bledny wskaznik,
	// poniewaz funkcja jest dostepna od Windows 2000 i jesli
	// bylby nullptr zwrocony to znaczy, ze albo ktos cos
	// majstrowal albo siedzi na antycznym Windows NT 4
	return pBlockInput(bBlock);
}

///////////////////////////////////////////////////////////////////////////////
//
// funkcja oblicza hash MD5 i sprawdza czy pasuje do podanego
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
// Sprawdzanie poprawnosci wszystkich kluczy oraz generowanie flagi
// z pojedynczych znakow kluczy dostepowych
//
// Poprawna flaga to:
//
// "PELock v2.0"
//  01234567890
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Check(DWORD Param)
{
	SpeedStart('C');

	// Klucz 0 - falszywy klucz
	if (WaitForSingleObject(hEvents[0], 1) == WAIT_OBJECT_0)
	{
		// falszywe nadpisanie danych, znaki z tego hasla
		// i tak nie beda uzyte (zapisujemy je poza wlasciwym
		// buforem)
		wszFlag[16] = TCHAR(szPassword[4]);
		wszFlag[12] = TCHAR(szPassword[1]);

		#ifdef _DEBUG
		_tprintf(_T("[i] klucz 0 - OK\n"));
		#endif
	}

	// Klucz 1 - zmienna srodowiskowa
	if (WaitForSingleObject(hEvents[1], 1) == WAIT_OBJECT_0)
	{
		// "PELock[ ]v2.0" - "AMD64[ ]"
		wszFlag[6] = wszEnvrionmentVariable[5];

		#ifdef _DEBUG
		_tprintf(_T("[i] klucz 1 - OK\n"));
		#endif
	}

	// Klucz 2 - ADS
	if (WaitForSingleObject(hEvents[2], 1) == WAIT_OBJECT_0)
	{
		// "PELock v[2].[0]" - "[2][0]16.07"
		wszFlag[8] = TCHAR(szADS[0]);
		wszFlag[10] = TCHAR(szADS[1]);
		wszFlag[9] = TCHAR(szADS[4]);

		#ifdef _DEBUG
		_tprintf(_T("[i] klucz 2 - OK\n"));
		#endif
	}

	// Klucz 3 - zawartosc schowka
	if (WaitForSingleObject(hEvents[3], 1) == WAIT_OBJECT_0)
	{
		// "Boom Boom - Lip Lock - Song"
		wszFlag[4] = TCHAR(szClipboard[18]);
		wszFlag[3] = TCHAR(szClipboard[17]);
		wszFlag[2] = TCHAR(szClipboard[16]);
		wszFlag[5] = TCHAR(szClipboard[19]);

		#ifdef _DEBUG
		_tprintf(_T("[i] klucz 3 - OK\n"));
		#endif
	}

	// Klucz 4 - klikniecie CTRL-C
	if (WaitForSingleObject(hEvents[4], 1) == WAIT_OBJECT_0)
	{
		#ifdef _DEBUG
		_tprintf(_T("[i] klucz 4 - OK\n"));
		#endif

		// brakujaca literka
		wszFlag[7] = TCHAR('v');
	}

	// Klucz 5 - wersja systemu pasujaca do Windows Vista
	if (WaitForSingleObject(hEvents[5], 1) == WAIT_OBJECT_0)
	{
		// literka 'P' = 0x4A + 6
		wszFlag[0] = TCHAR(0x4A + osvi.dwMajorVersion);

		// literka 'E' = 0x45 - 0
		wszFlag[1] = TCHAR(0x45 - osvi.dwMinorVersion);

		#ifdef _DEBUG
		_tprintf(_T("[i] klucz 5 - OK\n"));
		#endif
	}

	SpeedEnd('C');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// handler dla skrotu CTRL-C
//
///////////////////////////////////////////////////////////////////////////////

BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
	case CTRL_C_EVENT:

		// ustaw flage oznaczajaca, ze uzytkownik kliknal CTRL-C
		SetEvent(hEvents[5]);

		return TRUE;
	}

	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////
//
// Klucz 5 - sprawdz czy uzytkownik nacisnal CTRL-C
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Klucz5(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('5');

	// ustaw obsluge CTRL-C
	SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(CtrlHandler), TRUE);

	SpeedEnd('5');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Klucz 4 - sprawdzanie trybu zgodnosci
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Klucz4(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('4');

	// odpal kolejny watek (kaskadowo)
	hThreads[5] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[5])), lpKeyProc, 0, &dwThreadIds[5]);

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	// funkcja GetVersionEx() jest juz oznaczona jako przestarzala,
	// jednak dla naszego CrackMe spelni swoja role
	#pragma warning(disable : 4996)
	GetVersionEx(&osvi);

	// numeracja bedzie pasowac do Windows Vista oraz Windows Server 2008
	// https://msdn.microsoft.com/pl-pl/library/windows/desktop/ms724833(v=vs.85).aspx
	if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
	{
		// ustaw flage oznaczajaca, ze tryb zgodnosci jest poprawnie ustawiony
		SetEvent(hEvents[4]);
	}

	SpeedEnd('4');

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Klucz 3 - sprawdzanie systemowego schowka
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Klucz3(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('3');

	// odpal kolejny watek (kaskadowo)
	hThreads[4] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[4])), lpKeyProc, 0, &dwThreadIds[4]);

	// otworz schowek
	if (OpenClipboard(nullptr) == TRUE)
	{
		// pobierz uchwyt danych w formacie CF_TEXT
		HANDLE hData = GetClipboardData(CF_TEXT);

		// czy jakies dane sa skopiowane?
		if (hData != nullptr)
		{
			// zablokuj pamiec
			char *pszText = static_cast<char *>(GlobalLock(hData));

			if (pszText != nullptr)
			{
				// hehe ;)
				if (strcmp(pszText, "Boom Boom - Lip Lock - Song") == 0)
				{
					// kopiuj zawartosc schowka do zmiennej globalnej
					strcpy_s(szClipboard, sizeof(szClipboard), pszText);

					// ustaw flage dla tego klucza
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
// Klucz 2 - sprawdzanie ADS
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Klucz2(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('2');

	// odpal kolejny watek (kaskadowo)
	hThreads[3] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[3])), lpKeyProc, 0, &dwThreadIds[3]);

	TCHAR wszPath[512] = { 0 };

	// pobierz sciezke do pliku CrackMe
	GetModuleFileName(GetModuleHandle(nullptr), wszPath, sizeof(wszPath));

	// dodaj sciezke do ADS
	_tcscat_s(wszPath, _countof(wszPath), _T(":Z3S.txt"));

	// otworz plik "CrackMeZ3S.exe:Z3S.txt"
	HANDLE hFile = CreateFile(wszPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	SpeedEnd('2');

	// czy udalo sie otworzyc plik?
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	// pobierz rozmiar tego pliku (sprawdz czy nie jest wiekszy
	// niz bufor, gdzie chcemy go odczytac)
	DWORD dwFileSize = GetFileSize(hFile, nullptr);

	if (dwFileSize > sizeof(szADS))
	{
		CloseHandle(hFile);
		return 0;
	}

	DWORD dwReadBytes = 0;

	// odczytaj zawartosc ukrytego pliku
	if (ReadFile(hFile, &szADS, dwFileSize, &dwReadBytes, nullptr) == FALSE || dwReadBytes != dwFileSize)
	{
		CloseHandle(hFile);
		return 0;
	}

	// zamknij uchwyt
	CloseHandle(hFile);

	char szTemp[sizeof(szADS)];

	strcpy_s(szTemp, _countof(szTemp), szADS);

	// odwroc kolejnosc znakow
	_strrev(szTemp);

	if (strcmp(szTemp, "\n\r70.6102") == 0)
	{
		// ustaw flage oznaczajaca, ze istnieje ADS dla pliku CrackMe
		SetEvent(hEvents[2]);
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// Klucz 1 - sprawdzanie zmiennej srodowiskowej
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Klucz1(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	SpeedStart('1');

	// odpal kolejny watek (kaskadowo)
	hThreads[2] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[2])), lpKeyProc, 0, &dwThreadIds[2]);

	// nazwe zmiennej srodowiskowej zaszyfrujemy
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
		// oczekiwana wartosc zmiennej to "AMD64 ", ja tez zaszyfrujemy
		// tak zeby trzeba bylo debuggowac CrackMe, a nie jedynie posilkowac
		// sie deasemblerem

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

		// ustaw flage oznaczajaca, ze zmienna srodowiskowa jest dostepna
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
// Falszywy klucz - dla zmarnowania czasu ;)
//
///////////////////////////////////////////////////////////////////////////////

DWORD WINAPI Klucz0(LPTHREAD_START_ROUTINE lpKeyProc[])
{
	// odpal kolejny watek (kaskadowo)
	hThreads[1] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[1])), lpKeyProc, 0, &dwThreadIds[1]);

	_tprintf(_T("Podaj tajne haslo: "));

	// odczytaj haslo jako ciag ANSI (zeby latwiej atakujacym bylo
	// znalezc niepoprawne haslo stosujac np. rainbow tables, juz
	// pojdziemy im na reke i nie bedziemy pobierac tego jako UNICODE
	gets_s(szPassword, sizeof(szPassword));

	// zacznij mierzyc czas tylko od tego momentu gets_s() by
	// to sztucznie wydluzyl
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

		// sprawdzamy hash ze slowa "fake" (https://www.pelock.com/products/hash-calculator)
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
// mechanizm TLS callback pozwala na wykonanie kodu przed
// wejsciem programu do punktu wejsciowego (EP), mozna tutaj
// ukryc inicjalizacje kilku rzeczy
//
// szczegoly implementacji w C++
// http://stackoverflow.com/questions/14538159/about-tls-callback-in-windows
//
///////////////////////////////////////////////////////////////////////////////

void NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID)
{
	// powod wywolania callbacka - dolaczenie do procesu
	// czyli uruchomienie aplikacji, dokladnie tak samo
	// jak w przypadku funkcji DllMain() w bibliotekach DLL
	// jesli to inny powod - wyjdz
	if (dwReason != DLL_PROCESS_ATTACH)
	{
		return;
	}

	// sprawdz flagi sterty, w przypadku debuggowanej
	// aplikacji sa one inne niz w przypadku normalnie
	// uruchomionej aplikacji, w razie wykrycia debuggera
	// zablokuj dzialanie aplikacji w tym punkcie
	__asm
	{
		mov     eax, dword ptr fs:[30h]
		test	dword ptr [eax + 68h], HEAP_REALLOC_IN_PLACE_ONLY or HEAP_TAIL_CHECKING_ENABLED or HEAP_FREE_CHECKING_ENABLED
		je		_no_debugger

		_spij_slodko_aniolku:

		push	1000000
		call	Sleep

		jmp		_spij_slodko_aniolku

		_no_debugger:
	}
}

// dodatkowe opcje dla linkera, zeby aktywowac TLS Callbacks
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
// poczatek programu
//
///////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[], char* envp[])
{
	//
	// inicjalizuj generator pseudolosowy dla funkcji rand()
	//
	srand(GetTickCount());

	SpeedStart('W');

	//
	// pobierz uchwyt konsoli
	//
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	//
	// wyswietl informacje powitalne
	//

	// ustaw zielony kolor tekstu
	SetConsoleTextAttribute(hConsole, ConsoleForeground::GREEN);
	_tprintf(_T("\n[i] CrackMeZ3S CTF - autor Bartosz Wojcik - https://www.pelock.com\n"));

	SetConsoleTextAttribute(hConsole, ConsoleForeground::DARKGREEN);
	_tprintf(_T("[i] dla Zaufanej Trzeciej Strony - https://zaufanatrzeciastrona.pl\n\n"));

	SetConsoleTextAttribute(hConsole, ConsoleForeground::DARKGRAY);

	SpeedEnd('W');

	//
	// tablica z adresami kolejnych funkcji sprawdzajacych
	// klucze dostepowe, wskazniki beda w niej zaszyfrowane
	// i odszyfrowane jedynie w momencie uruchomienia kolejnego
	//
	// zapisujemy tutaj adresy przesuniete o 100 bajtow do przodu
	// w kazdym deasemblerze spowoduje to maly "zamet", bo zostanie
	// to odczytane jako wskaznik do funkcji, dla wiekszej rozrywki
	// mozna tu zapisac wiecej tych elementow
	//
	#define ENCRYPTED_PTR(x, y) reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(&x) + y) 

	PVOID lpKeyProc[KEYS_COUNT] = {

		ENCRYPTED_PTR(Klucz0, 100),
		ENCRYPTED_PTR(Klucz1, 100),
		ENCRYPTED_PTR(Klucz2, 100),
		ENCRYPTED_PTR(Klucz3, 100),
		ENCRYPTED_PTR(Klucz4, 100),
		ENCRYPTED_PTR(Klucz5, 100),

	};

	SpeedStart('C');

	//
	// utworz 5 obiektow EVENT, ktore beda sluzyly
	// jako znaczniki poprawnosci kluczy dostepowych
	// dodatkowo zaszyfruj wskazniki do funkcji
	// sprawdzajacych poprawnosci kluczy
	//
	for (int i = 0; i < KEYS_COUNT; i++)
	{
		hEvents[i] = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		lpKeyProc[i] = static_cast<LPTHREAD_START_ROUTINE>(EncodePointer(reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(lpKeyProc[i]) - 100)));
	}

	//
	// odpal pierwszy watek do falszywego sprawdzenia numeru seryjnego
	// w nim zostana uruchomione kolejne watki, do kolejnych metod
	// sprawdzajacych klucze dostepowe
	//
	hThreads[0] = CreateThread(nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(DecodePointer(lpKeyProc[0])), lpKeyProc, 0, &dwThreadIds[0]);

	SpeedEnd('C');

	// zaczekaj az wszystkie watki zostana zainicjalizowane (jakby ktos
	// chcial cos pominac), watki sa odpalane kaskadowo, wiec ich
	// wszystkie uchwyty nie beda w tym momencie ustawione, dlatego nie
	// mozna od razu uzyc WaitForMultipleObjects()
	for (int i = 0; i < _countof(hThreads); i++)
	{
		while (hThreads[i] == nullptr)
		{
			OutputDebugString(_T("Co slychac doktorku?"));
		}
	}

	// zaczekaj az watki zakoncza prace
	WaitForMultipleObjects(_countof(hThreads), hThreads, TRUE, INFINITE);

	SpeedStart('V');

	// sprawdz poprawnosc kluczy
	Check(0);

	#ifdef _DEBUG
	_tprintf(_T("[i] flaga - \"%s\"\n"), wszFlag);
	#endif

	//
	// oblicz MD5 z ciagu tekstowego flagi oraz soli
	// (aby zapobiec atakom brute-force)
	// ma to na celu unikniecie sytuacji, w ktorej
	// ktos chcialby ominac czesc zabezpieczen (np.
	// recznie ustawiajac EVENTy)
	//
	TCHAR wszFlagSalty[128];

	_stprintf_s(wszFlagSalty, _T("#flag4poprawna %s \n123458s3cr3t _+=-=-="), wszFlag);

	// hash liczymy z ciagu TCHAR, a wynik otrzymamy w postaci ciagu ANSI
	BOOL bValidFlag = CheckMD5(wszFlagSalty, _tcslen(wszFlagSalty) * sizeof(TCHAR), "4ED28DA4AAE4F2D58BF52EB0FE09F40B");

	SpeedEnd('V');

	if (bValidFlag == TRUE)
	{
		SpeedStart('S');

		_tprintf(_T("\n"));

		// tresc komunikatu o sukcesie zaszyfrujemy, zeby nie bylo jej
		// widac w deasemblerze

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

		// wyswietl losowy tekst o niepowodzeniu :P
		_putts(pwszFail[rand() % _countof(pwszFail)]);
	}

	// przywroc domyslny kolor
	SetConsoleTextAttribute(hConsole, ConsoleForeground::DARKGRAY);

	_tprintf(_T("\nNacisnij dowolny klawisz, aby kontynuowac..."));

	_getch();

	return 0;
}

