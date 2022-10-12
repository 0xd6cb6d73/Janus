#include <Windows.h>
#include <Shlwapi.h>
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include "IScramble.h"

#pragma comment(lib, "shlwapi.lib")

static enum StringType : unsigned int {
	stWCHAR = 1,
	stCHAR = 2
};

typedef struct _JANUS_NODE {
	WCHAR*		wcFilePath;

	INT64		iLineNumber;
	INT64		iStartIndex;
	INT64		iLength;

	StringType	eStringType;
	CHAR*		cString;
	INT64		iBinLength;

	_JANUS_NODE* pNextNode;

}JANUS_NODE, *PJANUS_NODE, *PJANUS_LIST;

BOOL g_bModificationError = FALSE;
IScramble* g_pScram = NULL;
WCHAR* g_wcOutDir = NULL;

BOOL GenerateModifiedFiles(WCHAR* pszRoot, PJANUS_LIST& pJanusList);

BOOL ProcessFile(WCHAR* wcPath, PJANUS_LIST& pJanusList);
BOOL ParseLine(StringType stType, char* cStart, INT64 iLength, LPBYTE& lpbOutput, INT32& iOutputLen, char*& cVarName, INT32& iVarNameLen);
BOOL GenerateLineNumberList(WCHAR* wcFilePath, DWORD*& dwLineStartList, DWORD& dwNumLines);

BOOL ConvertQuoteToBytes(CHAR* cStringToConvert, int iStringToConvertLen, LPBYTE& lpbBytes, INT32& iBytesLen);
BOOL ConvertBraceToBytes(CHAR* cStringToConvert, int iStringToConvertLen, LPBYTE& lpbBytes, INT32& iBytesLen);

BOOL ProcessFile(WCHAR* wcPath, PJANUS_LIST& pJanusList) {
	if (wcPath == NULL) {
		return FALSE;
	}

	BOOL bRet = FALSE;

	//Read in entire file
	HANDLE hSrcFile = CreateFileW(wcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSrcFile == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] Failed to open file for read\n");
		return FALSE;
	}

	DWORD dwRWBytes = 0;
	DWORD dwFileSize = GetFileSize(hSrcFile, NULL);
	LPBYTE lpbFile = NULL;
	lpbFile = (LPBYTE)calloc(1, dwFileSize + 1);
	if (ReadFile(hSrcFile, lpbFile, dwFileSize, &dwRWBytes, NULL) == FALSE) {
		wprintf(L"[!] Error reading file\n");
		CloseHandle(hSrcFile);
		return FALSE;
	}
	CloseHandle(hSrcFile);
	
	//Scan file in loop and build nodes
	PJANUS_LIST pList = NULL;
	INT64 iCurrentIndex = 0;
	BOOL bError = FALSE;
	INT64 iPosit = std::string((CHAR*)lpbFile).find("JANUS", 0, strlen("JANUS"));
	while (iPosit >= 0 && !bError) {

		//Create Node containing info about string to scramble
		PJANUS_NODE pNode = (PJANUS_NODE)calloc(sizeof(JANUS_NODE), 1);
		pNode->iStartIndex = iCurrentIndex + iPosit;

		//Make copy of file name - we'll want to keep a gold copy before modifying anything
		pNode->wcFilePath = (WCHAR*)calloc(sizeof(WCHAR), wcslen(wcPath) + 1);
		memcpy(pNode->wcFilePath, wcPath, wcslen(wcPath) * sizeof(WCHAR));
		pNode->eStringType = stCHAR;

		//Determine length of statement
		INT64 iStart = pNode->iStartIndex;
		BOOL bFoundEnd = FALSE;
		BOOL bInQuotes = FALSE;
		while (iStart < dwFileSize && !bFoundEnd) {
			if (lpbFile[iStart] == '\"') {
				if (iStart > 0) {
					//Go backwards until not a backslash counting backslashes (if odd then we're escaped - even we're not)
					INT64 iTempCount = iStart - 1;
					BOOL bIsBackSlash = TRUE;
					DWORD dwBackCount = 0;
					while (iTempCount > pNode->iStartIndex && bIsBackSlash) {
						if (lpbFile[iTempCount] != '\\') {
							bIsBackSlash = FALSE;
						}
						else {
							iTempCount--;
							dwBackCount++;
						}

						DWORD dwIsEscaped = dwBackCount % 2;
						if (dwIsEscaped == 0) {
							bInQuotes ^= 0x1;
						}
					}
				}
			}

			if (lpbFile[iStart] == ';' && !bInQuotes) {
				bFoundEnd = TRUE;
			}
			iStart++;
		}

		if (!bFoundEnd) {
			bError = TRUE;
		}
		else {
			pNode->iLength = iStart - pNode->iStartIndex;
		}

		if (!bError) {
			iCurrentIndex = pNode->iStartIndex + pNode->iLength;
			pNode->pNextNode = pList;
			pList = pNode;
		}
		else {
			//Free Node
			if (pNode->wcFilePath) {
				free(pNode->wcFilePath);
			}
			free(pNode);
		}
		iPosit = std::string((CHAR*)lpbFile + iCurrentIndex).find("JANUS", 0, strlen("JANUS"));
	}

	if (bError) {
		//Add to list
		pJanusList = pList;
		bRet = FALSE;
		goto freelist;
	}
	if (pList == NULL) {
		bRet = TRUE;
		goto cleanup;
	}

	wprintf(L"[+] Processing File: %s\n", wcPath);

	//Copy off original
	WCHAR* wcGoldPath = (WCHAR*)calloc(sizeof(WCHAR), wcslen(wcPath) + wcslen(L".janus") + 1);
	swprintf(wcGoldPath, L"%s.janus", wcPath);
	BOOL bCopySuccess = CopyFileW(wcPath, wcGoldPath, TRUE);
	DWORD dwAttribs = GetFileAttributesW(wcGoldPath);
	free(wcGoldPath);

	if (!bCopySuccess || dwAttribs == INVALID_FILE_ATTRIBUTES) {
		
		//Add to list
		pJanusList = pList;
		bRet = FALSE;
		goto freelist;
	}

	//Build Line Number List
	DWORD* dwLineStartList = NULL;
	DWORD dwNumLines = 0;
	GenerateLineNumberList(wcPath, dwLineStartList, dwNumLines);

	//Loop through, get string, scramble and write file
	PJANUS_NODE pNode = pList;
	//printf("%lld\n", pNode->iStartIndex);
	while (pNode != NULL) {

		//Translate string to byte array - get varaible name
		LPBYTE lpbLine = NULL;
		INT32 iLineLen = 0;
		CHAR* cVarName = NULL;
		INT32 iVarNameLen = 0;
		BOOL bParsed = ParseLine(pNode->eStringType, (CHAR*)lpbFile + pNode->iStartIndex, pNode->iLength, lpbLine, iLineLen, cVarName, iVarNameLen);

		if (!bParsed || cVarName == NULL || iVarNameLen <= 0 || lpbLine == NULL || iLineLen <= 0) { //If there is an error in parsing, go ahead and bail
			
			//Cleanup
			if (cVarName) {
				free(cVarName);
			}
			if (lpbLine) {
				free(lpbLine);
			}

			//Add to list
			pJanusList = pList;
			bRet = FALSE;
			wprintf(L"[!] Failure parsing string at offset %lld in %s\n", pNode->iStartIndex, wcPath);
			goto freelist;
		}

		//Determine Line Number
		if (dwLineStartList != NULL)
		{
			BOOL bFoundLineNum = FALSE;
			DWORD dwIndex = 0;
			while (dwIndex < dwNumLines && !bFoundLineNum)
			{
				if (pNode->iStartIndex == dwLineStartList[dwIndex])
				{
					pNode->iLineNumber = dwIndex + 1;
					bFoundLineNum = TRUE;
				}
				else if (pNode->iStartIndex < dwLineStartList[dwIndex])
				{
					pNode->iLineNumber = dwIndex;
					bFoundLineNum = TRUE;
				}

				dwIndex++;
			}
		}

		//Print out line numbers
		{
			WCHAR wcLineNum[MAX_PATH] = { 0 };
			swprintf(wcLineNum, L"[+] Scrambling Line %lld\n", pNode->iLineNumber);
			wprintf(wcLineNum);
		}

		//Make copies, store original hex for review
		DWORD dwCharSize = sizeof(CHAR);
		if (pNode->eStringType == stWCHAR) {
			dwCharSize = sizeof(WCHAR);
		}

		pNode->cString = (CHAR*)calloc(dwCharSize, iLineLen);
		memcpy(pNode->cString, lpbLine, iLineLen* dwCharSize);
		pNode->iBinLength = iLineLen * dwCharSize;

		//Scramble String, Create Literal, Generate Insert
		CHAR* asciiBase64Enc = NULL;
		CHAR* cLiteral = NULL;
		CHAR* cInsert = NULL;
		BOOL bModError = FALSE;
		//TODO: Error reporting
		printf("[+] Original: %s\n", (CHAR*)lpbLine);
		int iResult = g_pScram->ScrambleA((unsigned char*)lpbLine, iLineLen);
		if (iResult > 0) {
			asciiBase64Enc = g_pScram->base64(g_pScram->encrypted, iResult);
			printf("[+] Base64: %s\n", asciiBase64Enc);
			free(g_pScram->encrypted);
			iResult = g_pScram->GenerateInsertA(cVarName, asciiBase64Enc, sizeof(asciiBase64Enc), cInsert);
			if (iResult <= 0) {
				bModError = TRUE;
			}
		}
		else {
			bModError = TRUE;
		}

		//Done with literal, line and variable
		if (cVarName) {
			free(cVarName);
		}
		if (lpbLine) {
			free(lpbLine);
		}
		if (cLiteral) {
			free(cLiteral);
		}
		if (asciiBase64Enc) {
			free(asciiBase64Enc);
		}

		if (bModError || cInsert == NULL) {
			
			//Free and release
			wprintf(L"[!] Failed to obfuscate line %lld\n", pNode->iLineNumber);
			if (cInsert) {
				free(cInsert);
			}

			//Add to list
			pJanusList = pList;
			bRet = FALSE;
			goto freelist;
		}

		//Write File With Modifications
		LPBYTE lpbTemp = lpbFile;
		DWORD dwTempLen = dwFileSize;

		//New Length of file
		dwFileSize = dwTempLen + strlen(cInsert) - pNode->iLength;
		lpbFile = (LPBYTE)calloc(sizeof(CHAR), dwFileSize);

		memcpy(lpbFile, lpbTemp, pNode->iStartIndex);
		memcpy(lpbFile + pNode->iStartIndex, cInsert, strlen(cInsert));
		memcpy(lpbFile + pNode->iStartIndex + strlen(cInsert), lpbTemp + pNode->iStartIndex + pNode->iLength, dwTempLen - pNode->iStartIndex - pNode->iLength);

		free(cInsert);
		free(lpbTemp);
		lpbTemp = NULL;
		dwTempLen = 0;

		if (pNode->pNextNode == NULL) {
			pNode->pNextNode = pJanusList;		//Set Last Node To Head Of Janus List
			pNode = NULL;
		}
		else {
			pNode = pNode->pNextNode;
		}
	}

	pJanusList = pList;
	if (dwLineStartList) {
		free(dwLineStartList);
	}

	//Flush File if no errors
	hSrcFile = CreateFile(wcPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSrcFile == INVALID_HANDLE_VALUE) {
		bRet = FALSE;
		goto freelist;
	}

	WriteFile(hSrcFile, lpbFile, dwFileSize, &dwRWBytes, NULL);
	SetEndOfFile(hSrcFile);
	CloseHandle(hSrcFile);
	bRet = TRUE;
	wprintf(L"[+] Successfully modified\n");
	goto cleanup;

freelist:
	{
		//Freeing list of nodes
		wprintf(L"[+] Freeing list of nodes\n");
		PJANUS_NODE pCurrent = (PJANUS_NODE)pJanusList;
		while (pCurrent != NULL) {
			
			PJANUS_NODE pTemp = (PJANUS_NODE)pCurrent;
			pCurrent = pCurrent->pNextNode;

			if (pTemp->wcFilePath) {
				free(pTemp->wcFilePath);
			}
			if (pTemp->cString) {
				free(pTemp->cString);
			}
			free(pTemp);
		}
		pJanusList = NULL;
	}

cleanup:
	free(lpbFile);
	return bRet;
}

BOOL ParseLine(StringType stType, char* cStart, INT64 iLength, LPBYTE& lpbOutput, INT32& iOutputLen, char*& cVarName, INT32& iVarNameLen) {

	//Validate Args
	if (cStart == NULL || iLength <= 0) {
		return FALSE;
	}

	lpbOutput = NULL;
	iOutputLen = 0;
	cVarName = NULL;
	iVarNameLen = 0;

	//Get Variable Name
	BOOL bFoundVarName = FALSE;
	DWORD dwVarStart = 0;
	DWORD dwVarEnd = 0;
	DWORD dwIndex = strlen("JANUS");
	while (dwIndex < iLength && !bFoundVarName) {
		if (dwVarStart == 0 && cStart[dwIndex] != 0x20) {
			dwVarStart = dwIndex;
		}
		if (dwVarEnd <= dwVarStart && cStart[dwIndex] == '[') { //If not the right format, error out
			dwVarEnd = dwIndex;
			bFoundVarName = TRUE;
		}
		
		dwIndex++;
	}

	if (dwVarEnd <= dwVarStart || !bFoundVarName) {
		return FALSE;
	}

	iVarNameLen = dwVarEnd - dwVarStart;
	cVarName = (CHAR*)calloc(sizeof(CHAR), iVarNameLen + 1);
	memcpy(cVarName, cStart + dwVarStart, iVarNameLen);

	//Parse string to get bytes - handle char cstring[] = "\x22\x33"; and char cstring[] = { 0x22, 0x33 };
	BOOL bFoundString = FALSE;
	BOOL bFoundEquals = FALSE;
	DWORD dwStringStart = 0;
	DWORD dwStringEnd = 0;
	BOOL isQuotedString = TRUE;
	while (dwIndex < iLength && !bFoundString) {
		
		if (!bFoundEquals && cStart[dwIndex] == '=') {
			bFoundEquals = TRUE;
		}

		if (bFoundEquals && dwStringStart == 0 && (cStart[dwIndex] == '\"' || cStart[dwIndex] == '{')) {
			dwStringStart = dwIndex + 1;
			if (cStart[dwIndex] == '{') {
				isQuotedString = FALSE;
			}
		}
		else if (bFoundEquals && dwStringStart != 0 && (cStart[dwIndex] == '\"' || cStart[dwIndex] == '}')) {
			bFoundString = TRUE;
			if (isQuotedString && cStart[dwIndex] == '\"') {
				
				//Go backwards until not a backslash counting backslashes (if odd then we're escaped - even we're not)
				DWORD dwCount = dwIndex - 1;
				BOOL bIsBackSlash = TRUE;
				DWORD dwBackCount = 0;
				while (dwCount >= dwStringStart && bIsBackSlash) {
					if (cStart[dwCount] != '\\') {
						bIsBackSlash = FALSE;
					}
					else {
						dwCount--;
						dwBackCount++;
					}
				}

				DWORD dwIsEscaped = dwBackCount % 2;
				if (dwIsEscaped == 0) {
					dwStringEnd = dwIndex;
				}
				else {
					bFoundString = FALSE;
				}
			}
			else if (!isQuotedString && cStart[dwIndex] == '}') {
				dwStringEnd = dwIndex;
			}
			else {
				bFoundString = FALSE;
			}
		}

		dwIndex++;
	}

	if (!bFoundString || dwStringStart >= dwStringEnd) {
		
		//Cleanup and return FALSE
		free(cVarName);
		cVarName = NULL;
		return FALSE;
	}

	//Convert to bytes - WCHAR vs CHAR
	BOOL bConverted = FALSE;
	if (isQuotedString) {
		if (stType == stCHAR) {
			bConverted = ConvertQuoteToBytes(cStart + dwStringStart, dwStringEnd - dwStringStart, lpbOutput, iOutputLen);
		}
	}
	else {
		if (stType == stCHAR) {
			bConverted = ConvertBraceToBytes(cStart + dwStringStart, dwStringEnd - dwStringStart, lpbOutput, iOutputLen);
		}
	}

	if (!bConverted) {
		
		//Cleanup return FALSE
		free(cVarName);
		cVarName = NULL;

		free(lpbOutput);
		lpbOutput = NULL;
	}

	return TRUE;
}

BOOL ConvertQuoteToBytes(CHAR* cStringToConvert, int iStringToConvertLen, LPBYTE& lpbBytes, INT32& iBytesLen)
{
	if (cStringToConvert == NULL || iStringToConvertLen <= 0)
		return FALSE;

	lpbBytes = (LPBYTE)calloc(sizeof(CHAR), iStringToConvertLen + 1);
	iBytesLen = 0;
	INT32 iBytesIndex = 0;

	BOOL bRet = TRUE;

	//Char by char converting the string to bytes
	for (int i = 0; i < iStringToConvertLen; i++, iBytesIndex++)
	{
		if (cStringToConvert[i] == '\\' && i < iStringToConvertLen - 1)
		{
			switch (cStringToConvert[i + 1])
			{
			case 'n':
				lpbBytes[iBytesIndex] = '\n';
				break;
			case 't':
				lpbBytes[iBytesIndex] = '\t';
				break;
			case 'v':
				lpbBytes[iBytesIndex] = '\v';
				break;
			case 'b':
				lpbBytes[iBytesIndex] = '\b';
				break;
			case 'r':
				lpbBytes[iBytesIndex] = '\r';
				break;
			case 'f':
				lpbBytes[iBytesIndex] = '\f';
				break;
			case 'a':
				lpbBytes[iBytesIndex] = '\a';
				break;
			case '\\':
				lpbBytes[iBytesIndex] = '\\';
				break;
			case '?':
				lpbBytes[iBytesIndex] = '\?';
				break;
			case '\'':
				lpbBytes[iBytesIndex] = '\'';
				break;
			case '\"':
				lpbBytes[iBytesIndex] = '\"';
				break;
			case '\0':
				lpbBytes[iBytesIndex] = '\"';
				break;
			case 'x':
			{
				if (!(i < iStringToConvertLen - 3))
					bRet = FALSE;
				else
				{
					//Convert from hexascii
					CHAR cTemp[2] = { 0 };
					CHAR cTemp2[2] = { 0 };
					cTemp[0] = cStringToConvert[i + 2];
					cTemp[1] = cStringToConvert[i + 3];
					DWORD dwTempLen = 2;
					CryptStringToBinaryA(cTemp, 2, CRYPT_STRING_HEXASCII, (BYTE*)cTemp2, &dwTempLen, NULL, NULL);

					//Convert to hex
					lpbBytes[iBytesIndex] = cTemp2[0];
					i += 2;
				}
			}
			break;
			default:
			{
				//Octal - no support
				bRet = FALSE;
			}
			break;
			}
			i++;
		}
		else
			lpbBytes[iBytesIndex] = cStringToConvert[i];
	}
	iBytesLen = iBytesIndex;


	if (!bRet)
	{
		if (lpbBytes)
			free(lpbBytes);
		lpbBytes = NULL;
		iBytesLen = 0;
	}

	return bRet;
}

BOOL ConvertBraceToBytes(CHAR* cStringToConvert, int iStringToConvertLen, LPBYTE& lpbBytes, INT32& iBytesLen)
{
	if (cStringToConvert == NULL || iStringToConvertLen <= 0)
		return FALSE;

	lpbBytes = (LPBYTE)calloc(sizeof(CHAR), iStringToConvertLen);
	iBytesLen = 0;
	INT32 iBytesIndex = 0;

	BOOL bRet = TRUE;

	//Char by char converting the string to bytes
	for (int i = 0; i < iStringToConvertLen; i++)
	{
		if ((cStringToConvert[i] == 'x' || cStringToConvert[i] == 'X') && i < iStringToConvertLen - 2)
		{
			CHAR cTemp[2] = { 0 };
			CHAR cTemp2[2] = { 0 };
			cTemp[0] = cStringToConvert[i + 1];
			cTemp[1] = cStringToConvert[i + 2];
			DWORD dwTempLen = 2;
			CryptStringToBinaryA(cTemp, 2, CRYPT_STRING_HEXASCII, (BYTE*)cTemp2, &dwTempLen, NULL, NULL);

			//Convert to hex
			lpbBytes[iBytesIndex] = cTemp2[0];
			i += 2;
			iBytesIndex++;
		}
	}

	iBytesLen = iBytesIndex;

	if (!bRet)
	{
		if (lpbBytes)
			free(lpbBytes);
		lpbBytes = NULL;
		iBytesLen = 0;
	}

	return bRet;
}

BOOL GenerateLineNumberList(WCHAR* wcFilePath, DWORD*& dwLineStartList, DWORD& dwNumLines) {
	if (wcFilePath == NULL) {
		return FALSE;
	}

	dwLineStartList = NULL;
	dwNumLines = 0;
	std::string line;

	std::ifstream fsParseFile(wcFilePath, std::ifstream::in);
	if (fsParseFile.is_open()) {
		//Roll through once counting how many lines there are
		while (std::getline(fsParseFile, line)) {
			dwNumLines++;
		}

		//Alloc necessary mem
		dwLineStartList = (DWORD*)calloc(sizeof(DWORD), dwNumLines);

		//Roll through and set start indexes
		fsParseFile.clear();
		fsParseFile.seekg(0);
		DWORD dwIndex = 1;
		while (std::getline(fsParseFile, line) && dwIndex < dwNumLines) {
			dwLineStartList[dwIndex] = fsParseFile.tellg();
			dwIndex++;
		}

		fsParseFile.close();
	}

	return TRUE;
}

BOOL GenerateModifiedFiles(WCHAR* pszRoot, PJANUS_LIST &pJanusList) {
	if (pszRoot == NULL) {
		return FALSE;
	}

	WIN32_FIND_DATAW FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	DWORD dwRootLength = lstrlenW(pszRoot);
	BOOL bHasBackSlash = FALSE;

	if (pszRoot[dwRootLength - 1] == '\\') {
		bHasBackSlash = TRUE;
	}

	LPWSTR pszSearchPath;
	pszSearchPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (dwRootLength + 10) * sizeof(WCHAR));
	if (pszSearchPath == NULL) {
		return FALSE; //Failed to allocate...
	}

	LPWSTR pszFullPath;
	pszFullPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (dwRootLength + (MAX_PATH * 2) + 2) * sizeof(WCHAR));
	if (pszFullPath == NULL) {
		HeapFree(GetProcessHeap(), 0, pszSearchPath);
		return FALSE; //Failed to allocate...
	}

	if (bHasBackSlash) {
		wsprintfW(pszSearchPath, L"%s*.*", pszRoot); //Copy our path over and append *.*
	}
	else {
		wsprintfW(pszSearchPath, L"%s\\*.*", pszRoot); //Copy our path over and append *.*
	}

	if ((hFind = FindFirstFileW(pszSearchPath, &FindFileData)) != INVALID_HANDLE_VALUE) { //Find the first file
		do { //Go until there are no more files
			if (lstrcmpW(L".", FindFileData.cFileName) == 0 || lstrcmpW(L"..", FindFileData.cFileName) == 0 || (lstrcmpW(L"Janus", FindFileData.cFileName) == 0 && FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { //THE DOT AND DOTDOT FOLDERS, IGNORE THESE
				continue;
			}
			if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) { //If we are a directory
				if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
					continue;
				}
				else { //This is a folder we want to look through
					if (bHasBackSlash) {
						wsprintfW(pszFullPath, L"%s%s", pszRoot, FindFileData.cFileName);
					}
					else {
						wsprintfW(pszFullPath, L"%s\\%s", pszRoot, FindFileData.cFileName);
					}
					GenerateModifiedFiles(pszFullPath, pJanusList);
				}
			}
			else {
				if (bHasBackSlash) {
					wsprintf(pszFullPath, L"%s%s", pszRoot, FindFileData.cFileName);
				}
				else {
					wsprintf(pszFullPath, L"%s\\%s", pszRoot, FindFileData.cFileName);
				}

				//Process file(s)
				if (PathMatchSpecW(pszFullPath, L"*.c") || PathMatchSpecW(pszFullPath, L"*.cpp") || PathMatchSpecW(pszFullPath, L"*.h")) {
					if (!PathMatchSpec(FindFileData.cFileName, L"Janus.*")) {
						BOOL bProcessed = ProcessFile(pszFullPath, pJanusList);
						//Global flag for error 
						if (!bProcessed) {
							g_bModificationError = TRUE;
						}
					}
				}
			}

		} while (FindNextFile(hFind, &FindFileData) && !g_bModificationError); //Keep going until we are out of files, passed the threshold, or stop mutex is present 
	}

	if (hFind != INVALID_HANDLE_VALUE) { //We found everything, close the handle
		FindClose(hFind);
	}
	
	HeapFree(GetProcessHeap(), 0, pszSearchPath);
	HeapFree(GetProcessHeap(), 0, pszFullPath);

	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

	//Validate Args
	if (__argc != 2) {
		wprintf(L"[!] USAGE: $(SolutionDir)");
		return 0;
	}
	
	INT32 iRet = -1;
	PJANUS_LIST pJanusList = NULL;

	g_pScram = new IScramble;
	if (g_pScram->InitializeRSA() == FALSE) {
		wprintf(L"[!] InitializeRSA() failed");
		return 0;
	}

	g_wcOutDir = __wargv[1];
	wprintf(L"[+] Obfuscating contents of %s\n", g_wcOutDir);

	//Generate linked list of modifications for WARBLE, CARBLE, and BARBLE, cache files ---- ALL FAILURES FROM THIS POINT ON RESULT IN A REST OF FILES
	GenerateModifiedFiles(g_wcOutDir, pJanusList);
	if (g_bModificationError) {
		wprintf(L"[!] Error in modifying files... Resetting to original files\n");
		goto reset;
	}
	else if (pJanusList == NULL) {
		iRet = 0;
		wprintf(L"[!] Failed to find data to obfuscate\n");

		//Restore Janus to original state...
		goto nostrings;
	}

	iRet = 0;
	if (!g_bModificationError) { //If no errors, free linked list and return 0
		goto cleanup;
	}

reset:
	iRet = -1;
	//Call post-build to clean up mistakes
	wprintf(L"[!] Failure in Obfuscating Strings, Restoring Files");

nostrings:
	{
		iRet = 0;
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);
		WCHAR wcApp[MAX_PATH] = { 0 };
		swprintf(wcApp, L"Elyashib.exe \"%s\"", __wargv[1]);

		if (CreateProcess(NULL, wcApp, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
		else {
			wprintf(L"[!] Failed to run Elyashib Application");
		}
	}

cleanup:
	//Free linked list of Janus Nodes
	PJANUS_NODE pCurrentNode = pJanusList;
	while (pCurrentNode != NULL) {

		PJANUS_NODE pTempNode = pCurrentNode;
		pCurrentNode = pCurrentNode->pNextNode;

		if (pTempNode->wcFilePath) {
			free(pTempNode->wcFilePath);
		}
		if (pTempNode->cString) {
			free(pTempNode->cString);
		}

		free(pTempNode);
	}

	//Delete Scrambler Object and RSA Object (public key)
	if (g_pScram) {
		RSA_free(g_pScram->pubKey);
		delete g_pScram;
	}

	wprintf(L"\n\n");

	return iRet;
}