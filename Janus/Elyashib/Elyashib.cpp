#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#pragma comment (lib, "shlwapi.lib")

BOOL RestoreFiles(WCHAR* pszRoot);

int wmain(int argc, wchar_t* argv[]) {

	INT32 iRet = 0;

	//Validate Args
	if (__argc < 2) {
		wprintf(L"[!} USAGE: $(SolutionDir)");
		return iRet;
	}

	WCHAR* wcRootDir = (WCHAR*)calloc(sizeof(WCHAR), wcslen(__wargv[1]) + 1);
	if (!wcRootDir) {
		wprintf(L"[!] Memory allocation failed");
		return 0;
	}
	memcpy(wcRootDir, __wargv[1], wcslen(__wargv[1]) * sizeof(WCHAR));
	wprintf(L"[+] Attempting to restore files in %s\n", wcRootDir);

	//Restore .*.janus to .*
	RestoreFiles(wcRootDir);
	free(wcRootDir);

	return 0;
}

BOOL RestoreFiles(WCHAR* pszRoot) {
	if (pszRoot == NULL) {
		return FALSE;
	}

	WIN32_FIND_DATA FindFileData;				//Our FindFirst FindNext file data
	HANDLE hFind = INVALID_HANDLE_VALUE;		//Handle to the found file

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
		wsprintfW(pszSearchPath, L"%s*.*", pszRoot);	//Copy our path over and append *.*
	}
	else {
		wsprintfW(pszSearchPath, L"%s\\*.*", pszRoot);	//Copy our path over and append *.*
	}

	if ((hFind = FindFirstFileW(pszSearchPath, &FindFileData)) != INVALID_HANDLE_VALUE) { //Finde the first file.
		
		do { //Go until there are no more.
			if (lstrcmp(L".", FindFileData.cFileName) == 0 || lstrcmp(L"..", FindFileData.cFileName) == 0 || (lstrcmp(L"Janus", FindFileData.cFileName) == 0 && FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { //The dot and dotdot folders, ignore these.
				continue;
			}
			if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {		//If we are a directory.
				if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
					continue;
				}
				else { //This is a folder we want to look through
					if (bHasBackSlash) {
						wsprintf(pszFullPath, L"%s%s", pszRoot, FindFileData.cFileName);
					}
					else {
						wsprintf(pszFullPath, L"%s\\%s", pszRoot, FindFileData.cFileName);
					}
					RestoreFiles(pszFullPath);
				}
			}
			else {
				if (bHasBackSlash) {
					wsprintf(pszFullPath, L"%s%s", pszRoot, FindFileData.cFileName);
				}
				else {
					wsprintf(pszFullPath, L"%s\\%s", pszRoot, FindFileData.cFileName);
				}

				//Process File
				if (PathMatchSpec(pszFullPath, L"*.janus")) {
					wprintf(L"[+] Restoring File: ");
					//Restore to original path
					DWORD dwPathLen = wcslen(pszFullPath);
					if (dwPathLen < 8) {
						wprintf(L"[!] Invalid File Path\n");
					}
					else {
						WCHAR* wcDest = (WCHAR*)calloc(sizeof(WCHAR), dwPathLen + 1);
						if (!wcDest) {
							wprintf(L"[!] Memory allocation failed");
							return FALSE;
						}
						memcpy(wcDest, pszFullPath, (dwPathLen - 7) * sizeof(WCHAR));
						wprintf(wcDest);
						wprintf(L"\n");

						BOOL bCopied = CopyFile(pszFullPath, wcDest, FALSE);
						if (bCopied) {
							wprintf(L"[+] Successful restoration\n");
							DeleteFile(pszFullPath);
						}
						else {
							wprintf(L"[!] Failed to restore file\n");
						}

						free(wcDest);
					}
				}
			}
		} while (FindNextFile(hFind, &FindFileData));	//Keep going until we are out of files, passed the threshold, or stop mutex is present
	} 

	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);	//We found everything, close the handle
	}

	HeapFree(GetProcessHeap(), 0, pszSearchPath);
	HeapFree(GetProcessHeap(), 0, pszFullPath);

	return TRUE;
}