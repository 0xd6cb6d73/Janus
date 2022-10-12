#include <Windows.h>
#include <iostream>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#pragma warning(disable : 4996)

typedef char JANUS;

extern unsigned char* decrypted;

unsigned char* decode64(const char* input, int length);

CHAR* Deobfuscate(char* cBuffer);