#pragma once

#include "pch.h"
#include <SimpleIni.h>

static CSimpleIni ini;

namespace util {
	VOID LoadConfig();
	static const char* ClientVersion;
	static const char* RSAPublicKey;
	static const char* RSAPrivateKey;
	const char* GetRSAPublicKey();
	const char* GetRSAPrivateKey();
	long GetOffsetValue(const char* a_pKey, long a_pDefault);
	VOID SaveConfig();
	VOID InitConsole();
	VOID DisableLogReport();
	VOID DisableVMProtect();
	VOID Dump(VOID* ptr, int buflen);
	VOID HexDump(VOID* ptr, int buflen);
}
