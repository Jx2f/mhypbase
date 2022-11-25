#pragma once

#include "pch.h"
#include <SimpleIni.h>

static CSimpleIni ini;

namespace util {
	VOID LoadConfig();
	static const char* ClientVersion;
	static const char* PublicRSAKey;
	static const char* PrivateRSAKey;
	const char* GetPublicRSAKey();
	const char* GetPrivateRSAKey();
	long GetOffsetValue(const char* a_pKey, long a_pDefault);
	VOID SaveConfig();
	VOID InitConsole();
	VOID DisableLogReport();
	VOID DisableVMProtect();
	VOID Dump(VOID* ptr, int buflen);
	VOID HexDump(VOID* ptr, int buflen);
}
