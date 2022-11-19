using namespace app;

// 40 55 48 83 EC 40 48 8D 6C 24 20 48 C7 45 08 FE FF FF FF 8B 04 24 48 83 EC 10 8B 04 24 C7
DO_APP_FUNC(0, LPVOID, System__Text__EncodingHelper_GetDefaultEncoding, ());

// 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 40 48 8B FA 48 8B F1 48 85
DO_APP_FUNC(0, LPVOID, System__Text__Encoding_GetBytes, (LPVOID __this, LPVOID str));

// 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 85 DB 74 7B
DO_APP_FUNC(0, LPVOID, MiHoYo__SDK__SDKUtil_RSAEncrypt, (LPVOID publicKey, LPVOID content));

// 3C 52 53 41 4B 65 79 56
DO_APP_FUNC(0, LPVOID, MoleMole__MoleMoleSecurity_GetPublicRSAKey, ());

// 3C 52 53 41 4B 65 79 56
DO_APP_FUNC(0, LPVOID, MoleMole__MoleMoleSecurity_GetPrivateRSAKey, ());

// ?? ?? ?? ?? ?? ?? ?? ??
DO_APP_FUNC(0, LPVOID, MoleMole__FightModule_OnWindSeedClientNotify, (LPVOID __this, LPVOID notify));

// ?? ?? ?? ?? ?? ?? ?? ??
DO_APP_FUNC(0, LPVOID, MoleMole__PlayerModule_OnWindSeedClientNotify, (LPVOID __this, LPVOID notify));

// ?? ?? ?? ?? ?? ?? ?? ??
DO_APP_FUNC(0, LPVOID, MoleMole__PlayerModule_OnReciveLuaShell, (LPVOID __this, LPVOID notify));
