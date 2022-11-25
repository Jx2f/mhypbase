#include "pch.h"
#include "util.h"

namespace util
{
    VOID LoadConfig()
    {
        ini.SetUnicode();
        ini.LoadFile("mhypbase.ini");
        if (ini.GetBoolValue("Basic", "EnableConsole", false)) {
            InitConsole();
        }
        ClientVersion = ini.GetValue("Offset", "ClientVersion", nullptr);
        if (ClientVersion == nullptr) {
            char pathOut[MAX_PATH] = {};
            GetModuleFileName(NULL, pathOut, MAX_PATH);
            auto path = std::filesystem::path(pathOut).parent_path() / "pkg_version";
            std::ifstream infile(path);
            std::string line;
            std::regex str_expr = std::regex("UserAssembly.dll.*\"([0-9a-f]{32})\"");
            auto match = std::smatch();
            while (std::getline(infile, line)) {
                std::regex_search(line, match, str_expr);
                if (match.size() == 2) {
                    auto str_match = match[1].str();
                    ClientVersion = ini.GetValue("MD5ClientVersion", str_match.c_str(), nullptr);
                    if (ClientVersion == nullptr) {
                        ClientVersion = "Offset";
                    }
                    std::cout << "[init] Version detected " << ClientVersion << std::endl;
                    break;
                }
            }
        }
        PublicRSAKey = ini.GetValue("Value", "PublicRSAKey", nullptr);
        PrivateRSAKey = ini.GetValue("Value", "PrivateRSAKey", nullptr);
    }

    const char* GetPublicRSAKey() 
    {
        return PublicRSAKey;
    }

    const char* GetPrivateRSAKey()
    {
        return PrivateRSAKey;
    }

    bool GetBoolValue(const char* a_pSection, const char* a_pKey, bool a_nDefault)
    {
        return ini.GetBoolValue(a_pSection, a_pKey, a_nDefault);
    }

    long GetOffsetValue(const char* a_pKey, long a_nDefault)
    {
        return ini.GetLongValue(ClientVersion, a_pKey, a_nDefault);
    }

    VOID SaveConfig()
    {
        ini.SaveFile("mhypbase.ini");
    }

    VOID InitConsole()
    {
        AllocConsole();
        freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
        freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);
        auto consoleWindow = GetConsoleWindow();
        SetForegroundWindow(consoleWindow);
        ShowWindow(consoleWindow, SW_RESTORE);
        ShowWindow(consoleWindow, SW_SHOW);
    }

    VOID DisableLogReport()
    {
        char pathOut[MAX_PATH] = {};
        GetModuleFileName(NULL, pathOut, MAX_PATH);
        auto pathOS = std::filesystem::path(pathOut).parent_path() / "GenshinImpact_Data" / "Plugins";
        auto pathCN = std::filesystem::path(pathOut).parent_path() / "YuanShen_Data" / "Plugins";
        std::error_code ec; // always ignore error code
        std::filesystem::rename(pathOS / "Astrolabe.dll", pathOS / "Astrolabe.dll.bak", ec);
        std::filesystem::rename(pathOS / "MiHoYoMTRSDK.dll", pathOS / "MiHoYoMTRSDK.dll.bak", ec);
        std::filesystem::rename(pathCN / "Astrolabe.dll", pathCN / "Astrolabe.dll.bak", ec);
        std::filesystem::rename(pathCN / "MiHoYoMTRSDK.dll", pathCN / "MiHoYoMTRSDK.dll.bak", ec);
        // how to restore them??? hope nobody use it in prod.... XD
    }

    // https://github.com/yubie-re/vmp-virtualprotect-bypass/blob/main/src/vp-patch.hpp
    VOID DisableVMProtect()
    {
        DWORD oldProtect = 0;
        auto ntdll = GetModuleHandleA("ntdll.dll");
        BYTE callcode = ((BYTE *)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1; // Since the syscall code is partially corrupted, we have to figure out what it is (always 1 less than NtQuerySection) since it changes based on windows version.
        BYTE restore[] = {0x4C, 0x8B, 0xD1, 0xB8, callcode};                      // x64 ntdll
        auto nt_vp = (BYTE *)GetProcAddress(ntdll, "NtProtectVirtualMemory");
        VirtualProtect(nt_vp, sizeof(restore), PAGE_EXECUTE_READWRITE, &oldProtect); // They don't even check if we are vping vp 👎😹👎
        memcpy(nt_vp, restore, sizeof(restore));
        VirtualProtect(nt_vp, sizeof(restore), oldProtect, &oldProtect);
    }

    VOID Dump(VOID *ptr, int buflen)
    {
        unsigned char *buf = (unsigned char *)ptr;
        int i;
        for (i = 0; i < buflen; i++)
        {
            printf("%02x ", buf[i]);
        }
        printf("\n");
    }

    VOID HexDump(VOID *ptr, int buflen)
    {
        unsigned char *buf = (unsigned char *)ptr;
        int i, j;
        for (i = 0; i < buflen; i += 16)
        {
            printf("%06x: ", i);
            for (j = 0; j < 16; j++)
                if (i + j < buflen)
                    printf("%02x ", buf[i + j]);
                else
                    printf("   ");
            printf(" ");
            for (j = 0; j < 16; j++)
                if (i + j < buflen)
                    printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            printf("\n");
        }
    }
}
