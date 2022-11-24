#include "pch.h"
#include "util.h"

namespace util
{
    VOID LoadConfig()
    {
        HWND hwnd = GetActiveWindow();
        char ini_path[MAX_PATH] = {};
        GetIniPath(ini_path);

        ini.SetUnicode();

        SI_Error err =ini.LoadFile(ini_path);

        if (err!=0)
        {
            MessageBox(hwnd, "Load ini failed", "Error", MB_ICONERROR);
        }
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
        RSAPublicKey = ini.GetValue("Value", "RSAPublicKey", nullptr);
        RSAPrivateKey = ini.GetValue("Value", "RSAPrivateKey", nullptr);
    }

    const char* GetRSAPublicKey() 
    {
        return RSAPublicKey;
    }

    const char* GetRSAPrivateKey()
    {
        return RSAPrivateKey;
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
        char ini_path[MAX_PATH] = {};
        GetIniPath(ini_path);
        ini.SaveFile(ini_path);
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
        auto path = std::filesystem::path(pathOut).parent_path() / "GenshinImpact_Data\\Plugins";
        std::error_code ec;
        std::filesystem::rename(path / "Astrolabe.dll", path / "Astrolabe.dll.bak", ec);
        std::filesystem::rename(path / "MiHoYoMTRSDK.dll", path / "MiHoYoMTRSDK.dll.bak", ec);
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


    //获取配置路径相关
    HMODULE getSelfModuleHandle()
    {
        MEMORY_BASIC_INFORMATION mbi;
        return ((::VirtualQuery(getSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
    }

    std::string getSelfPath() {
        char curDir[100] = { 0 };
        GetModuleFileName(getSelfModuleHandle(), curDir, 100);
        std::string CurrentDirectory = std::string(curDir);
        int pos = CurrentDirectory.rfind("\\", CurrentDirectory.length());
        CurrentDirectory = CurrentDirectory.substr(0, pos);
        return CurrentDirectory;
    }

    int GetIniPath(char* c) {

        std::string const& cc = getSelfPath() + std::string("\\mhypbase.ini");

        strcpy_s(c, MAX_PATH, cc.c_str());

        return 0;
    }
}
