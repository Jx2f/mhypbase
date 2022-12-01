#include "pch.h"
#include "hook.h"
#include "hook-manager.h"
#include "il2cpp-init.h"
#include "il2cpp-appdata.h"
#include "util.h"

const char* WarnLuaScript = "[warn] Server is trying to execute a Lua script remotely, which is potentially dangerous if not from a trusted source.";

namespace hook {
	VOID Install() {
		HookManager::install(app::MiHoYo__SDK__SDKUtil_RSAEncrypt, hook::MiHoYo__SDK__SDKUtil_RSAEncrypt);
		HookManager::install(app::MoleMole__MoleMoleSecurity_GetPublicRSAKey, hook::MoleMole__MoleMoleSecurity_GetPublicRSAKey);
		HookManager::install(app::MoleMole__MoleMoleSecurity_GetPrivateRSAKey, hook::MoleMole__MoleMoleSecurity_GetPrivateRSAKey);
		HookManager::install(app::MoleMole__ConfigUtil_LoadJSONStrConfig, hook::MoleMole__ConfigUtil_LoadJSONStrConfig);
		HookManager::install(app::MoleMole__Miscs_GetConfigChannel, hook::MoleMole__Miscs_GetConfigChannel);
		if (util::GetEnableValue("DropRCEPacket", false)) {
			HookManager::install(app::MoleMole__FightModule_OnWindSeedClientNotify, hook::MoleMole__FightModule_OnWindSeedClientNotify);
			HookManager::install(app::MoleMole__PlayerModule_OnWindSeedClientNotify, hook::MoleMole__PlayerModule_OnWindSeedClientNotify);
			HookManager::install(app::MoleMole__PlayerModule_OnReciveLuaShell, hook::MoleMole__PlayerModule_OnReciveLuaShell);
		}
	}

	LPVOID MiHoYo__SDK__SDKUtil_RSAEncrypt(LPVOID publicKey, LPVOID content) {
		std::cout << "[hook] MiHoYo__SDK__SDKUtil_RSAEncrypt reached." << std::endl;
		const char* key = util::GetPublicRSAKey();
		if (key != nullptr) {
			std::cout << "[hook] MiHoYo__SDK__SDKUtil_RSAEncrypt using the configured value." << std::endl;
			publicKey = il2cpp_string_new(key);
		}
		return CALL_ORIGIN(MiHoYo__SDK__SDKUtil_RSAEncrypt, publicKey, content);
	}

	LPVOID MoleMole__MoleMoleSecurity_GetPublicRSAKey() {
		std::cout << "[hook] MoleMole__MoleMoleSecurity_GetPublicRSAKey reached." << std::endl;
		const char* key = util::GetPublicRSAKey();
		if (key == nullptr) {
			return CALL_ORIGIN(MoleMole__MoleMoleSecurity_GetPublicRSAKey);
		}
		std::cout << "[hook] MoleMole__MoleMoleSecurity_GetPublicRSAKey using the configured value." << std::endl;
		auto encoding = app::System__Text__EncodingHelper_GetDefaultEncoding();
		return app::System__Text__Encoding_GetBytes(encoding, il2cpp_string_new(key));
	}

	LPVOID MoleMole__MoleMoleSecurity_GetPrivateRSAKey() {
		std::cout << "[hook] MoleMole__MoleMoleSecurity_GetPrivateRSAKey reached." << std::endl;
		const char* key = util::GetPrivateRSAKey();
		if (key == nullptr) {
			return CALL_ORIGIN(MoleMole__MoleMoleSecurity_GetPrivateRSAKey);
		}
		std::cout << "[hook] MoleMole__MoleMoleSecurity_GetPrivateRSAKey using the configured value." << std::endl;
		auto encoding = app::System__Text__EncodingHelper_GetDefaultEncoding();
		return app::System__Text__Encoding_GetBytes(encoding, il2cpp_string_new(key));
	}

	LPVOID MoleMole__ConfigUtil_LoadJSONStrConfig(LPVOID jsonText, LPVOID useJsonUtility, LPVOID method)
	{
		std::cout << "[hook] MoleMole__ConfigUtil_LoadJSONStrConfig reached." << std::endl;
		const char* config = util::GetConfigChannel();
		if (config != nullptr) {
			std::cout << "[hook] MoleMole__ConfigUtil_LoadJSONStrConfig using the configured value." << std::endl;
			jsonText = il2cpp_string_new(config);
		}
		return CALL_ORIGIN(MoleMole__ConfigUtil_LoadJSONStrConfig, jsonText, useJsonUtility, method);
	}

	LPVOID MoleMole__Miscs_GetConfigChannel() {
		std::cout << "[hook] MoleMole__Miscs_GetConfigChannel reached." << std::endl;
		return app::MoleMole__Miscs_LoadConfigChannelBlk();
	}

	LPVOID MoleMole__FightModule_OnWindSeedClientNotify(LPVOID __this, LPVOID notify) {
		std::cout << "[hook] MoleMole__FightModule_OnWindSeedClientNotify blocked." << std::endl;
		std::cout << WarnLuaScript << std::endl;
		return nullptr;
	}

	LPVOID MoleMole__PlayerModule_OnWindSeedClientNotify(LPVOID __this, LPVOID notify) {
		std::cout << "[hook] MoleMole__PlayerModule_OnWindSeedClientNotify blocked." << std::endl;
		std::cout << WarnLuaScript << std::endl;
		return nullptr;
	}

	LPVOID MoleMole__PlayerModule_OnReciveLuaShell(LPVOID __this, LPVOID notify) {
		std::cout << "[hook] MoleMole__PlayerModule_OnReciveLuaShell blocked." << std::endl;
		std::cout << WarnLuaScript << std::endl;
		return nullptr;
	}
}
