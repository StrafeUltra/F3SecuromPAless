#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <filesystem>


namespace F3SPAless
{
	constexpr std::uint64_t sMapSize = 0x6C4;
	constexpr char sMapName[] = "-=[SMS_Fable3.exe_SMS]=-";
	constexpr std::uint32_t sIPCMsg = WM_APP + 0x51;
	constexpr std::uint32_t sOpenToken = 0x2000;

	constexpr std::uint32_t sHashIV = 0x7A30DCF3u;
	constexpr std::uint32_t sHashK = 0x9A0F1C24u;
	constexpr std::uint32_t sHashFile = 0xDE551B5Cu;
	constexpr std::uint32_t sHashIPC = 0x68C4203Au;

	HANDLE hMap = nullptr;
	void* MapView = nullptr;
	HWND IPCHwnd = nullptr;
	DWORD ChildPID = 0;
	HANDLE ChildProc = nullptr;
	std::vector<std::uint8_t> F3Ini;
	std::uint8_t T2Data[256]{};

	static bool ConsoleEnabled = false;

	void Log(const char* fmt, ...);


	std::uint32_t Rol32(std::uint32_t x, std::int32_t n);

	std::uint32_t Ror32(std::uint32_t x, std::int32_t n);

	std::uint32_t Mix(std::uint32_t h, std::uint8_t b);

	std::uint32_t Unmix(std::uint32_t h, std::uint8_t b);

	std::uint32_t Hash256(const std::uint8_t* p);

	bool MakeT2FromIni(const std::uint8_t* ini256, std::uint8_t out[256]);

#pragma pack(push, 4)
	struct Msg9 { uint32_t token, zero, outSize; };
	struct MsgA { uint32_t token, a, span, b, out; };
	struct Msg7 { uint32_t token, length, dest, outBytes; };
#pragma pack(pop)


	bool ReadAll(const std::wstring& path, std::vector<std::uint8_t>* out);

	bool WPM(std::uint32_t addr, const void* data, unsigned long n);

	bool RPM(std::uint32_t addr, void* dst, unsigned long n);

	void PublishBlock(DWORD parentpid, const wchar_t* parentpath);

	LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

	bool LaunchGame(const std::wstring& exe, const std::wstring& dir, PROCESS_INFORMATION* pi);
}