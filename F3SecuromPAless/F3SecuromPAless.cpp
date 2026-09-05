#include "F3SecuromPAless.hpp"


namespace F3SPAless
{
    void Log(const char* fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        std::vprintf(fmt, ap);
        va_end(ap);
        std::fflush(stdout);
    }


    std::uint32_t Rol32(std::uint32_t x, std::int32_t n)
    {
        return (x << n) | (x >> (32 - n));
    }

    std::uint32_t Ror32(std::uint32_t x, std::int32_t n)
    {
        return (x >> n) | (x << (32 - n));
    }

    std::uint32_t Mix(std::uint32_t h, std::uint8_t b)
    {
        return Rol32(h, 3) ^ std::uint32_t(b) ^ sHashK;
    }

    std::uint32_t Unmix(std::uint32_t h, std::uint8_t b)
    {
        return Ror32(h ^ std::uint32_t(b) ^ sHashK, 3);
    }

    std::uint32_t Hash256(const std::uint8_t* p)
    {
        std::uint32_t h = std::uint32_t(p[0]) ^ sHashIV;
        for (std::int32_t i = 1; i < 256; ++i)
            h = Rol32(h, 3) ^ std::uint32_t(p[i]) ^ sHashK;
        return h;
    }

    bool MakeT2FromIni(const std::uint8_t* ini256, std::uint8_t out[256])
    {
        std::memcpy(out, ini256, 256);

        std::uint32_t h = std::uint32_t(out[0]) ^ sHashIV;
        for (std::int32_t i = 1; i <= 246; ++i)
            h = Mix(h, out[i]);

        struct Fwd { std::uint32_t s; std::uint64_t path; };
        std::vector<Fwd> cur, nxt;
        cur.push_back({ h, 0 });
        for (std::int32_t step = 0; step < 5; ++step)
        {
            nxt.clear();
            std::unordered_map<std::uint32_t, std::uint64_t> seen;
            seen.reserve(cur.size() * 8 + 16);
            for (const auto& n : cur) {
                for (std::int32_t b = 0; b < 256; ++b)
                {
                    const std::uint32_t ns = Mix(n.s, std::uint8_t(b));
                    const std::uint64_t np = (n.path << 8) | std::uint64_t(b);
                    if (seen.emplace(ns, np).second)
                        nxt.push_back({ ns, np });
                }
            }
            cur.swap(nxt);
        }

        std::unordered_map<std::uint32_t, std::uint64_t> fwd;
        fwd.reserve(cur.size() * 2);
        for (const auto& n : cur)
            fwd.emplace(n.s, n.path);

        struct Bwd { std::uint32_t s; std::uint32_t path; };
        std::vector<Bwd> bc, bn;
        bc.push_back({ sHashIPC, 0 });
        for (std::int32_t step = 0; step < 4; ++step)
        {
            bn.clear();
            std::unordered_map<std::uint32_t, std::uint32_t> seen;
            seen.reserve(bc.size() * 8 + 16);
            for (const auto& n : bc)
            {
                for (std::int32_t b = 0; b < 256; ++b)
                {
                    const std::uint32_t ns = Unmix(n.s, std::uint8_t(b));
                    const std::uint32_t np = n.path | (std::uint32_t(b) << (8 * step));
                    if (seen.emplace(ns, np).second)
                        bn.push_back({ ns, np });
                }
            }
            bc.swap(bn);
        }

        for (const auto& n : bc)
        {
            const auto it = fwd.find(n.s);
            if (it == fwd.end())
                continue;
            const std::uint64_t fp = it->second;
            out[247] = std::uint8_t(fp >> 32);
            out[248] = std::uint8_t(fp >> 24);
            out[249] = std::uint8_t(fp >> 16);
            out[250] = std::uint8_t(fp >> 8);
            out[251] = std::uint8_t(fp);
            out[255] = std::uint8_t(n.path);
            out[254] = std::uint8_t(n.path >> 8);
            out[253] = std::uint8_t(n.path >> 16);
            out[252] = std::uint8_t(n.path >> 24);
            if (Hash256(out) == sHashIPC)
                return true;
        }
        return false;
    }


    bool ReadAll(const std::wstring& path, std::vector<std::uint8_t>* out)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;

        out->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        return in.good() || in.eof();
    }

    bool WPM(std::uint32_t addr, const void* data, unsigned long n)
    {
        if (!ChildProc || !addr) return false;
        unsigned long w = 0;
        return ::WriteProcessMemory(ChildProc, reinterpret_cast<void*>(addr), data, n, &w) && w == n;
    }

    bool RPM(std::uint32_t addr, void* dst, unsigned long n)
    {
        if (!ChildProc || !addr) return false;
        unsigned long r = 0;
        return ::ReadProcessMemory(ChildProc, reinterpret_cast<void*>(addr), dst, n, &r) && r == n;
    }

    void PublishBlock(DWORD parentpid, const wchar_t* parentpath)
    {
        std::uint8_t blk[sMapSize];
        ::RtlZeroMemory(blk, sMapSize);

        *reinterpret_cast<std::uint32_t*>(blk + 0x00) = 0x00080309;
        *reinterpret_cast<std::uint32_t*>(blk + 0x04) = std::uint32_t(IPCHwnd);
        *reinterpret_cast<std::uint32_t*>(blk + 0x0C) = 1;
        for (std::int32_t i = 0; i < 20; ++i)
            *reinterpret_cast<std::uint16_t*>(blk + 0x10 + i * 2) = std::uint16_t(0xB100 + i);
        *reinterpret_cast<std::uint32_t*>(blk + 0x44) = sIPCMsg;
        *reinterpret_cast<std::uint32_t*>(blk + 0x60) = 0x008659D0;
        *reinterpret_cast<std::uint32_t*>(blk + 0x64) = 0x711EC211;
        *reinterpret_cast<std::uint32_t*>(blk + 0x68) = 0x00090308;
        *reinterpret_cast<std::uint32_t*>(blk + 0x6C) = 0x0001000B;
        // "Sony DADC Austria AG"
        *reinterpret_cast<std::uint32_t*>(blk + 0xA8) = 0x796E6F53;
        *reinterpret_cast<std::uint32_t*>(blk + 0xAC) = 0x44414420;
        *reinterpret_cast<std::uint32_t*>(blk + 0xB0) = 0x75412043;
        *reinterpret_cast<std::uint32_t*>(blk + 0xB4) = 0x69727473;
        *reinterpret_cast<std::uint32_t*>(blk + 0xB8) = 0x47412061;
        if (parentpath && parentpath[0])
        {
            unsigned long n = wcslen(parentpath);
            if (n > 259) n = 259;
            std::memcpy(blk + 0x2A8, parentpath, (n + 1) * sizeof(wchar_t));
        }

        std::memcpy(blk + 0x4B4, L"Fable3.exe", 11 * sizeof(wchar_t));
        *reinterpret_cast<std::uint32_t*>(blk + 0x6C0) = parentpid;
        std::memcpy(MapView, blk, sMapSize);
        Log("[Map] hwnd=%p msg=0x%X parent=%lu path=%ls\n", IPCHwnd, sIPCMsg, parentpid, parentpath ? parentpath : L"");
    }

    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
    {
        if (msg != sIPCMsg)
            return ::DefWindowProcA(hwnd, msg, wparam, lparam);

        switch (wparam)
        {
        case 2:
        {
            Log("[IPC] wParam=2 PID query -> %lu\n", ChildPID);
            return LRESULT(ChildPID);
        }
        case 4:
        {
            Log("[IPC] wParam=4 open -> token 0x%X\n", sOpenToken);
            return LRESULT(sOpenToken);
        }
        case 6:
        {
            Log("[IPC] wParam=6 close\n");
            return 1;
        }
        case 9:
        {
            Msg9 q{};
            if (!RPM(std::uint32_t(lparam), &q, sizeof(q)))
            {
                Log("[IPC] wParam=9 RPM failed lParam=%p\n", reinterpret_cast<void*>(lparam));
                return 0;
            }
            q.outSize = F3Ini.empty() ? 256u : std::uint32_t(F3Ini.size());
            WPM(std::uint32_t(lparam), &q, sizeof(q));
            Log("[IPC] wParam=9 size query token=%u\n", q.token, q.outSize);
            return 1;
        }
        case 10:
        {
            MsgA a{};
            if (!RPM(std::uint32_t(lparam), &a, sizeof(a)))
            {
                Log("[IPC] wParam=10 RPM failed lParam=%p\n", reinterpret_cast<void*>(lparam));
                return 0;
            }

            a.out = 0;
            WPM(std::uint32_t(lparam), &a, sizeof(a));
            Log("[IPC] wParam=10 lock/span token=%u span=%u\n", a.token, a.span);
            return LRESULT(a.span);
        }
        case 7:
        {
            Msg7 r{};
            if (!RPM(std::uint32_t(lparam), &r, sizeof(r)))
            {
                Log("[IPC] wParam=7 RPM failed lParam=%p\n", reinterpret_cast<void*>(lparam));
                return 0;
            }

            Log("[IPC] wParam=7 token=%u len=%u, dest=0x%X\n", r.token, r.length, r.dest);

            std::uint32_t n = r.length;
            if (!F3Ini.empty() && n > std::uint32_t(F3Ini.size()))
                n = std::uint32_t(F3Ini.size());

            bool ok = true;
            if (r.dest && n)
            {
                if (!F3Ini.empty())
                    ok = WPM(r.dest, F3Ini.data(), n);
                if (ok && n >= 256)
                    ok = WPM(r.dest, T2Data, 256);
                else if (ok && n)
                    ok = WPM(r.dest, T2Data, n);
            }
            r.outBytes = ok ? n : 0;
            WPM(std::uintptr_t(lparam), &r, sizeof(r));
            Log("[IPC] wParam=7 wrote %u bytes dest=0x%X t2hash=0x%08X %s\n", r.outBytes, r.dest, Hash256(T2Data), ok ? "ok" : "WPM FAILED");
            return ok ? 1 : 0;
        }
        default:
        {
            Log("[IPC] wParam=%u unhandled lParam=%p\n", unsigned(wparam), reinterpret_cast<void*>(lparam));
            return 0;
        }
        }
    }

    bool LaunchGame(const std::wstring& exe, const std::wstring& dir, PROCESS_INFORMATION* pi)
    {
        STARTUPINFOW si{};
        si.cb = sizeof(STARTUPINFOW);
        std::wstring cmd = L"\"" + exe + L"\"";
        std::vector<wchar_t> buf(cmd.begin(), cmd.end());
        buf.push_back(0);
        return ::CreateProcessW(exe.c_str(), buf.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, dir.empty() ? nullptr : dir.c_str(), &si, pi) != 0;
    }

}

int main()
{
    ::SetConsoleTitleA("F3SecuromPAless");
    ::SetConsoleTextAttribute(::GetStdHandle(STD_OUTPUT_HANDLE), 11);

    F3SPAless::Log("WARNING DO NOT CLOSE THIS WHILE THE GAME IS RUNNING IF YOU DO SECUROM CHECKS WILL NOT PASS!\n");

    wchar_t self[MAX_PATH]{};
    ::GetModuleFileNameW(nullptr, self, MAX_PATH);

    const std::filesystem::path here = std::filesystem::path(self).parent_path();
    const std::filesystem::path ini = here / L"fableaudioex.ini";
    const std::filesystem::path target = here / L"Fable3.exe";

    if (!std::filesystem::exists(ini))
    {
        F3SPAless::Log("fableaudioex.ini not found!\n");
        std::getchar();
        return 1;
    }

    F3SPAless::ReadAll(ini, &F3SPAless::F3Ini);

    if (!std::filesystem::exists(target))
    {
        F3SPAless::Log("Fable3.exe not found!\n");
        std::getchar();
        return 1;
    }

    std::uint32_t CalculatedT1Hash = F3SPAless::Hash256(F3SPAless::F3Ini.data());
    F3SPAless::Log("T1 Hash: 0x%08X %s\n", CalculatedT1Hash, CalculatedT1Hash ? "OK" : "MISMATCH");

    if (!F3SPAless::MakeT2FromIni(F3SPAless::F3Ini.data(), F3SPAless::T2Data))
    {
        F3SPAless::Log("Could not solve T2 hash!\n");
        std::getchar();
        return 1;
    }

    F3SPAless::Log("T2 Hash: 0x%08X %s\n", F3SPAless::Hash256(F3SPAless::T2Data), F3SPAless::Hash256(F3SPAless::T2Data) == F3SPAless::sHashIPC ? "OK" : "FAIL");


    WNDCLASSA wc{};
    wc.lpfnWndProc = F3SPAless::WndProc;
    wc.hInstance = ::GetModuleHandleA(nullptr);
    wc.lpszClassName = "F3SPAlessWnd";
    if (!::RegisterClassA(&wc))
    {
        F3SPAless::Log("RegisterClass failed %lu\n", ::GetLastError());
        std::getchar();
        return 2;
    }

    F3SPAless::IPCHwnd = ::CreateWindowExA(0, "F3SPAlessWnd", "sms.mod_ok_0001_x", WS_OVERLAPPED, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
    if (!F3SPAless::IPCHwnd)
        F3SPAless::IPCHwnd = ::CreateWindowExA(0, "F3SPAlessWnd", "sms.mod_ok_0001_x", WS_OVERLAPPED, 0, 0, 1, 1, nullptr, nullptr, wc.hInstance, nullptr);

    if (!F3SPAless::IPCHwnd)
    {
        F3SPAless::Log("CreateWindow failed %lu\n", ::GetLastError());
        std::getchar();
        return 2;
    }

    F3SPAless::Log("hWnd: %p\n", F3SPAless::IPCHwnd);

    F3SPAless::hMap = ::CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, DWORD(F3SPAless::sMapSize), F3SPAless::sMapName);
    if (!F3SPAless::hMap)
    {
        F3SPAless::Log("CreateFileMapping failed %lu\n", ::GetLastError());
        std::getchar();
        return 3;
    }

    F3SPAless::MapView = ::MapViewOfFile(F3SPAless::hMap, FILE_MAP_ALL_ACCESS, 0, 0, F3SPAless::sMapSize);
    if (!F3SPAless::MapView)
    {
        F3SPAless::Log("MapViewOfFile failed %lu\n", ::GetLastError());
        std::getchar();
        return 4;
    }

    PROCESS_INFORMATION pi{};
    if (!F3SPAless::LaunchGame(target, here, &pi))
    {
        F3SPAless::Log("CreateProcess failed %lu\n", ::GetLastError());
        std::getchar();
        return 5;
    }

    F3SPAless::ChildPID = pi.dwProcessId;
    F3SPAless::ChildProc = pi.hProcess;
    F3SPAless::Log("Child: pid=%lu\n", F3SPAless::ChildPID);

    F3SPAless::PublishBlock(::GetCurrentProcessId(), self);

    ::ResumeThread(pi.hThread);
    ::CloseHandle(pi.hThread);
    F3SPAless::Log("Child resumed waiting for IPC\n");

    MSG msg{};
    while (::GetMessageA(&msg, nullptr, 0, 0) > 0)
    {
        ::TranslateMessage(&msg);
        ::DispatchMessageA(&msg);
        if (::WaitForSingleObject(F3SPAless::ChildProc, 0) == WAIT_OBJECT_0)
        {
            DWORD code = 0;
            ::GetExitCodeProcess(F3SPAless::ChildProc, &code);
            F3SPAless::Log("Child exited %lu\n", code);
            break;
        }
    }

    return 0;
}