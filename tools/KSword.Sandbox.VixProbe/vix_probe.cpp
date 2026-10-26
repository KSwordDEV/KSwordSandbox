// VMware Workstation GuestOps transport prototype. Password is read from this
// process's environment, never argv or a file. Caller enforces path/budget policy.
#include <windows.h>
#include <iostream>
#include <string>
#include "vix.h"

namespace {
std::string Utf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
        static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string text(n, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                            &text[0], n, nullptr, nullptr) != n) return {};
    return text;
}

std::wstring Env(const wchar_t* name) {
    const DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
    if (n < 2) return {};
    std::wstring value(n, L'\0');
    const DWORD copied = GetEnvironmentVariableW(name, &value[0], n);
    if (copied == 0 || copied >= n) return {};
    value.resize(copied);
    return value;
}

DWORD Timeout() {
    const auto raw = Env(L"KSWORDBOX_VIX_TIMEOUT_SECONDS");
    if (raw.empty()) return 180000;
    wchar_t* end = nullptr;
    const unsigned long seconds = wcstoul(raw.c_str(), &end, 10);
    return *end == L'\0' && seconds >= 1 && seconds <= 3600
        ? static_cast<DWORD>(seconds * 1000) : 180000;
}

bool Complete(VixHandle job, DWORD timeout) {
    if (job == VIX_INVALID_HANDLE) {
        std::cerr << "VIX invalid job handle\n";
        return false;
    }
    const ULONGLONG deadline = GetTickCount64() + timeout;
    do {
        Bool ready = FALSE;
        const VixError error = VixJob_CheckCompletion(job, &ready);
        if (VIX_FAILED(error)) {
            std::cerr << "VIX completion error=" << static_cast<unsigned long long>(error) << '\n';
            return false;
        }
        if (ready) return true;
        Sleep(100);
    } while (GetTickCount64() < deadline);
    std::cerr << "VIX timeout; backend cancellation is not guaranteed\n";
    return false;
}

bool Wait(VixHandle job, DWORD timeout) {
    const bool ready = Complete(job, timeout);
    const VixError error = ready ? VixJob_Wait(job, VIX_PROPERTY_NONE) : VIX_OK;
    if (job != VIX_INVALID_HANDLE) Vix_ReleaseHandle(job);
    if (!ready) return false;
    if (VIX_FAILED(error)) {
        std::cerr << "VIX operation error=" << static_cast<unsigned long long>(error) << '\n';
        return false;
    }
    return true;
}

bool WaitHandle(VixHandle job, DWORD timeout, VixHandle* handle) {
    const bool ready = Complete(job, timeout);
    const VixError error = ready
        ? VixJob_Wait(job, VIX_PROPERTY_JOB_RESULT_HANDLE, handle, VIX_PROPERTY_NONE) : VIX_OK;
    if (job != VIX_INVALID_HANDLE) Vix_ReleaseHandle(job);
    if (!ready) return false;
    if (VIX_FAILED(error)) {
        std::cerr << "VIX handle error=" << static_cast<unsigned long long>(error) << '\n';
        return false;
    }
    return true;
}

bool GuestPassword(std::string& password) {
    auto wide = Env(L"KSWORDBOX_GUEST_PASSWORD");
    if (wide.empty()) return false;
    password = Utf8(wide);
    SecureZeroMemory(&wide[0], wide.size() * sizeof(wchar_t));
    SetEnvironmentVariableW(L"KSWORDBOX_GUEST_PASSWORD", nullptr);
    return !password.empty();
}

void Erase(std::string& value) {
    if (!value.empty()) SecureZeroMemory(&value[0], value.size());
    value.clear();
}

void Usage() {
    std::cerr << "Usage: vix_probe.exe status <vmx>\n"
              << "       vix_probe.exe file-exists <vmx> <guest-path>\n"
              << "       vix_probe.exe copy-to <vmx> <host-file> <guest-file>\n"
              << "       vix_probe.exe copy-from <vmx> <guest-file> <host-file>\n"
              << "       vix_probe.exe run <vmx> <guest-program> [argument-string]\n";
}
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) { Usage(); return 2; }
    const std::wstring op(argv[1]);
    const bool status = op == L"status" && argc == 3;
    const bool exists = op == L"file-exists" && argc == 4;
    const bool copyTo = op == L"copy-to" && argc == 5;
    const bool copyFrom = op == L"copy-from" && argc == 5;
    const bool run = op == L"run" && (argc == 4 || argc == 5);
    if (!(status || exists || copyTo || copyFrom || run)) { Usage(); return 2; }
    const std::wstring vmxWide(argv[2]);
    if (vmxWide.size() < 5 || vmxWide.substr(vmxWide.size()-4) != L".vmx" ||
        GetFileAttributesW(vmxWide.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "VMX path missing or invalid\n";
        return 2;
    }
    const auto vmx = Utf8(vmxWide);
    const DWORD timeout = Timeout();
    VixHandle host = VIX_INVALID_HANDLE;
    VixHandle vm = VIX_INVALID_HANDLE;
    int rc = 1;
    if (!WaitHandle(VixHost_Connect(VIX_API_VERSION, VIX_SERVICEPROVIDER_VMWARE_WORKSTATION,
        nullptr, 0, nullptr, nullptr, 0, VIX_INVALID_HANDLE, nullptr, nullptr),
        timeout, &host)) goto done;
    if (!WaitHandle(VixHost_OpenVM(host, vmx.c_str(), VIX_VMOPEN_NORMAL,
        VIX_INVALID_HANDLE, nullptr, nullptr), timeout, &vm)) goto done;
    if (status) {
        int power = 0;
        const VixError error = Vix_GetProperties(vm, VIX_PROPERTY_VM_POWER_STATE,
                                                  &power, VIX_PROPERTY_NONE);
        if (VIX_FAILED(error)) {
            std::cerr << "VIX power query error=" << static_cast<unsigned long long>(error) << '\n';
            goto done;
        }
        std::cout << "power-state=" << power << '\n';
        rc = 0;
        goto done;
    }
    {
        std::string password;
        if (!GuestPassword(password)) {
            std::cerr << "Dedicated guest password environment variable missing\n";
            goto done;
        }
        auto userWide = Env(L"KSWORDBOX_GUEST_USER");
        if (userWide.empty()) userWide = L"SandboxUser";
        const auto user = Utf8(userWide);
        const bool ok = Wait(VixVM_LoginInGuest(vm, user.c_str(), password.c_str(),
                                                0, nullptr, nullptr), timeout);
        Erase(password);
        if (!ok) goto done;
    }
    if (exists) {
        const auto guest = Utf8(argv[3]);
        VixHandle job = VixVM_FileExistsInGuest(vm, guest.c_str(), nullptr, nullptr);
        const bool ready = Complete(job, timeout);
        Bool found = FALSE;
        const VixError error = ready
            ? VixJob_Wait(job, VIX_PROPERTY_JOB_RESULT_GUEST_OBJECT_EXISTS,
                          &found, VIX_PROPERTY_NONE) : VIX_OK;
        if (job != VIX_INVALID_HANDLE) Vix_ReleaseHandle(job);
        if (!ready || VIX_FAILED(error)) {
            if (ready) std::cerr << "VIX file query error=" << static_cast<unsigned long long>(error) << '\n';
            goto done;
        }
        std::cout << "exists=" << (found ? "true" : "false") << '\n';
        rc = found ? 0 : 3;
    } else if (copyTo) {
        const DWORD flags = GetFileAttributesW(argv[3]);
        if (flags == INVALID_FILE_ATTRIBUTES || (flags & FILE_ATTRIBUTE_DIRECTORY)) {
            std::cerr << "Host source file missing\n";
            goto done;
        }
        const auto hostPath = Utf8(argv[3]);
        const auto guestPath = Utf8(argv[4]);
        if (!Wait(VixVM_CopyFileFromHostToGuest(vm, hostPath.c_str(), guestPath.c_str(),
            0, VIX_INVALID_HANDLE, nullptr, nullptr), timeout)) goto done;
        std::cout << "copy-to=ok\n";
        rc = 0;
    } else if (copyFrom) {
        if (GetFileAttributesW(argv[4]) != INVALID_FILE_ATTRIBUTES) {
            std::cerr << "Host destination already exists\n";
            goto done;
        }
        const auto guestPath = Utf8(argv[3]);
        const auto hostPath = Utf8(argv[4]);
        if (!Wait(VixVM_CopyFileFromGuestToHost(vm, guestPath.c_str(), hostPath.c_str(),
            0, VIX_INVALID_HANDLE, nullptr, nullptr), timeout)) goto done;
        std::cout << "copy-from=ok\n";
        rc = 0;
    } else if (run) {
        const auto guestProgram = Utf8(argv[3]);
        const auto arguments = argc == 5 ? Utf8(argv[4]) : std::string();
        VixHandle job = VixVM_RunProgramInGuest(vm, guestProgram.c_str(),
            arguments.c_str(), 0, VIX_INVALID_HANDLE, nullptr, nullptr);
        const bool ready = Complete(job, timeout);
        int exitCode = -1;
        const VixError error = ready
            ? VixJob_Wait(job, VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_EXIT_CODE,
                          &exitCode, VIX_PROPERTY_NONE) : VIX_OK;
        if (job != VIX_INVALID_HANDLE) Vix_ReleaseHandle(job);
        if (!ready || VIX_FAILED(error)) {
            if (ready) std::cerr << "VIX run error=" << static_cast<unsigned long long>(error) << '\n';
            goto done;
        }
        std::cout << "guest-exit=" << exitCode << '\n';
        rc = exitCode == 0 ? 0 : 4;
    }
    if (!Wait(VixVM_LogoutFromGuest(vm, nullptr, nullptr), timeout) && rc == 0) rc = 1;
done:
    if (vm != VIX_INVALID_HANDLE) Vix_ReleaseHandle(vm);
    if (host != VIX_INVALID_HANDLE) VixHost_Disconnect(host);
    return rc;
}
