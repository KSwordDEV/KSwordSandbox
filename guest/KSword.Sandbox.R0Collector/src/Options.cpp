#include "Options.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cwchar>
#include <iostream>

namespace KSword::Sandbox::R0Collector {

// Input: CLI numeric value plus accepted inclusive bounds.
// Processing: Parses a base-10 integer and validates the full string was used.
// Return: true with parsed output, or false with a user-facing parse error.
bool ParseBoundedInt(
    const std::wstring& value,
    const int minValue,
    const int maxValue,
    const std::wstring& optionName,
    int* parsedValue,
    std::wstring* error) {
    if (value.empty()) {
        if (error != nullptr) {
            *error = optionName + L" requires a numeric value.";
        }
        return false;
    }

    errno = 0;
    wchar_t* end = nullptr;
    const long number = std::wcstol(value.c_str(), &end, 10);
    if (errno == ERANGE || end == value.c_str() || *end != L'\0' || number < minValue || number > maxValue) {
        if (error != nullptr) {
            *error = optionName + L" must be a base-10 integer between " +
                std::to_wstring(minValue) + L" and " + std::to_wstring(maxValue) + L".";
        }
        return false;
    }

    *parsedValue = static_cast<int>(number);
    return true;
}

// Input: CLI unsigned value that may be decimal or 0x-prefixed hexadecimal.
// Processing: Parses the full string and validates it fits in the public ULONG
// request fields used by READ_EVENTS or producer masks.
// Return: true with parsed output, or false with a user-facing parse error.
bool ParseUnsignedMask(
    const std::wstring& value,
    const std::wstring& optionName,
    const unsigned long minValue,
    const unsigned long maxValue,
    unsigned long* parsedValue,
    std::wstring* error) {
    if (value.empty()) {
        if (error != nullptr) {
            *error = optionName + L" requires a numeric value.";
        }
        return false;
    }

    errno = 0;
    wchar_t* end = nullptr;
    const bool hexadecimal =
        value.size() > 2 &&
        value[0] == L'0' &&
        (value[1] == L'x' || value[1] == L'X');
    const unsigned long long number = std::wcstoull(value.c_str(), &end, hexadecimal ? 16 : 10);
    if (errno == ERANGE ||
        end == value.c_str() ||
        *end != L'\0' ||
        number > 0xFFFFFFFFULL ||
        number < minValue ||
        number > maxValue) {
        if (error != nullptr) {
            *error = optionName + L" must be an unsigned decimal or 0x-prefixed hexadecimal value between " +
                std::to_wstring(minValue) + L" and " + std::to_wstring(maxValue) + L".";
        }
        return false;
    }

    *parsedValue = static_cast<unsigned long>(number);
    return true;
}

// Input: Process argc/argv from wmain.
// Processing: Handles long and short collector options and validates bounded
// numeric values before any driver handle or output sink is opened.
// Return: true with Options populated, or false with an error string.
bool ParseArguments(int argc, wchar_t* argv[], Options* options, std::wstring* error) {
    for (int index = 1; index < argc; ++index) {
        const std::wstring arg = argv[index];
        const auto readValue = [&](const std::wstring& optionName, std::wstring* value) -> bool {
            if (index + 1 >= argc) {
                if (error != nullptr) {
                    *error = optionName + L" requires a value.";
                }
                return false;
            }
            *value = argv[++index];
            return true;
        };

        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            options->showHelp = true;
            return true;
        }

        if (arg == L"--mock" || arg == L"--synthetic" || arg == L"--self-test") {
            options->mockMode = true;
            continue;
        }

        if (arg == L"--heartbeat") {
            options->heartbeat = true;
            continue;
        }

        if (arg == L"--abi-self-check" || arg == L"--contract-self-check") {
            options->abiSelfCheck = true;
            continue;
        }

        if (arg == L"--health") {
            options->healthOnly = true;
            continue;
        }

        std::wstring value;
        if (arg == L"--device" || arg == L"-d") {
            if (!readValue(arg, &value)) {
                return false;
            }
            options->devicePath = value;
        } else if (arg == L"--output" || arg == L"--out" || arg == L"-o") {
            if (!readValue(arg, &value)) {
                return false;
            }
            options->outputPath = value;
        } else if (arg == L"--duration" || arg == L"-t") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 0, 86400, arg, &options->durationSeconds, error)) {
                return false;
            }
        } else if (arg == L"--poll-interval" || arg == L"--poll-interval-ms" || arg == L"--poll-ms" || arg == L"-p") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 1, 600000, arg, &options->pollIntervalMs, error)) {
                return false;
            }
        } else if (arg == L"--max-read-batches") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 0, 1000000, arg, &options->maxReadBatches, error)) {
                return false;
            }
        } else if (arg == L"--max-events") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseUnsignedMask(value, arg, 1, 1024, &options->readEventsMaxEvents, error)) {
                return false;
            }
        } else if (arg == L"--enable-mask") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseUnsignedMask(value, arg, 0, 0xFFFFFFFFUL, &options->enableMask, error)) {
                return false;
            }
            options->enableMaskSpecified = true;
        } else {
            if (error != nullptr) {
                *error = L"Unknown argument: " + arg;
            }
            return false;
        }
    }

    return true;
}

// Input: Program name as printed by the shell.
// Processing: Writes supported arguments and defaults to stderr.
// Return: No return value.
void PrintUsage(const wchar_t* programName) {
    std::wcerr
        << L"Usage: " << programName << L" [options]\n"
        << L"\n"
        << L"Options:\n"
        << L"  -d, --device <path>          Win32 device path (default: \\\\.\\KSwordSandboxDriver)\n"
        << L"  -o, --output, --out <path>   JSON Lines output path, or '-' for stdout (default: -)\n"
        << L"  -t, --duration <seconds>     Poll duration; 0 opens once and exits (default: 0)\n"
        << L"  -p, --poll-ms <ms>           Poll interval in milliseconds (default: 500)\n"
        << L"      --poll-interval-ms <ms>  Alias for --poll-ms\n"
        << L"      --max-events <count>     READ_EVENTS MaxEvents request cap 1..1024 (default: 64)\n"
        << L"      --max-read-batches <n>   Stop after n READ_EVENTS batches; 0 means unlimited\n"
        << L"      --enable-mask <mask>     Set producer enable mask through SET_PRODUCER_ENABLE_MASK\n"
        << L"      --abi-self-check         Emit ABI/event-quality contract row and exit without opening the driver\n"
        << L"      --contract-self-check    Alias for --abi-self-check\n"
        << L"      --health                 Open the device, emit GET_HEALTH, and exit without draining\n"
        << L"      --heartbeat              Emit r0collector.heartbeat lifecycle rows\n"
        << L"      --mock                   Emit synthetic rows without opening a device\n"
        << L"      --synthetic              Alias for --mock\n"
        << L"      --self-test              Alias for --mock\n"
        << L"  -h, --help                   Show this help text\n";
}

} // namespace KSword::Sandbox::R0Collector
