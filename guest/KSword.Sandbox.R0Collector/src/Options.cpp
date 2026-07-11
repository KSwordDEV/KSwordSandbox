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
            *error = optionName + L" requires a numeric value. / " +
                optionName + L" \u9700\u8981\u4e00\u4e2a\u6570\u503c\u3002";
        }
        return false;
    }

    errno = 0;
    wchar_t* end = nullptr;
    const long number = std::wcstol(value.c_str(), &end, 10);
    if (errno == ERANGE || end == value.c_str() || *end != L'\0' || number < minValue || number > maxValue) {
        if (error != nullptr) {
            *error = optionName + L" must be a base-10 integer between " +
                std::to_wstring(minValue) + L" and " + std::to_wstring(maxValue) + L". / " +
                optionName + L" \u5fc5\u987b\u662f " + std::to_wstring(minValue) +
                L" \u5230 " + std::to_wstring(maxValue) +
                L" \u4e4b\u95f4\u7684\u5341\u8fdb\u5236\u6574\u6570\u3002";
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
            *error = optionName + L" requires a numeric value. / " +
                optionName + L" \u9700\u8981\u4e00\u4e2a\u6570\u503c\u3002";
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
                std::to_wstring(minValue) + L" and " + std::to_wstring(maxValue) + L". / " +
                optionName + L" \u5fc5\u987b\u662f " + std::to_wstring(minValue) +
                L" \u5230 " + std::to_wstring(maxValue) +
                L" \u4e4b\u95f4\u7684\u65e0\u7b26\u53f7\u5341\u8fdb\u5236\u6570\u6216 0x \u524d\u7f00\u5341\u516d\u8fdb\u5236\u6570\u3002";
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
                    *error = optionName + L" requires a value. / " +
                        optionName + L" \u9700\u8981\u4e00\u4e2a\u503c\u3002";
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

        if (arg == L"--inject-jsonl-noise") {
            options->injectJsonlNoise = true;
            continue;
        }

        if (arg == L"--heartbeat") {
            options->heartbeat = true;
            continue;
        }

        if (arg == L"--suppress-self-noise") {
            options->suppressSelfNoise = true;
            continue;
        }

        if (arg == L"--emit-self-noise" || arg == L"--no-suppress-self-noise") {
            options->suppressSelfNoise = false;
            continue;
        }

        if (arg == L"--abi-self-check" || arg == L"--contract-self-check") {
            options->abiSelfCheck = true;
            continue;
        }

        if (arg == L"--diagnose" || arg == L"--readiness" || arg == L"--readiness-check") {
            options->diagnose = true;
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
        } else if (arg == L"--service-name") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (value.empty()) {
                if (error != nullptr) {
                    *error = arg + L" requires a non-empty service name. / " +
                        arg + L" \u9700\u8981\u975e\u7a7a\u7684\u9a71\u52a8\u670d\u52a1\u540d\u3002";
                }
                return false;
            }
            options->serviceName = value;
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
        } else if (arg == L"--diagnose-read-timeout-ms" || arg == L"--read-timeout-ms") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 1, 600000, arg, &options->diagnoseReadTimeoutMs, error)) {
                return false;
            }
        } else if (arg == L"--max-read-batches") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 0, 1000000, arg, &options->maxReadBatches, error)) {
                return false;
            }
        } else if (arg == L"--stress-count") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 0, 100000, arg, &options->stressCount, error)) {
                return false;
            }
            if (options->stressCount > 0) {
                options->mockMode = true;
            }
        } else if (arg == L"--max-events") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseUnsignedMask(value, arg, 1, 1024, &options->readEventsMaxEvents, error)) {
                return false;
            }
        } else if (arg == L"--driver-event-sample-stride" || arg == L"--event-sample-stride") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseUnsignedMask(value, arg, 1, 1000000, &options->driverEventSampleStride, error)) {
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
                *error = L"Unknown argument: " + arg + L" / \u672a\u77e5\u53c2\u6570: " + arg;
            }
            return false;
        }
    }

    if (options->injectJsonlNoise && !options->mockMode) {
        if (error != nullptr) {
            *error = L"--inject-jsonl-noise is only supported with --mock/--synthetic or --stress-count. / "
                L"--inject-jsonl-noise 仅支持与 --mock/--synthetic 或 --stress-count 一起使用。";
        }
        return false;
    }

    if (options->injectJsonlNoise &&
        (options->abiSelfCheck || options->diagnose || options->healthOnly)) {
        if (error != nullptr) {
            *error = L"--inject-jsonl-noise cannot be combined with --abi-self-check, --diagnose/readiness, or --health. / "
                L"--inject-jsonl-noise 不能与 --abi-self-check、--diagnose/readiness 或 --health 同时使用；"
                L"噪声注入只用于 mock/stress 读取器容错测试。";
        }
        return false;
    }

    return true;
}

// Input: Program name as printed by the shell.
// Processing: Writes supported arguments and defaults to stderr.
// Return: No return value.
void PrintUsage(const wchar_t* programName) {
    std::wcerr
        << L"Usage: " << programName << L" [options]\n"
        << L"\u7528\u6cd5: " << programName << L" [\u9009\u9879]\n"
        << L"\n"
        << L"Options:\n"
        << L"\u9009\u9879:\n"
        << L"  -d, --device <path>          Win32 device path (default: \\\\.\\KSwordSandboxDriver) / Win32 \u8bbe\u5907\u8def\u5f84\n"
        << L"      --service-name <name>    Driver service name for --diagnose (default: KSwordSandboxDriver) / --diagnose \u4f7f\u7528\u7684\u9a71\u52a8\u670d\u52a1\u540d\n"
        << L"  -o, --output, --out <path>   JSON Lines output path, or '-' for stdout (default: -) / JSONL \u8f93\u51fa\u8def\u5f84\uff0c'-' \u8868\u793a\u6807\u51c6\u8f93\u51fa\n"
        << L"  -t, --duration <seconds>     Poll duration; 0 opens once and exits (default: 0) / \u8f6e\u8be2\u6301\u7eed\u65f6\u95f4\uff1b0 \u8868\u793a\u4e00\u6b21\u6027\u6253\u5f00\u540e\u9000\u51fa\n"
        << L"  -p, --poll-ms <ms>           Poll interval in milliseconds (default: 500) / \u8f6e\u8be2\u95f4\u9694\uff08\u6beb\u79d2\uff09\n"
        << L"      --poll-interval-ms <ms>  Alias for --poll-ms / --poll-ms \u522b\u540d\n"
        << L"      --diagnose               Emit service/device/ABI/READ_EVENTS readiness diagnostics / \u53d1\u51fa\u670d\u52a1/\u8bbe\u5907/ABI/READ_EVENTS \u5c31\u7eea\u8bca\u65ad\n"
        << L"      --readiness              Alias for --diagnose / --diagnose \u522b\u540d\n"
        << L"      --readiness-check        Alias for --diagnose / --diagnose \u522b\u540d\n"
        << L"      --read-timeout-ms <ms>   READ_EVENTS timeout used by --diagnose (default: 2000) / --diagnose \u7684 READ_EVENTS \u8d85\u65f6\n"
        << L"      --max-events <count>     READ_EVENTS MaxEvents request cap 1..1024 (default: 64) / READ_EVENTS \u5355\u6279\u4e8b\u4ef6\u4e0a\u9650\n"
        << L"      --max-read-batches <n>   Stop after n READ_EVENTS batches; 0 means unlimited / \u6700\u591a\u8bfb\u53d6 n \u6279\uff0c0 \u8868\u793a\u4e0d\u9650\n"
        << L"      --driver-event-sample-stride <n>  Emit first and every nth eligible driver row; 1 emits all / \u9a71\u52a8\u884c\u91c7\u6837\u6b65\u957f\uff0c1 \u8868\u793a\u5168\u91cf\n"
        << L"      --enable-mask <mask>     Set producer enable mask through SET_PRODUCER_ENABLE_MASK / \u8bbe\u7f6e\u9a71\u52a8 producer enable mask\n"
        << L"      --abi-self-check         Emit ABI/event-quality contract row and exit without opening the driver / \u4e0d\u6253\u5f00\u9a71\u52a8\uff0c\u53d1\u51fa ABI/\u4e8b\u4ef6\u8d28\u91cf\u81ea\u68c0\u884c\n"
        << L"      --contract-self-check    Alias for --abi-self-check / --abi-self-check \u522b\u540d\n"
        << L"      --health                 Open the device, emit GET_HEALTH, and exit without draining / \u4ec5\u6253\u5f00\u8bbe\u5907\u5e76\u53d1\u51fa GET_HEALTH\n"
        << L"      --heartbeat              Emit r0collector.heartbeat lifecycle rows / \u53d1\u51fa\u8fdb\u5ea6\u5fc3\u8df3\u884c\n"
        << L"      --suppress-self-noise    Suppress known KSword/collector-owned driver rows (default) / \u6291\u5236\u5df2\u77e5 KSword/Collector \u81ea\u8eab\u566a\u58f0\n"
        << L"      --emit-self-noise        Emit known self-noise rows but mark them in data.selfNoise / \u4fdd\u7559\u81ea\u8eab\u566a\u58f0\u5e76\u5728 data.selfNoise \u6807\u8bb0\n"
        << L"      --mock                   Emit synthetic rows without opening a device / \u53d1\u51fa\u5408\u6210\u884c\uff0c\u4e0d\u6253\u5f00\u8bbe\u5907\n"
        << L"      --synthetic              Alias for --mock / --mock \u522b\u540d\n"
        << L"      --self-test              Alias for --mock / --mock \u522b\u540d\n"
        << L"      --stress-count <n>       Emit n synthetic contiguous driver.file stress rows; implies --mock / \u53d1\u51fa n \u6761\u5408\u6210\u538b\u6d4b\u884c\uff0c\u9690\u542b --mock\n"
        << L"      --inject-jsonl-noise     In mock/stress mode also emit blank and malformed JSONL rows / mock/stress \u6a21\u5f0f\u4e2d\u989d\u5916\u53d1\u51fa\u7a7a\u884c\u548c\u7578\u5f62 JSONL \u884c\n"
        << L"  -h, --help                   Show this help text / \u663e\u793a\u5e2e\u52a9\u6587\u672c\n";
}

} // namespace KSword::Sandbox::R0Collector
