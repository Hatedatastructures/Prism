/**
 * @file Compare.cpp
 * @brief Mailbox 基线 CLI。
 */

#include "Compare.hpp"

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>

namespace Prism::Runtime::Perf
{
    auto Run(const Options &Settings) -> int;
}

namespace
{

    using Prism::Runtime::Perf::Options;

    auto Require(const bool Condition, const std::string_view Message) -> void
    {
        if (!Condition)
        {
            throw std::invalid_argument(std::string{Message});
        }
    }

    auto ParseUnsigned(const std::string_view Text) -> std::uint64_t
    {
        std::uint64_t Value = 0;
        const auto Result = std::from_chars(Text.data(), Text.data() + Text.size(), Value);
        Require(Result.ec == std::errc{} && Result.ptr == Text.data() + Text.size(),
                "invalid unsigned integer");
        return Value;
    }

    auto ParseOptions(const int Argc, char **Argv, Options &Settings) -> bool
    {
        bool Help = false;
        for (int Index = 1; Index < Argc; ++Index)
        {
            const std::string_view Argument{Argv[Index]};
            if (Argument == "--help" || Argument == "-h")
            {
                Help = true;
                continue;
            }
            if (Argument == "--validate-only")
            {
                Settings.ValidateOnly = true;
                continue;
            }
            Require(Index + 1 < Argc, "option is missing its value");
            const std::string_view Value{Argv[++Index]};
            if (Argument == "--producers")
            {
                Settings.Producers = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--capacity")
            {
                Settings.Capacity = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--commands")
            {
                Settings.Commands = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--rounds")
            {
                Settings.Rounds = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--seed")
            {
                Settings.Seed = ParseUnsigned(Value);
            }
            else
            {
                throw std::invalid_argument("unknown option");
            }
        }
        if (Help)
        {
            return false;
        }
        if (Settings.ValidateOnly)
        {
            Require(Argc == 2, "--validate-only cannot be combined with benchmark options");
            return true;
        }
        Require(Settings.Producers == 1 || Settings.Producers == 2 || Settings.Producers == 4,
                "producers must be 1, 2, or 4");
        Require(Settings.Capacity >= 1 && Settings.Capacity <= 1'048'576,
                "capacity must be between 1 and 1048576");
        Require(Settings.Commands >= 100 && Settings.Commands <= 5'000'000,
                "commands must be between 100 and 5000000");
        Require(Settings.Rounds >= 1 && Settings.Rounds <= 100,
                "rounds must be between 1 and 100");
        return true;
    }

    auto PrintUsage() -> void
    {
        std::puts("MailboxCompare --producers 1|2|4 --capacity N --commands N");
        std::puts("                [--rounds N] [--seed N]");
        std::puts("MailboxCompare --validate-only");
        std::puts("同一 --capacity/--commands/--rounds/--seed 下分别运行 1、2、4 producer，trace_hash 应相同。");
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    try
    {
        Options Settings;
        if (!ParseOptions(Argc, Argv, Settings))
        {
            PrintUsage();
            return 0;
        }
        return Prism::Runtime::Perf::Run(Settings);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "[FAIL] %s\n", Error.what());
        PrintUsage();
        return 2;
    }
}
