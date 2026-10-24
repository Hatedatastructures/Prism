/**
 * @file Record.cpp
 * @brief 按接收记录锁定的 epoch 渲染日志行。
 */
#include <Prism/Foundation/Utility/Diagnose/Detail/Record.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>

#if defined(_WIN32)
namespace
{
    [[nodiscard]] auto ConvertUtc(const std::time_t *Clock, std::tm *Utc) noexcept -> bool
    {
        return ::gmtime_s(Utc, Clock) == 0;
    }
}
#else
namespace
{
    [[nodiscard]] auto ConvertUtc(const std::time_t *Clock, std::tm *Utc) noexcept -> bool
    {
        return ::gmtime_r(Clock, Utc) != nullptr;
    }
}
#endif

namespace Prism::Diagnose::Detail
{
    auto FormatHumanTimestamp(const std::uint64_t Milliseconds) -> std::string
    {
        const auto Point = std::chrono::system_clock::time_point{
            std::chrono::milliseconds{static_cast<std::int64_t>(Milliseconds)}};
        const auto WholeSeconds = std::chrono::floor<std::chrono::seconds>(Point);
        const auto Clock = std::chrono::system_clock::to_time_t(WholeSeconds);
        std::tm Utc{};
        if (!ConvertUtc(&Clock, &Utc)) { return {}; }
        std::array<char, 32> Buffer{};
        const auto Length = std::strftime(Buffer.data(), Buffer.size(), "[%Y-%m-%d %H:%M:%S", &Utc);
        if (Length == 0U) { return {}; }
        const auto Fraction = static_cast<unsigned>(Milliseconds % 1000U);
        std::string Result(Buffer.data(), Length);
        Result.push_back('.');
        Result.push_back(static_cast<char>('0' + (Fraction / 100U)));
        Result.push_back(static_cast<char>('0' + ((Fraction / 10U) % 10U)));
        Result.push_back(static_cast<char>('0' + (Fraction % 10U)));
        Result.append("] ");
        return Result;
    }

    auto BuildPayload(const SubmissionRecord& Record) -> std::string
    {
        if (Record.Context.Mode == RenderMode::Structured)
        {
            auto Payload = ContextDecoder::RenderStructured(Record);
            if (!Payload.empty() && Payload.back() == '\n') { Payload.pop_back(); }
            return Payload;
        }
        auto Payload = ContextDecoder::RenderHuman(Record.Context, Record.Message);
        Payload.insert(0U, "[" + std::string(LogLevelName(Record.Level)) + "] ");
        if (Record.MessageTruncated) { Payload.append(" [MessageTruncated=true]"); }
        Payload.insert(0U, FormatHumanTimestamp(Record.TimestampMilliseconds));
        return Payload;
    }
}
