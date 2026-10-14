/** @file RenderRecord.hpp
 * @brief 按 accepted record 固定的 epoch 渲染日志行。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>

namespace Preview::Diagnose::Detail
{
    [[nodiscard]] inline auto FormatHumanTimestamp(const std::uint64_t Milliseconds) -> std::string
    {
        const auto Point = std::chrono::system_clock::time_point{
            std::chrono::milliseconds{static_cast<std::int64_t>(Milliseconds)}};
        const auto WholeSeconds = std::chrono::floor<std::chrono::seconds>(Point);
        const auto Clock = std::chrono::system_clock::to_time_t(WholeSeconds);
        const auto *Local = std::localtime(&Clock);
        if (!Local)
        {
            return {};
        }
        std::array<char, 32> Buffer{};
        const auto Length = std::strftime(Buffer.data(), Buffer.size(), "[%Y-%m-%d %H:%M:%S", Local);
        if (Length == 0U)
        {
            return {};
        }
        const auto Fraction = static_cast<unsigned>(Milliseconds % 1000U);
        std::string Result(Buffer.data(), Length);
        Result.push_back('.');
        Result.push_back(static_cast<char>('0' + (Fraction / 100U)));
        Result.push_back(static_cast<char>('0' + ((Fraction / 10U) % 10U)));
        Result.push_back(static_cast<char>('0' + (Fraction % 10U)));
        Result.append("] ");
        return Result;
    }

    /** @brief 后台渲染一条独立拥有的记录，渲染策略来自其 accepted epoch。 */
    [[nodiscard]] inline auto BuildPayload(const SubmissionRecord& Record) -> std::string
    {
        if (Record.Context.Mode == RenderMode::Structured)
        {
            auto Payload = ContextDecoder::RenderStructured(Record);
            if (!Payload.empty() && Payload.back() == '\n')
            {
                Payload.pop_back();
            }
            return Payload;
        }
        auto Payload = ContextDecoder::RenderHuman(Record.Context, Record.Message);
        Payload.insert(0U, "[" + std::string(LogLevelName(Record.Level)) + "] ");
        if (Record.MessageTruncated)
        {
            Payload.append(" [MessageTruncated=true]");
        }
        Payload.insert(0U, FormatHumanTimestamp(Record.TimestampMilliseconds));
        return Payload;
    }
}