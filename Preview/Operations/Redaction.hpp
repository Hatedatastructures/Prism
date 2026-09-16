/**
 * @file Redaction.hpp
 * @brief Operations API 的值快照脱敏。
 */

#pragma once

#include <Preview/Operations/Models.hpp>
#include <Preview/Statistics/Redaction.hpp>

#include <type_traits>
#include <utility>

namespace Preview::Operations
{

    [[nodiscard]] inline auto Redact(std::string_view Detail) -> std::string
    {
        return Preview::Statistics::RedactSensitiveText(Detail);
    }

    [[nodiscard]] inline auto Redact(const EventSnapshot &EventValue) -> EventSnapshot
    {
        auto Result = EventValue;
        Result.Detail = Redact(Result.Detail);
        return Result;
    }

    [[nodiscard]] inline auto Redact(const HealthSnapshot &Value) -> HealthSnapshot
    {
        return Value;
    }

    [[nodiscard]] inline auto Redact(const GenerationSnapshot &Value) -> GenerationSnapshot
    {
        return Value;
    }

    [[nodiscard]] inline auto Redact(const ProcessSnapshot &Value) -> ProcessSnapshot
    {
        return Value;
    }

    [[nodiscard]] inline auto Redact(const WorkerSnapshot &Value) -> WorkerSnapshot
    {
        return Value;
    }

    [[nodiscard]] inline auto Redact(const AccountSnapshot &Value) -> AccountSnapshot
    {
        auto Result = Value;
        Result.Label = Redact(Result.Label);
        return Result;
    }

    [[nodiscard]] inline auto Redact(const SessionSnapshot &Value) -> SessionSnapshot
    {
        auto Result = Value;
        Result.Protocol = Redact(Result.Protocol);
        Result.Target = Redact(Result.Target);
        return Result;
    }

    [[nodiscard]] inline auto Redact(const StreamSnapshot &Value) -> StreamSnapshot
    {
        auto Result = Value;
        Result.Protocol = Redact(Result.Protocol);
        return Result;
    }

    [[nodiscard]] inline auto Redact(const TaskSnapshot &Value) -> TaskSnapshot
    {
        return Value;
    }

    template <typename Value>
    [[nodiscard]] auto Redact(const Page<Value> &PageValue) -> Page<Value>
    {
        auto Result = PageValue;
        for (auto &Item : Result.Items)
        {
            Item = Redact(Item);
        }
        return Result;
    }

    [[nodiscard]] inline auto Redact(const CommandResult &Value) -> CommandResult
    {
        auto Result = Value;
        Result.Message = Redact(Result.Message);
        return Result;
    }

    [[nodiscard]] inline auto Redact(const QueryResult &Value) -> QueryResult
    {
        auto Result = Value;
        Result.Message = Redact(Result.Message);
        std::visit(
            [](auto &Payload)
            {
                using PayloadType = std::remove_cvref_t<decltype(Payload)>;
                if constexpr (!std::is_same_v<PayloadType, std::monostate>)
                {
                    Payload = Redact(Payload);
                }
            },
            Result.Value);
        return Result;
    }

} // namespace Preview::Operations
