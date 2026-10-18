/**
 * @file Socks5AccountIngressTestSupport.hpp
 * @brief SOCKS5 入口测试的 JSON 与诊断辅助。
 */
#pragma once
/**
 * @file Socks5AccountIngressTestSupport.hpp
 * @brief Application SOCKS5 UserPass、CONNECT 与账户会话生命周期真实入口测试。
 */

#include <gtest/gtest.h>

#include <glaze/glaze.hpp>

#include "Socks5AccountIngressCore.hpp"
#include "Socks5AccountIngressClient.hpp"
#include "Socks5AccountIngressOperations.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace
{

    namespace Testing = Prism::Testing::Socks5AccountIngress;

    auto OperationsFailure(const Testing::OperationsWaitResult &Result) -> std::string
    {
        return "Accounts response:\n" + Result.Last.Accounts +
               "\nSessions response:\n" + Result.Last.Sessions;
    }

    [[nodiscard]] auto FindJsonValue(const glz::generic &Document,
                                     const std::string_view Key) -> const glz::generic *
    {
        if (!Document.is_object())
        {
            return nullptr;
        }
        const auto &Object = Document.get_object();
        const auto Found = Object.find(Key);
        return Found == Object.end() ? nullptr : &Found->second;
    }

    [[nodiscard]] auto ParseJsonBody(const std::string_view Response)
        -> std::optional<glz::generic>
    {
        const auto HeaderEnd = Response.find("\r\n\r\n");
        if (HeaderEnd == std::string_view::npos)
        {
            return std::nullopt;
        }
        glz::generic Document;
        if (glz::read_json(Document, Response.substr(HeaderEnd + 4U)))
        {
            return std::nullopt;
        }
        return Document;
    }

    [[nodiscard]] auto SessionIdFromOperations(const std::string_view Response)
        -> std::optional<Prism::SessionId>
    {
        const auto Document = ParseJsonBody(Response);
        if (!Document)
        {
            return std::nullopt;
        }
        const auto *Status = FindJsonValue(*Document, "status");
        const auto *Value = FindJsonValue(*Document, "value");
        if (Status == nullptr || !Status->is_string() || Status->get<std::string>() != "ok" ||
            Value == nullptr || !Value->is_object())
        {
            return std::nullopt;
        }
        const auto *Items = FindJsonValue(*Value, "items");
        if (Items == nullptr || !Items->is_array() || Items->get_array().size() != 1U)
        {
            return std::nullopt;
        }
        const auto *Id = FindJsonValue(Items->get_array().front(), "id");
        if (Id == nullptr || !Id->is_number())
        {
            return std::nullopt;
        }
        return Prism::SessionId{static_cast<std::uint64_t>(Id->get_number())};
    }

    struct CommandObservation final
    {
        std::string Status;
        std::string Message;
    };

    [[nodiscard]] auto ParseCommandObservation(const std::string_view Response)
        -> std::optional<CommandObservation>
    {
        const auto Document = ParseJsonBody(Response);
        if (!Document)
        {
            return std::nullopt;
        }
        const auto *Status = FindJsonValue(*Document, "status");
        const auto *Message = FindJsonValue(*Document, "message");
        if (Status == nullptr || Message == nullptr || !Status->is_string() ||
            !Message->is_string())
        {
            return std::nullopt;
        }
        return CommandObservation{Status->get<std::string>(), Message->get<std::string>()};
    }

} // namespace

