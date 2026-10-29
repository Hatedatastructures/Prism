/**
 * @file Socks5IngressSupport.hpp
 * @brief SOCKS5 入口测试的 JSON 与诊断辅助。
 */
#pragma once
/**
 * @file Socks5IngressSupport.hpp
 * @brief Application SOCKS5 UserPass、CONNECT 与账户会话生命周期真实入口测试。
 */

#include <gtest/gtest.h>

#include <glaze/glaze.hpp>

#include "SocksCore.hpp"
#include "SocksClient.hpp"
#include "SocksOps.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

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
        if (Id == nullptr || !Id->is_string())
        {
            return std::nullopt;
        }
        const auto &Text = Id->get_string();
        std::uint64_t SessionValue{};
        const auto [End, Error] = std::from_chars(
            Text.data(), Text.data() + Text.size(), SessionValue);
        if (Error != std::errc{} || End != Text.data() + Text.size())
        {
            return std::nullopt;
        }
        return Prism::SessionId{SessionValue};
    }

    struct CommandObservation final
    {
        std::string Status;
        std::string Message;
        std::optional<std::uint64_t> Operation;
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
        const auto *Operation = FindJsonValue(*Document, "operation");
        if (Status == nullptr || Message == nullptr || Operation == nullptr ||
            !Status->is_string() || !Message->is_string() || !Operation->is_string())
        {
            return std::nullopt;
        }

        std::uint64_t OperationValue{};
        const auto &OperationText = Operation->get<std::string>();
        const auto [End, Error] = std::from_chars(
            OperationText.data(), OperationText.data() + OperationText.size(), OperationValue);
        if (Error != std::errc{} || End != OperationText.data() + OperationText.size())
        {
            return std::nullopt;
        }
        std::optional<std::uint64_t> OperationId;
        if (OperationValue != 0U)
        {
            OperationId = OperationValue;
        }
        return CommandObservation{
            Status->get<std::string>(), Message->get<std::string>(), OperationId};
    }

} // namespace

