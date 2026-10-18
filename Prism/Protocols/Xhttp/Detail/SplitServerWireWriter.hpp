/**
 * @file SplitServerWireWriter.hpp
 * @brief XHTTP Split 服务端 TLS frame 写入 owner。
 */
#pragma once

#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <system_error>

namespace Prism::Xhttp::Detail
{
    struct SplitServerWireWriter final
    {
        std::weak_ptr<Prism::Transport::Encrypted> Encrypted;

        [[nodiscard]] auto operator()(std::span<const std::byte> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return Run(Encrypted, Data);
        }

        [[nodiscard]] static auto Run(
            std::weak_ptr<Prism::Transport::Encrypted> Encrypted,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Owner = Encrypted.lock();
            if (!Owner)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }
            const auto Result = co_await Owner->WriteExact(Data);
            if (Result.Failure.Failed())
            {
                co_return std::unexpected(Result.Failure);
            }
            if (Result.Bytes != Data.size())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
    };
} // namespace Prism::Xhttp::Detail
