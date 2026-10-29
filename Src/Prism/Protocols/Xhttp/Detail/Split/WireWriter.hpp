/**
 * @file WireWriter.hpp
 * @brief XHTTP Split 服务端 TLS frame 写入 owner。
 */
#pragma once

#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
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
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };
} // namespace Prism::Xhttp::Detail
