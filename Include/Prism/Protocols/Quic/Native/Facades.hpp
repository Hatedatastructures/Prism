/**
 * @file Facades.hpp
 * @brief 原生 QUIC Client、Server、Gateway 门面 owner。
 * @details 门面只转发到共享 NativeConnection，生命周期关闭仍由连接 owner 负责；
 *          多连接监听和 CID 路由由上层 Boundary/Registry 持有。
 */

#pragma once

#include <Prism/Protocols/Quic/Native/Connection.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace Prism::Quic
{

    inline auto Client::Datagram() const -> SharedDatagramProvider
    {
        if (Connection_)
        {
            return Connection_->DatagramProvider();
        }
        return nullptr;
    }

    inline auto Client::IsRetired() const noexcept -> bool
    {
        return !Connection_ || Connection_->IsRetired();
    }

    inline auto Client::Health() const noexcept -> NativeConnectionHealth
    {
        if (!Connection_)
        {
            return NativeConnectionHealth{.Closed = true};
        }
        return Connection_->Health();
    }

    inline auto Server::Datagram() const -> SharedDatagramProvider
    {
        if (Connection_)
        {
            return Connection_->DatagramProvider();
        }
        return nullptr;
    }

    inline auto Server::IsRetired() const noexcept -> bool
    {
        return !Connection_ && !TlsContext_ && !OnStarted_;
    }

    inline auto Server::Health() const noexcept -> NativeConnectionHealth
    {
        if (!Connection_)
        {
            return NativeConnectionHealth{.Closed = true};
        }
        return Connection_->Health();
    }

    inline auto Gateway::Datagram() const -> SharedDatagramProvider
    {
        if (Server_)
        {
            return Server_->Datagram();
        }
        return nullptr;
    }

    inline auto Gateway::IsRetired() const noexcept -> bool
    {
        return !Server_ || Server_->IsRetired();
    }

    inline auto Gateway::Health() const noexcept -> NativeConnectionHealth
    {
        if (!Server_)
        {
            return NativeConnectionHealth{.Closed = true};
        }
        return Server_->Health();
    }


} // namespace Prism::Quic
