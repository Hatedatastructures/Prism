/**
 * @file Conn.hpp
 * @brief TrustTunnel 流连接的公开请求与拥有型结果类型。
 * @details Conn 的线协议、认证缓冲和关闭状态机由 Detail::Conn 独占实现。
 */
#pragma once

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <memory>
#include <string>

namespace Prism::Trusttunnel
{

    /** @brief TrustTunnel 流连接构造的按值冷路径输入。 */
    struct ConnRequest final
    {
        SharedTransmission Upstream;
        std::string User;
        std::string Password;
    };

    namespace Detail
    {
        template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
        class Conn;
    }

    using SharedConn = std::shared_ptr<Detail::Conn<>>;

} // namespace Prism::Trusttunnel