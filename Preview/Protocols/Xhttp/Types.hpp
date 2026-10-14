/**
 * @file Types.hpp
 * @brief XHTTP 伪装方案的公开类型定义。
 * @details XHTTP = TLS + HTTP/2 + Stream-one（单 POST 长连接）。
 *          客户端经 h2 POST {Path} 建立双向流，服务端响应 200 后
 *          流量透明传输（HTTP/2 DATA 帧承载）。
 */

#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/Encrypted.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/ssl/context.hpp>

#include <expected>
#include <memory>

#include <string>

namespace Preview::Xhttp
{

    namespace Net = boost::asio;

    /**
     * @struct Config
     * @brief XHTTP 方案配置。
     * @note Path 为空时方案不可用；是否挂载由调用方决定。
     */
    struct Config
    {
        std::string Path{"/"}; ///< POST 路径前缀
        std::string Host{}; ///< 可选的 :authority 约束
        std::string Mode{"StreamOne"}; ///< StreamOne / StreamUp / PacketUp

        /**
         * @brief 判断方案是否启用。
         * @return 路径与模式有效时返回真；是否挂载由调用方决定。
         */
        [[nodiscard]] auto Enabled() const noexcept -> bool
        {
            return !Path.empty() &&
                   (Mode == "StreamOne" || Mode == "StreamUp" || Mode == "PacketUp");
        }

        [[nodiscard]] auto IsSplit() const noexcept -> bool
        {
            return Mode == "StreamUp" || Mode == "PacketUp";
        }
    };


    /**
     * @struct ClientConnectRequest
     * @brief XHTTP 客户端连接的正式按值输入。
     * @details Raw、Config、Host 和 byte pool 由 factory 接管；TLS context 由调用方
     *          保活到连接 awaitable 完成。
     */
    struct ClientConnectRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context *SslContext{nullptr};
        Config Configuration;
        std::string Host;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

    using FactoryResult = std::expected<SharedTransmission, Preview::Fault::Failure>;

    /** @brief XHTTP 服务端接受结果，保留真实 TLS 协商快照与唯一 transport owner。 */
    struct ServerAcceptance final
    {
        SharedTransmission Transport;
        Preview::Transport::Encrypted::NegotiatedTlsInfo Negotiated;
    };

    using ServerAcceptResult = std::expected<ServerAcceptance, Preview::Fault::Failure>;

} // namespace Preview::Xhttp
