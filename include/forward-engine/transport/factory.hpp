/**
 * @file factory.hpp
 * @brief 流工厂
 * @details 提供工厂函数，根据配置创建传输层和协议装饰器。
 * 支持 TCP、UDP 等传输层，以及 Trojan 等协议装饰器。
 */

#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/transport/unreliable.hpp>
#include <forward-engine/protocol/trojan/stream.hpp>
#include <memory>
#include <string>
#include <stdexcept>

namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @brief 流工厂
     * @details 静态工厂类，用于创建传输层和协议装饰器实例。
     */
    class factory
    {
    public:

        /**
         * @brief 创建传输层实例（从现有 socket）
         * @param socket TCP socket
         * @return transmission_pointer 传输层实例
         */
        static auto create_transport(net::ip::tcp::socket socket)
            -> transmission_pointer
        {
            return make_reliable(std::move(socket));
        }

        /**
         * @brief 创建传输层实例（从现有 UDP socket）
         * @param socket UDP socket
         * @param remote_endpoint 远程端点（可选）
         * @return transmission_pointer 传输层实例
         */
        static auto create_transport(net::ip::udp::socket socket, std::optional<net::ip::udp::endpoint> remote_endpoint = std::nullopt)
            -> transmission_pointer
        {
            return make_unreliable(std::move(socket), std::move(remote_endpoint));
        }

        /**
         * @brief 创建 Trojan 协议装饰器
         * @param next_layer 底层传输层
         * @param credential_verifier 凭据验证回调
         * @return transmission_pointer Trojan 装饰器实例
         */
        static auto create_trojan(transmission_pointer next_layer,std::function<bool(std::string_view)> credential_verifier = nullptr)
            -> transmission_pointer
        {
            return protocol::trojan::make_trojan_stream(std::move(next_layer), std::move(credential_verifier));
        }
    };

} // namespace ngx::transport