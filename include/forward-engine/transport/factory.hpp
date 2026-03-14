/**
 * @file factory.hpp
 * @brief 流工厂
 * @details 提供工厂函数，根据配置创建传输层和协议装饰器。
 * 支持 TCP、UDP 等传输层，以及 Trojan 等协议装饰器。
 * 工厂类 factory 提供静态工厂方法，无需实例化，支持从现有 socket
 * 创建 TCP 和 UDP 传输层，支持创建 Trojan 等协议装饰器，
 * 所有工厂方法返回 transmission_pointer 智能指针。使用模板参数和
 * 返回类型确保类型安全性，所有工厂方法返回智能指针自动管理对象
 * 生命周期，可轻松添加新的传输层或协议装饰器类型，工厂方法无需
 * 额外配置，参数完全通过函数签名传递。该工厂是传输层和协议装饰器
 * 的统一创建入口。
 * @note 该工厂类不需要实例化，所有方法都是静态的。
 * @warning 工厂方法可能抛出 std::bad_alloc（内存分配失败）或
 * std::runtime_error（配置错误）。
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
     * @class factory
     * @brief 流工厂
     * @details 静态工厂类，用于创建传输层和协议装饰器实例。
     * 该类提供了统一的创建接口，隐藏了具体的实现细节。
     * 核心职责包括传输层创建，支持从现有 socket 创建 TCP 和 UDP 传输层；
     * 协议装饰器创建，支持创建 Trojan 等协议装饰器；智能指针管理，
     * 所有工厂方法返回智能指针，自动管理生命周期；错误处理，
     * 工厂方法可能抛出异常，调用者应处理异常。工厂方法包括
     * create_transport(tcp::socket) 从 TCP socket 创建可靠传输层，
     * create_transport(udp::socket, endpoint) 从 UDP socket 创建
     * 不可靠传输层，create_trojan(transmission_pointer, verifier)
     * 创建 Trojan 协议装饰器。线程安全性设计方面，工厂类不持有任何状态，
     * 所有方法都是静态的，静态方法可以在多线程中安全调用，
     * 工厂方法可能抛出异常，调用者应正确处理。
     * @note 该工厂类不需要实例化，所有方法都是静态的。
     * @warning 工厂方法可能抛出 std::bad_alloc（内存分配失败）或
     * std::runtime_error（配置错误）。
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::runtime_error 如果 socket 或配置无效
     */
    class factory
    {
    public:

        /**
         * @brief 创建传输层实例（从现有 socket）
         * @details 从现有的 TCP socket 创建可靠传输层实例。
         * 传输层接管 socket 的所有权。该方法是创建 TCP 传输层的标准方式。
         * 创建流程为 Socket 接管，接收 TCP socket 的所有权；
         * 传输层包装，将 socket 包装为 reliable 传输层；
         * 智能指针返回，返回 transmission_pointer 智能指针，自动管理生命周期。
         * @param socket TCP socket，所有权将被转移
         * @return transmission_pointer 传输层实例智能指针
         * @note 传输层接管 socket 后，调用者不应再使用原始 socket。
         * @warning Socket 必须已打开，否则传输层可能无法正常工作。
         * @throws std::bad_alloc 如果内存分配失败
         */
        static auto create_transport(net::ip::tcp::socket socket)
            -> transmission_pointer
        {
            return make_reliable(std::move(socket));
        }

        /**
         * @brief 创建传输层实例（从现有 UDP socket）
         * @details 从现有的 UDP socket 创建不可靠传输层实例。
         * 传输层接管 socket 的所有权。该方法是创建 UDP 传输层的标准方式。
         * 创建流程为 Socket 接管，接收 UDP socket 的所有权；
         * 远程端点，接收可选的远程端点，用于无连接 UDP；
         * 传输层包装，将 socket 包装为 unreliable 传输层；
         * 智能指针返回，返回 transmission_pointer 智能指针，
         * 自动管理生命周期。
         * @param socket UDP socket，所有权将被转移
         * @param remote_endpoint 远程端点（可选），用于无连接 UDP
         * @return transmission_pointer 传输层实例智能指针
         * @note UDP 传输层支持有连接和无连接两种模式。
         * @warning 对于有连接 UDP，远程端点由 socket 自动管理。
         * @throws std::bad_alloc 如果内存分配失败
         */
        static auto create_transport(net::ip::udp::socket socket, std::optional<net::ip::udp::endpoint> remote_endpoint = std::nullopt)
            -> transmission_pointer
        {
            return make_unreliable(std::move(socket), std::move(remote_endpoint));
        }

        /**
         * @brief 创建 Trojan 协议装饰器
         * @details 创建 Trojan 协议装饰器，用于加密和认证代理流量。
         * 装饰器包装底层传输层，在数据传输前进行加密和认证处理。
         * 创建流程为传输层包装，接收底层传输层的所有权；
         * 凭据验证，接收凭据验证回调，用于 Trojan 握手认证；
         * 装饰器构造，将传输层包装为 Trojan 装饰器；
         * 智能指针返回，返回 transmission_pointer 智能指针，
         * 自动管理生命周期。Trojan 协议特性包括 TLS 加密，
         * 所有流量通过 TLS 加密传输；凭据认证，
         * 使用密码哈希或令牌进行认证；混淆技术，
         * 使用密码派生密钥进行数据混淆；流量伪装，
         * 加密流量伪装成正常的 HTTPS 流量。
         * @param next_layer 底层传输层，所有权将被转移
         * @param credential_verifier 凭据验证回调，用于 Trojan 握手认证
         * @return transmission_pointer Trojan 装饰器实例智能指针
         * @note 凭据验证回调在 Trojan 握手时被调用。
         * @warning 凭据验证回调必须线程安全，可能在多线程中调用。
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::runtime_error 如果底层传输层无效
         */
        static auto create_trojan(transmission_pointer next_layer,std::function<bool(std::string_view)> credential_verifier = nullptr)
            -> transmission_pointer
        {
            return protocol::trojan::make_trojan_stream(std::move(next_layer), std::move(credential_verifier));
        }
    };

}
