/**
 * @file stream.hpp
 * @brief SOCKS5 协议中继器
 * @details 实现完整的 SOCKS5 协议（RFC 1928）服务端中继器，提供
 * 协程友好的高级 API。该类继承自 transport::transmission，将底层
 * 传输层包装为 SOCKS5 协议中继，处理握手、认证、请求解析和响应
 * 生成。核心特性包括协议完整性（支持 CONNECT 和 UDP_ASSOCIATE
 * 命令）、地址类型全面（支持 IPv4、IPv6 和域名）、错误处理完善
 * （使用 fault::code 错误码系统）、能力控制（通过 config 结构控制
 * 命令启用状态）。协议流程分为方法协商、请求处理、命令检查、
 * 响应发送和数据转发五个阶段。内存高效，使用栈分配缓冲区避免
 * 热路径堆分配；统一抽象，继承 transmission 接口支持多态使用。
 */

#pragma once

#include <array>
#include <functional>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <forward-engine/fault/handling.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/protocol/common/form.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/protocol/socks5/message.hpp>
#include <forward-engine/protocol/socks5/wire.hpp>
#include <forward-engine/protocol/socks5/config.hpp>

namespace ngx::protocol::socks5
{
    namespace net = boost::asio;

    /**
     * @class relay
     * @brief SOCKS5 协议中继器
     * @details 将底层传输层封装为完整的 SOCKS5 协议中继，提供协程友好的
     * 高层 API。该类实现了 SOCKS5 协议的服务端逻辑，包括方法协商、请求
     * 处理和响应生成。relay 对象持有 next_layer_ 的独占所有权，其生命
     * 周期与 relay 对象绑定。调用 close() 后 next_layer_ 仍有效，可
     * 再次使用；析构时通过 unique_ptr 自动释放底层资源，无需显式定义
     * 析构函数。也可以通过 release() 提前转移所有权，但转移后不应再
     * 调用读写方法。
     * @note 实例非线程安全，应在同一协程或线程内使用
     * @note 拥有底层传输层的所有权，需确保生命周期正确管理
     * @note 握手缓冲区大小固定，避免动态分配
     * @warning 默认实现仅支持无认证，生产环境必须启用认证机制
     * @warning 严格遵循 RFC 1928，但某些扩展特性可能不受支持
     * @warning 不支持并发访问，调用者需保证顺序执行
     */
    class relay : public ngx::channel::transport::transmission, public std::enable_shared_from_this<relay>
    {
    public:
        // 路由回调函数类型，用于根据目标地址选择本地端点
        using route_callback = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

        /**
         * @brief 构造函数
         * @param next_layer 已经建立连接的底层传输层智能指针
         * @param cfg SOCKS5 协议配置
         * @details 构造 SOCKS5 协议中继对象，接管底层传输层的所有权。
         * 构造后对象处于初始状态，等待客户端发起 SOCKS5 握手流程。
         * @warning 构造函数通过独占智能指针获取底层传输层的所有权，
         * 调用者不应再使用原指针
         * @note 底层传输层必须已建立连接，否则后续操作将失败
         */
        explicit relay(ngx::channel::transport::transmission_pointer next_layer, const config &cfg = {})
            : next_layer_(std::move(next_layer)), config_(cfg)
        {
        }

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         * @details 返回底层传输层的执行器，用于协程调度和异步操作。
         */
        executor_type executor() const override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 异步读取数据
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         * @details 握手成功后，从底层传输层读取数据。直接透传到底层
         * 传输层的 async_read_some 方法。
         * @warning 调用前必须确保 next_layer_ 传输层指针有效且已连接
         */
        auto async_read_some(const std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         * @details 握手成功后，向底层传输层写入数据。直接透传到底层
         * 传输层的 async_write_some 方法。
         * @warning 调用前必须确保 next_layer_ 传输层指针有效且已连接
         */
        auto async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭传输层
         * @details 关闭底层传输层连接，释放网络资源。调用后 next_layer_
         * 指针仍然有效，但连接已断开。
         */
        void close() override
        {
            if (next_layer_)
            {
                next_layer_->close();
            }
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消底层传输层上所有待处理的异步操作，触发操作
         * 以 operation_aborted 错误码完成。
         */
        void cancel() override
        {
            if (next_layer_)
            {
                next_layer_->cancel();
            }
        }

        /**
         * @brief 异步处理 UDP 关联请求
         * @param request_info 包含请求信息的 SOCKS5 请求结构体
         * @param route_callback 路由回调函数，用于根据目标地址选择合适的本地端点
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 处理客户端发起的 UDP 关联请求，绑定本地端口并返回关联
         * 地址。成功后进入 UDP 数据报转发循环，直到控制连接关闭。
         * @warning 调用前必须确保 next_layer_ 传输层指针有效且已连接
         */
        auto async_associate(const request &request_info, route_callback route_callback) const
            -> net::awaitable<fault::code>
        {
            if (!config_.enable_udp || request_info.form != ngx::protocol::form::datagram)
            {
                co_return fault::code::not_supported;
            }

            auto [open_ec, ingress_socket] = co_await bind_datagram_port();
            if (fault::failed(open_ec))
            {
                co_await async_write_error(reply_code::server_failure);
                co_return open_ec;
            }

            boost::system::error_code endpoint_ec;
            const auto local_endpoint = ingress_socket.local_endpoint(endpoint_ec);
            if (endpoint_ec)
            {
                co_await async_write_error(reply_code::server_failure);
                co_return fault::to_code(endpoint_ec);
            }

            if (fault::failed(co_await async_write_associate_success(request_info, local_endpoint)))
            {
                boost::system::error_code ignore_ec;
                ingress_socket.close(ignore_ec);
                co_return fault::code::io_error;
            }

            using namespace boost::asio::experimental::awaitable_operators;
            co_await (associate_loop(ingress_socket, route_callback) || wait_control_close(ingress_socket));
            co_return fault::code::success;
        }

        /**
         * @brief 执行 SOCKS5 握手
         * @return net::awaitable<std::pair<fault::code, request>> 握手结果和请求信息
         * @details 执行完整的 SOCKS5 握手流程，包括方法协商、请求解析和
         * 命令检查。前提是 next_layer_ 已建立连接。握手过程首先进行方法
         * 协商：读取客户端支持的方法列表，并选择无认证方式（0x00）；若
         * 协商失败则立即返回错误码。协商成功后进入请求解析阶段，读取
         * 命令、地址类型和目标地址，并根据配置检查命令是否允许。命令
         * 处理规则：对于 connect 命令，要求 enable_tcp 为 true，成功后
         * form 字段设为 stream；对于 udp_associate 命令，要求 enable_udp
         * 为 true，成功后 form 设为 datagram；对于 bind 命令，要求
         * enable_bind 为 true，成功后 form 设为 stream。若命令不被支持
         * 或被配置禁用，会发送相应的错误响应并返回错误码。地址解析支持
         * IPv4、IPv6 和域名类型，解析失败时同样返回错误码。失败行为
         * 分类：协议错误（如方法协商失败、命令拒绝）会发送 SOCKS5 错误
         * 响应并返回错误码；网络错误（如读取失败）直接返回错误码，不
         * 发送响应。成功时返回包含目标地址、端口和命令信息的 request
         * 对象。
         */
        auto handshake()
            -> net::awaitable<std::pair<fault::code, request>>
        {
            const auto [negotiation_ec, method] = co_await negotiated_authentication();
            if (fault::failed(negotiation_ec))
            {
                co_return std::pair{negotiation_ec, request{}};
            }

            auto [read_ec, header] = co_await read_request_header();
            if (fault::failed(read_ec))
            {
                co_return std::pair{read_ec, request{}};
            }

            request req{};
            req.cmd = header.cmd;

            switch (req.cmd)
            {
            case command::connect:
                if (!config_.enable_tcp)
                {
                    co_await async_write_error(reply_code::connection_not_allowed);
                    co_return std::pair{fault::code::not_supported, request{}};
                }
                req.form = ngx::protocol::form::stream;
                break;
            case command::udp_associate:
                if (!config_.enable_udp)
                {
                    co_await async_write_error(reply_code::connection_not_allowed);
                    co_return std::pair{fault::code::not_supported, request{}};
                }
                req.form = ngx::protocol::form::datagram;
                break;
            case command::bind:
                if (!config_.enable_bind)
                {
                    co_await async_write_error(reply_code::command_not_supported);
                    co_return std::pair{fault::code::unsupported_command, request{}};
                }
                req.form = ngx::protocol::form::stream;
                break;
            default:
                co_await async_write_error(reply_code::command_not_supported);
                co_return std::pair{fault::code::unsupported_command, request{}};
            }

            switch (header.atyp)
            {
            case address_type::ipv4:
            {
                auto [ec, addr, port] = co_await read_address<4>(wire::parse_ipv4);
                if (fault::failed(ec))
                {
                    co_return std::pair{ec, request{}};
                }
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            case address_type::ipv6:
            {
                auto [ec, addr, port] = co_await read_address<16>(wire::parse_ipv6);
                if (fault::failed(ec))
                {
                    co_return std::pair{ec, request{}};
                }
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            case address_type::domain:
            {
                auto [ec, addr, port] = co_await read_domain_address();
                if (fault::failed(ec))
                {
                    co_return std::pair{ec, request{}};
                }
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            default:
                co_return std::pair{fault::code::unsupported_address, request{}};
            }

            co_return std::pair{fault::code::success, req};
        }

        /**
         * @brief 发送成功响应
         * @param info 请求信息，用于回显绑定地址和端口
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 构建并发送 SOCKS5 成功响应，包含绑定地址和端口信息。
         * 响应格式遵循 RFC 1928 规范。
         */
        auto async_write_success(const request &info) const
            -> net::awaitable<fault::code>
        {
            std::array<std::uint8_t, 262> buffer{};
            const std::size_t len = build_success_response(info, buffer);
            std::error_code ec;
            co_await async_write_impl(std::span(reinterpret_cast<const std::byte *>(buffer.data()), len), ec);
            co_return fault::to_code(ec);
        }

        /**
         * @brief 发送错误响应
         * @param code 错误码
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 构建并发送 SOCKS5 错误响应，使用固定格式的错误报文。
         * 响应中地址字段填充为零。
         */
        auto async_write_error(reply_code code) const
            -> net::awaitable<fault::code>
        {
            const std::array<std::uint8_t, 10> response = {
                0x05, static_cast<uint8_t>(code), 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00};
            std::error_code ec;
            co_await async_write_impl(std::span(reinterpret_cast<const std::byte *>(response.data()), response.size()), ec);
            co_return fault::to_code(ec);
        }

        /**
         * @brief 获取底层传输层引用
         * @return transport::transmission& 底层传输层引用
         * @details 返回底层传输层的可变引用，用于直接操作底层连接。
         * @warning 调用前应确保 is_valid() 返回 true
         */
        ngx::channel::transport::transmission &next_layer() noexcept
        {
            return *next_layer_;
        }

        /**
         * @brief 获取底层传输层常量引用
         * @return const transport::transmission& 底层传输层常量引用
         * @details 返回底层传输层的只读引用，用于查询底层连接状态。
         * @warning 调用前应确保 is_valid() 返回 true
         */
        const ngx::channel::transport::transmission &next_layer() const noexcept
        {
            return *next_layer_;
        }

        /**
         * @brief 检查底层传输层是否有效
         * @return bool true 表示有效，false 表示已被 release() 转移
         * @details 检查 next_layer_ 指针是否有效，用于判断是否可以
         * 安全调用读写方法。
         */
        [[nodiscard]] bool is_valid() const noexcept
        {
            return next_layer_ != nullptr;
        }

        /**
         * @brief 释放底层传输层所有权
         * @return transport::transmission_pointer 底层传输层指针
         * @details 释放底层传输层的所有权并返回指针。释放后 is_valid()
         * 返回 false，不应再调用读写方法。用于将底层连接转移给
         * 其他组件管理。
         */
        ngx::channel::transport::transmission_pointer release()
        {
            return std::move(next_layer_);
        }

    private:
        /**
         * @brief 打开并绑定 UDP 数据报端口
         * @return net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
         * 错误码与已绑定 socket
         * @details 使用当前执行器创建会话级 UDP socket，并绑定到
         * udp_bind_port 指定的端口。若 udp_bind_port 为 0，由系统
         * 自动分配端口。socket 绑定成功后可用于接收 UDP 数据报。
         */
        auto bind_datagram_port() const
            -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
        {
            boost::system::error_code ec;
            net::ip::udp::socket ingress_socket(executor());
            ingress_socket.open(net::ip::udp::v4(), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), net::ip::udp::socket(executor())};
            }

            ingress_socket.bind(net::ip::udp::endpoint(net::ip::udp::v4(), config_.udp_bind_port), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), net::ip::udp::socket(executor())};
            }

            co_return std::pair{fault::code::success, std::move(ingress_socket)};
        }

        /**
         * @brief 发送 UDP_ASSOCIATE 成功响应
         * @param request_info 原始请求信息
         * @param local_endpoint 本地 UDP 端点
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 将本地 UDP 绑定地址写入 SOCKS5 响应的 BND.ADDR 和
         * BND.PORT 字段，供客户端后续向该地址发送 UDP 数据报。
         */
        auto async_write_associate_success(const request &request_info, const net::ip::udp::endpoint &local_endpoint) const
            -> net::awaitable<fault::code>
        {
            request response_info = request_info;
            response_info.destination_address = endpoint_to_address(local_endpoint);
            response_info.destination_port = local_endpoint.port();
            co_return co_await async_write_success(response_info);
        }

        /**
         * @brief UDP_ASSOCIATE 主循环
         * @param ingress_socket 入站 UDP socket
         * @param route_callback 路由回调函数
         * @return net::awaitable<void> 异步操作
         * @details 持续读取客户端发往 ingress 的 UDP 数据报，并逐包转发。
         * 当 socket 被取消时（控制面关闭触发），协程退出。循环内部
         * 处理 SOCKS5 UDP 报头解析、路由查询、数据转发和响应封装。
         */
        auto associate_loop(net::ip::udp::socket &ingress_socket, route_callback &route_callback) const
            -> net::awaitable<void>
        {
            memory::vector<std::byte> ingress_buffer(config_.udp_max_datagram, memory::current_resource());
            memory::vector<std::byte> target_buffer(config_.udp_max_datagram, memory::current_resource());
            while (true)
            {
                boost::system::error_code read_ec;
                auto token = net::redirect_error(net::use_awaitable, read_ec);
                net::ip::udp::endpoint client_endpoint;
                const auto ingress_n = co_await ingress_socket.async_receive_from(
                    net::buffer(ingress_buffer.data(), ingress_buffer.size()), client_endpoint, token);
                if (read_ec)
                {
                    if (read_ec == net::error::operation_aborted)
                    {
                        co_return;
                    }
                    continue;
                }

                co_await relay_single_datagram(ingress_socket, std::span<const std::byte>(ingress_buffer.data(), ingress_n),
                                               client_endpoint, route_callback, target_buffer);
            }
        }

        /**
         * @brief 转发单个 SOCKS5 UDP 数据报
         * @param ingress_socket 入站 UDP socket
         * @param ingress_packet 入站数据包
         * @param client_endpoint 客户端端点
         * @param route_callback 路由回调函数
         * @param target_buffer 目标缓冲区
         * @return net::awaitable<void> 异步操作
         * @details 处理流程包括解码 SOCKS5 UDP 报头、调用路由回调解析
         * 目标端点、发送 payload 到目标并等待回包、将回包重新封装为
         * SOCKS5 UDP 数据报回写客户端。
         */
        auto relay_single_datagram(net::ip::udp::socket &ingress_socket, std::span<const std::byte> ingress_packet,
                                   const net::ip::udp::endpoint &client_endpoint, route_callback &route_callback, memory::vector<std::byte> &target_buffer) const
            -> net::awaitable<void>
        {
            const auto ingress_bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(ingress_packet.data()), ingress_packet.size());
            const auto [decode_ec, parsed] = wire::decode_udp_header(ingress_bytes);
            if (fault::failed(decode_ec))
            {
                co_return;
            }

            const auto target_host = to_string(parsed.header.destination_address, memory::current_resource());
            const auto target_port = std::to_string(parsed.header.destination_port);
            auto [route_ec, target_endpoint] = co_await route_callback(target_host, target_port);
            if (fault::failed(route_ec))
            {
                co_return;
            }

            if (parsed.header_size >= ingress_packet.size())
            {
                co_return;
            }

            boost::system::error_code io_ec;
            auto token = net::redirect_error(net::use_awaitable, io_ec);
            net::ip::udp::socket egress_socket(executor());
            egress_socket.open(target_endpoint.protocol(), io_ec);
            if (io_ec)
            {
                co_return;
            }

            const auto payload = ingress_packet.subspan(parsed.header_size);
            co_await egress_socket.async_send_to(net::buffer(payload.data(), payload.size()), target_endpoint, token);
            if (io_ec)
            {
                co_return;
            }

            net::ip::udp::endpoint sender_endpoint;
            const auto target_n = co_await egress_socket.async_receive_from(
                net::buffer(target_buffer.data(), target_buffer.size()), sender_endpoint, token);
            if (io_ec)
            {
                co_return;
            }

            wire::udp_header response_header{};
            response_header.destination_address = endpoint_to_address(sender_endpoint);
            response_header.destination_port = sender_endpoint.port();
            response_header.frag = 0;

            memory::vector<std::uint8_t> response_datagram(memory::current_resource());
            response_datagram.reserve(target_n + 64);
            const auto target_payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(target_buffer.data()), target_n);
            if (fault::failed(wire::encode_udp_datagram(response_header, target_payload, response_datagram)))
            {
                co_return;
            }

            co_await ingress_socket.async_send_to(net::buffer(response_datagram.data(), response_datagram.size()), client_endpoint, token);
        }

        /**
         * @brief 监听控制面关闭并停止 UDP 数据面
         * @param ingress_socket 入站 UDP socket
         * @return net::awaitable<void> 异步操作
         * @details 控制连接任意读结束（EOF 或错误）后，取消并关闭
         * ingress socket，驱动 UDP 主循环快速退出。这是 UDP_ASSOCIATE
         * 的标准终止机制。
         */
        auto wait_control_close(net::ip::udp::socket &ingress_socket) const
            -> net::awaitable<void>
        {
            std::array<std::byte, 1> dummy{};
            std::error_code control_ec;
            co_await next_layer_->async_read_some(std::span<std::byte>(dummy), control_ec);
            boost::system::error_code ignore_ec;
            ingress_socket.cancel(ignore_ec);
            ingress_socket.close(ignore_ec);
        }

        /**
         * @brief 将端点转换为地址结构
         * @param endpoint UDP 端点
         * @return address 地址变体
         * @details 根据 IP 地址版本自动选择 IPv4 或 IPv6 地址类型，
         * 将端点地址转换为 SOCKS5 地址格式。
         */
        [[nodiscard]] static auto endpoint_to_address(const net::ip::udp::endpoint &endpoint) -> address
        {
            if (endpoint.address().is_v4())
            {
                return ipv4_address{endpoint.address().to_v4().to_bytes()};
            }
            return ipv6_address{endpoint.address().to_v6().to_bytes()};
        }

        /**
         * @brief 协商 SOCKS5 认证方法
         * @return net::awaitable<std::pair<fault::code, auth_method>> 协商
         * 结果错误码与选定的认证方法
         * @details 读取客户端发送的方法协商请求，验证协议版本，检查
         * 客户端支持的方法列表中是否包含无认证方法（0x00）。若支持
         * 则选择无认证方法并返回成功；否则返回无可接受方法错误。
         * 当前实现仅支持无认证模式，后续可扩展用户名密码认证。
         */
        auto negotiated_authentication() const
            -> net::awaitable<std::pair<fault::code, auth_method>>
        {
            std::array<std::uint8_t, 258> methods_buffer{};

            std::error_code ec;
            co_await async_read_impl(std::span(reinterpret_cast<std::byte *>(methods_buffer.data()), 2), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), auth_method::no_acceptable_methods};
            }

            if (methods_buffer[0] != 0x05)
            {
                co_return std::pair{fault::code::protocol_error, auth_method::no_acceptable_methods};
            }

            const std::uint8_t nmethods = methods_buffer[1];

            co_await async_read_impl(std::span(reinterpret_cast<std::byte *>(methods_buffer.data() + 2), nmethods), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), auth_method::no_acceptable_methods};
            }

            bool no_auth_supported = false;
            const std::span<const std::uint8_t> methods(methods_buffer.data() + 2, nmethods);
            for (const auto method : methods)
            {
                if (method == 0x00)
                {
                    no_auth_supported = true;
                    break;
                }
            }

            if (!no_auth_supported)
            {
                constexpr std::uint8_t response[] = {0x05, 0xFF};
                co_await async_write_impl(std::span(reinterpret_cast<const std::byte *>(response), 2), ec);
                if (ec)
                {
                    co_return std::pair{fault::to_code(ec), auth_method::no_acceptable_methods};
                }
                co_return std::pair{fault::code::not_supported, auth_method::no_acceptable_methods};
            }

            constexpr std::uint8_t response[] = {0x05, 0x00};
            co_await async_write_impl(std::span(reinterpret_cast<const std::byte *>(response), 2), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), auth_method::no_acceptable_methods};
            }
            co_return std::pair{fault::code::success, auth_method::no_auth};
        }

        /**
         * @brief 读取请求头部
         * @return net::awaitable<std::pair<fault::code, wire::header_parse>>
         * 包含结果错误码和解析后的头部
         * @details 读取 4 字节的请求头部（VER + CMD + RSV + ATYP），
         * 并解析为结构化的头部信息。头部包含命令类型和地址类型，
         * 用于后续的地址读取和命令处理。
         */
        auto read_request_header() const
            -> net::awaitable<std::pair<fault::code, wire::header_parse>>
        {
            std::array<std::uint8_t, 4> request_header{};
            std::error_code ec;
            co_await async_read_impl(std::span(reinterpret_cast<std::byte *>(request_header.data()), 4), ec);

            if (ec)
            {
                co_return std::pair{fault::to_code(ec), wire::header_parse{}};
            }

            auto [header_ec, header] = wire::parse_header(request_header);
            if (fault::failed(header_ec))
            {
                co_return std::pair{header_ec, wire::header_parse{}};
            }
            co_return std::pair{fault::code::success, header};
        }

        /**
         * @brief 读取 IP 地址和端口
         * @tparam N IP 地址字节数（4 或 16）
         * @tparam Decoder 解码器类型
         * @param decoder 地址解码函数
         * @return net::awaitable<std::tuple<fault::code, address, uint16_t>>
         * 包含结果代码、地址和端口
         * @details 读取指定长度的 IP 地址数据和 2 字节端口，使用
         * 提供的解码器解析地址。适用于 IPv4 和 IPv6 地址类型。
         */
        template <size_t N, typename Decoder>
        auto read_address(Decoder &&decoder)
            -> net::awaitable<std::tuple<fault::code, address, uint16_t>>
        {
            std::array<std::uint8_t, N + 2> buffer{};
            std::error_code io_ec;
            co_await async_read_impl(std::span(reinterpret_cast<std::byte *>(buffer.data()), N + 2), io_ec);
            if (io_ec)
            {
                co_return std::tuple<fault::code, address, uint16_t>{fault::code::io_error, address{}, 0};
            }

            auto [decode_ec, ip] = decoder(std::span<const std::uint8_t>(buffer.data(), N));
            if (fault::failed(decode_ec))
            {
                co_return std::tuple<fault::code, address, uint16_t>{decode_ec, address{}, 0};
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + N, 2));
            if (fault::failed(ec_port))
            {
                co_return std::tuple<fault::code, address, uint16_t>{ec_port, address{}, 0};
            }

            co_return std::tuple{fault::code::success, address{ip}, port};
        }

        /**
         * @brief 读取域名地址和端口
         * @return net::awaitable<std::tuple<fault::code, address, uint16_t>>
         * 包含结果代码、地址和端口
         * @details 读取域名长度字节、域名内容和端口。域名格式为
         * 1 字节长度前缀后跟域名字符串，端口为 2 字节大端序整数。
         */
        auto read_domain_address() const
            -> net::awaitable<std::tuple<fault::code, address, uint16_t>>
        {
            std::uint8_t len = 0;
            std::error_code io_ec;
            co_await async_read_impl(std::span(reinterpret_cast<std::byte *>(&len), 1), io_ec);
            if (io_ec)
            {
                co_return std::tuple<fault::code, address, uint16_t>{fault::code::io_error, address{}, 0};
            }

            std::array<std::uint8_t, 258> buffer{};
            buffer[0] = len;

            co_await async_read_impl(std::span(reinterpret_cast<std::byte *>(buffer.data() + 1), len + 2), io_ec);
            if (io_ec)
            {
                co_return std::tuple<fault::code, address, uint16_t>{fault::code::io_error, address{}, 0};
            }

            auto [ec_domain, domain] = wire::parse_domain(std::span<const std::uint8_t>(buffer.data(), len + 1));
            if (fault::failed(ec_domain))
            {
                co_return std::tuple<fault::code, address, uint16_t>{ec_domain, address{}, 0};
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 1 + len, 2));
            if (fault::failed(ec_port))
            {
                co_return std::tuple<fault::code, address, uint16_t>{ec_port, address{}, 0};
            }

            co_return std::tuple{fault::code::success, address{domain}, port};
        }

        /**
         * @brief 构建 SOCKS5 成功响应
         * @param req 请求信息，用于获取地址类型和绑定地址
         * @param buffer 输出缓冲区，大小至少 262 字节
         * @return std::size_t 实际写入的字节数
         * @details 构建符合 RFC 1928 规范的成功响应报文。响应格式为
         * VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(变长) + BND.PORT(2)。
         * 根据地址类型写入不同格式的地址数据。
         */
        static auto build_success_response(const request &req, std::span<std::uint8_t> buffer)
            -> std::size_t
        {
            std::size_t offset = 0;
            buffer[offset++] = 0x05;
            buffer[offset++] = static_cast<std::uint8_t>(reply_code::succeeded);
            buffer[offset++] = 0x00;

            std::visit([&buffer, &offset]<typename Address>(const Address &addr)
                       {
                if constexpr (std::is_same_v<Address, ipv4_address>)
                {
                    buffer[offset++] = 0x01;
                    std::copy_n(addr.bytes.begin(), 4, buffer.subspan(offset).begin());
                    offset += 4;
                }
                else if constexpr (std::is_same_v<Address, ipv6_address>)
                {
                    buffer[offset++] = 0x04;
                    std::copy_n(addr.bytes.begin(), 16, buffer.subspan(offset).begin());
                    offset += 16;
                }
                else if constexpr (std::is_same_v<Address, domain_address>)
                {
                    buffer[offset++] = 0x03;
                    buffer[offset++] = addr.length;
                    std::copy_n(addr.value.begin(), addr.length, buffer.subspan(offset).begin());
                    offset += addr.length;
                } }, req.destination_address);

            buffer[offset++] = static_cast<std::uint8_t>((req.destination_port >> 8) & 0xFF);
            buffer[offset++] = static_cast<std::uint8_t>(req.destination_port & 0xFF);

            return offset;
        }

        /**
         * @brief 异步读取实现（内部）
         * @param buffer 要读取的字节数组
         * @param ec 错误码引用，用于存储读取错误信息
         * @return net::awaitable<std::size_t> 读取的字节数
         * @details 直接透传到底层传输层的 async_read_some 方法。
         * 注意 C++20 的 span 的 const 是针对 span 本身，不针对
         * std::byte，如果为 const std::byte 则不能写入数据。
         */
        auto async_read_impl(const std::span<std::byte> buffer, std::error_code &ec) const
            -> net::awaitable<std::size_t>
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 异步写入实现（内部）
         * @param buffer 要写入的字节数组
         * @param ec 错误码引用，用于存储写入错误信息
         * @return net::awaitable<std::size_t> 写入的字节数
         * @details 循环调用底层传输层的 async_write_some 方法，直到
         * 所有数据写入完成或发生错误。确保完整写入缓冲区内容。
         */
        auto async_write_impl(const std::span<const std::byte> buffer, std::error_code &ec) const
            -> net::awaitable<std::size_t>
        {
            std::size_t total = 0;
            while (total < buffer.size())
            {
                const auto n = co_await next_layer_->async_write_some(buffer.subspan(total), ec);
                if (ec)
                {
                    co_return total;
                }
                total += n;
            }
            co_return total;
        }

        // 底层传输层指针，所有权通过 unique_ptr 管理
        // 构造时转移所有权，生命周期与 stream 对象绑定
        // close() 后仍有效，析构时自动释放
        ngx::channel::transport::transmission_pointer next_layer_;

        // SOCKS5 协议配置，构造时传入，运行时只读
        config config_;
    };

    /**
     * @brief SOCKS5 中继器共享智能指针
     * @details 使用 shared_ptr 管理 relay 对象生命周期，支持协程
     * 上下文中的异步保活。通过 shared_from_this 实现安全回调。
     */
    using relay_pointer = std::shared_ptr<relay>;

    /**
     * @brief 创建 SOCKS5 中继器对象
     * @param next_layer 底层传输层指针
     * @param cfg SOCKS5 协议配置
     * @return relay_pointer 中继器对象共享指针
     * @details 工厂函数，封装 std::make_shared 调用，简化对象创建。
     */
    inline relay_pointer make_relay(ngx::channel::transport::transmission_pointer next_layer, const config &cfg = {})
    {
        return std::make_shared<relay>(std::move(next_layer), cfg);
    }

    // 兼容旧名称，将在未来版本移除
    using stream = relay;
    using stream_pointer = relay_pointer;
    inline stream_pointer make_stream(ngx::channel::transport::transmission_pointer next_layer, const config &cfg = {})
    {
        return make_relay(std::move(next_layer), cfg);
    }
}
