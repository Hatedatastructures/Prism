/**
 * @file stream.hpp
 * @brief Trojan 协议中继器
 * @details 实现完整的 Trojan 协议中继器，继承自 transport::transmission，
 * 提供协议握手、凭据验证和数据转发功能。Trojan 协议是一种基于 TLS 的
 * 加密代理协议，通过在应用层添加固定格式的头部来实现流量伪装和认证。
 * 该类采用装饰器设计模式，透明地增强底层传输层的功能，支持链式组合。
 * 协议流程包括凭据读取、协议头部解析、格式验证、命令检查和数据转发。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 *
 * @note 设计原则：严格遵循 Trojan 协议规范，确保与主流客户端兼容
 * @note 装饰器模式允许灵活组合，如 Trojan over TLS over TCP
 * @note 零拷贝设计：尽可能使用 std::span 引用原始数据，避免内存复制
 * @warning 安全考虑：必须启用凭据验证，否则协议无任何认证保护
 * @warning 加密依赖：协议本身不提供加密，依赖底层传输层提供机密性
 */

#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/transport/form.hpp>
#include <forward-engine/protocol/trojan/constants.hpp>
#include <forward-engine/protocol/trojan/message.hpp>
#include <forward-engine/protocol/trojan/wire.hpp>
#include <forward-engine/protocol/trojan/config.hpp>
#include <forward-engine/gist.hpp>
#include <forward-engine/gist/handling.hpp>
#include <memory>
#include <functional>
#include <span>
#include <array>
#include <algorithm>

namespace ngx::protocol::trojan
{
    namespace net = boost::asio;

    /**
     * @class relay
     * @brief Trojan 协议中继器
     * @details 实现完整的 Trojan 协议中继器，包装底层传输层并添加协议
     * 握手和数据处理功能。该类采用装饰器设计模式，透明地增强底层传输
     * 层的功能，支持链式组合和灵活配置。继承自 transport::transmission
     * 提供统一的传输层接口，继承自 std::enable_shared_from_this 支持安全
     * 的共享指针管理。持有 next_layer_ 的独占所有权，生命周期与对象绑定。
     * 支持命令包括 CONNECT（需 enable_tcp=true）和 UDP_ASSOCIATE（需
     * enable_udp=true），支持地址类型包括 IPv4、IPv6 和域名地址。
     *
     * @note 线程安全：单个实例非线程安全，应在同一协程或 strand 内使用
     * @note 生命周期：依赖底层传输层的生命周期，需确保底层传输层有效
     * @warning 加密警告：本类不提供加密功能，必须与 TLS 等加密传输层组合
     * @warning 认证警告：未提供凭据验证器时，任何凭据都会通过，存在安全风险
     */
    class relay : public transport::transmission, public std::enable_shared_from_this<relay>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 底层传输层智能指针，必须已建立连接
         * @param cfg 协议配置
         * @param credential_verifier 用户凭据验证回调函数，可选
         * @details 构造 Trojan 协议中继器，包装底层传输层并配置凭据验证器。
         * 构造后对象处于就绪状态，可立即开始协议握手或数据读写操作。
         * 构造函数通过 unique_ptr 获取底层传输层的所有权，调用者不应再使用原指针。
         *
         * @note 底层传输层必须已建立连接，否则后续操作将失败
         */
        explicit relay(transport::transmission_pointer next_layer,
                       const config &cfg = {},
                       std::function<bool(std::string_view)> credential_verifier = nullptr)
            : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(credential_verifier))
        {
        }

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
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
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭传输层
         */
        void close() override
        {
            next_layer_->close();
        }

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override
        {
            next_layer_->cancel();
        }

        /**
         * @brief 执行 Trojan 协议握手
         * @return net::awaitable<std::pair<gist::code, request>> 握手结果和请求信息
         * @details 完整的 Trojan 协议握手流程，包括凭据验证、协议头部解析和命令检查。
         * 状态机流程：首先读取 56 字节用户凭据并调用验证器检查有效性，然后读取
         * CRLF 分隔符，接着解析命令和地址类型，读取目标地址和端口，最后根据
         * config 检查命令是否允许。成功返回 request 对象，失败返回错误码。
         */
        auto handshake() -> net::awaitable<std::pair<gist::code, request>>
        {
            std::array<std::uint8_t, 1024> buffer;
            std::size_t offset = 0;

            auto read_exact = [this](std::span<std::byte> out) -> net::awaitable<std::pair<gist::code, std::size_t>>
            {
                std::size_t total = 0;
                while (total < out.size())
                {
                    std::error_code ec;
                    const auto n = co_await next_layer_->async_read_some(out.subspan(total), ec);
                    if (ec)
                    {
                        co_return std::pair{gist::to_code(ec), total};
                    }
                    if (n == 0)
                    {
                        co_return std::pair{gist::code::eof, total};
                    }
                    total += n;
                }
                co_return std::pair{gist::code::success, total};
            };

            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data()), 56);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec))
                {
                    co_return std::pair{read_ec, request{}};
                }
                if (n != 56)
                {
                    co_return std::pair{gist::code::bad_message, request{}};
                }
                offset += 56;
            }

            auto credential_span = std::span<const std::uint8_t>(buffer.data(), 56);
            auto [ec_cred, credential] = wire::decode_credential(credential_span);
            if (gist::failed(ec_cred))
            {
                co_return std::pair{ec_cred, request{}};
            }

            if (verifier_)
            {
                std::string_view cred_view(credential.data(), 56);
                if (!verifier_(cred_view))
                {
                    co_return std::pair{gist::code::auth_failed, request{}};
                }
            }

            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 2);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec) || n != 2)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                offset += 2;
            }

            auto crlf_span = std::span<const std::uint8_t>(buffer.data() + 56, 2);
            auto ec_crlf = wire::decode_crlf(crlf_span);
            if (gist::failed(ec_crlf))
            {
                co_return std::pair{ec_crlf, request{}};
            }

            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 2);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec) || n != 2)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                offset += 2;
            }

            auto cmd_atyp_span = std::span<const std::uint8_t>(buffer.data() + 58, 2);
            auto [ec_header, header] = wire::decode_cmd_atyp(cmd_atyp_span);
            if (gist::failed(ec_header))
            {
                co_return std::pair{ec_header, request{}};
            }

            address dest_addr;
            std::size_t addr_len = 0;

            switch (header.atyp)
            {
            case address_type::ipv4:
            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 4);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec) || n != 4)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                auto [ec, addr] = wire::parse_ipv4(std::span<const std::uint8_t>(buffer.data() + offset, 4));
                if (gist::failed(ec))
                {
                    co_return std::pair{ec, request{}};
                }
                dest_addr = addr;
                addr_len = 4;
                offset += 4;
                break;
            }
            case address_type::ipv6:
            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 16);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec) || n != 16)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                auto [ec, addr] = wire::parse_ipv6(std::span<const std::uint8_t>(buffer.data() + offset, 16));
                if (gist::failed(ec))
                {
                    co_return std::pair{ec, request{}};
                }
                dest_addr = addr;
                addr_len = 16;
                offset += 16;
                break;
            }
            case address_type::domain:
            {
                auto span_len = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 1);
                auto [read_ec, n] = co_await read_exact(span_len);
                if (gist::failed(read_ec) || n != 1)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                std::uint8_t domain_len = buffer[offset];
                offset += 1;

                auto span_domain = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), domain_len);
                auto [read_ec2, n2] = co_await read_exact(span_domain);
                if (gist::failed(read_ec2) || n2 != domain_len)
                {
                    co_return std::pair{gist::failed(read_ec2) ? read_ec2 : gist::code::bad_message, request{}};
                }
                auto [ec, addr] = wire::parse_domain(std::span<const std::uint8_t>(buffer.data() + offset - 1, 1 + domain_len));
                if (gist::failed(ec))
                {
                    co_return std::pair{ec, request{}};
                }
                dest_addr = addr;
                addr_len = 1 + domain_len;
                offset += domain_len;
                break;
            }
            default:
                co_return std::pair{gist::code::unsupported_address, request{}};
            }

            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 2);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec) || n != 2)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                offset += 2;
            }

            auto port_span = std::span<const std::uint8_t>(buffer.data() + offset - 2, 2);
            auto [ec_port, port] = wire::decode_port(port_span);
            if (gist::failed(ec_port))
            {
                co_return std::pair{ec_port, request{}};
            }

            {
                auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 2);
                auto [read_ec, n] = co_await read_exact(span);
                if (gist::failed(read_ec) || n != 2)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                offset += 2;
            }

            auto final_crlf_span = std::span<const std::uint8_t>(buffer.data() + offset - 2, 2);
            auto ec_final_crlf = wire::decode_crlf(final_crlf_span);
            if (gist::failed(ec_final_crlf))
            {
                co_return std::pair{ec_final_crlf, request{}};
            }

            request req;
            req.cmd = header.cmd;
            req.destination_address = dest_addr;
            req.port = port;
            std::copy(credential.begin(), credential.end(), req.credential.begin());

            switch (req.cmd)
            {
            case command::connect:
                if (!config_.enable_tcp)
                {
                    co_return std::pair{gist::code::forbidden, request{}};
                }
                req.form = transport::form::stream;
                break;
            case command::udp_associate:
                if (!config_.enable_udp)
                {
                    co_return std::pair{gist::code::forbidden, request{}};
                }
                req.form = transport::form::datagram;
                break;
            default:
                co_return std::pair{gist::code::unsupported_command, request{}};
            }

            co_return std::pair{gist::code::success, req};
        }

        /**
         * @brief 获取底层传输层引用
         * @return transport::transmission& 底层传输层引用
         */
        transport::transmission &next_layer() noexcept
        {
            return *next_layer_;
        }

        /**
         * @brief 获取底层传输层常量引用
         * @return const transport::transmission& 底层传输层常量引用
         */
        const transport::transmission &next_layer() const noexcept
        {
            return *next_layer_;
        }

        /**
         * @brief 释放底层传输层所有权
         * @return transport::transmission_pointer 底层传输层指针
         * @details 释放后 relay 不再持有传输层，不应再调用其方法。
         * 适用于需要将底层传输层转移给其他组件的场景。
         */
        transport::transmission_pointer release()
        {
            return std::move(next_layer_);
        }

    private:
        // 底层传输层，构造时通过 unique_ptr 转移所有权
        transport::transmission_pointer next_layer_;
        // 协议配置
        config config_;
        // 凭据验证回调函数
        std::function<bool(std::string_view)> verifier_;
    };

    /**
     * @brief Trojan 中继器共享智能指针
     * @details 使用 shared_ptr 管理 relay 对象生命周期，支持协程
     * 上下文中的异步保活。通过 shared_from_this 实现安全回调。
     */
    using relay_pointer = std::shared_ptr<relay>;

    /**
     * @brief 创建 Trojan 中继器对象
     * @param next_layer 底层传输层指针
     * @param cfg 协议配置
     * @param credential_verifier 凭据验证回调函数
     * @return relay_pointer 中继器对象共享指针
     * @details 工厂函数，封装 std::make_shared 调用，简化对象创建。
     */
    inline relay_pointer make_relay(transport::transmission_pointer next_layer, const config &cfg = {},
                                    std::function<bool(std::string_view)> credential_verifier = nullptr)
    {
        return std::make_shared<relay>(std::move(next_layer), cfg, std::move(credential_verifier));
    }

    // 兼容旧名称，将在未来版本移除
    using trojan_stream = relay;
    using trojan_stream_ptr = relay_pointer;
    inline trojan_stream_ptr make_trojan_stream(transport::transmission_pointer next_layer, const config &cfg = {},
                                                std::function<bool(std::string_view)> credential_verifier = nullptr)
    {
        return make_relay(std::move(next_layer), cfg, std::move(credential_verifier));
    }

}
