/**
 * @file stream.hpp
 * @brief Trojan 协议装饰器
 * @details 实现了完整的 Trojan 协议装饰器，继承自 `transport::transmission`，提供协议握手、凭据验证和数据转发功能。
 * Trojan 协议是一种基于 TLS 的加密代理协议，通过在应用层添加固定格式的头部来实现流量伪装和认证。
 *
 * 核心特性：
 * - 协议完整：实现 Trojan 协议完整握手流程，支持所有地址类型和命令
 * - 装饰器模式：包装底层传输层，透明添加协议头部，支持链式组合
 * - 凭据验证：支持可配置的凭据验证回调，实现灵活的认证机制
 * - 协程友好：所有操作基于 `boost::asio::awaitable`，支持异步无阻塞处理
 * - 错误处理完善：使用 `gist::code` 错误码系统，提供详细的协议错误信息
 * - 能力控制：通过 config 结构控制 TCP/UDP 命令的启用状态
 *
 * 协议流程：
 * 1. 凭据读取：读取 56 字节用户凭据（通常为 SHA224 哈希）
 * 2. 协议头部：解析命令、地址类型、目标地址和端口
 * 3. 格式验证：验证 CRLF 分隔符和协议格式
 * 4. 命令检查：根据 config 检查命令是否允许
 * 5. 数据转发：握手成功后，提供透明的加密数据转发
 *
 * 安全特性：
 * - 凭据验证：支持密码哈希验证，防止未授权访问
 * - 协议混淆：协议格式设计为与正常 TLS 流量相似，增强抗检测能力
 * - 前向安全：依赖底层 TLS 传输提供前向安全性
 *
 * @note 设计原则：
 * - 严格遵循 Trojan 协议规范，确保与主流客户端兼容
 * - 装饰器模式允许灵活组合，如 Trojan over TLS over TCP
 * - 零拷贝设计：尽可能使用 `std::span` 引用原始数据，避免内存复制
 * - 内存高效：使用栈分配缓冲区，避免热路径堆分配
 *
 * @warning 安全考虑：必须启用凭据验证，否则协议无任何认证保护
 * @warning 加密依赖：协议本身不提供加密，依赖底层传输层（如 TLS）提供机密性
 * @warning 性能影响：协议头部增加固定开销，小包性能可能受影响
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
     * @class trojan_stream
     * @brief Trojan 协议装饰器
     * @details 实现完整的 Trojan 协议装饰器，包装底层传输层并添加协议握手和数据处理功能。
     * 该类采用装饰器设计模式，透明地增强底层传输层的功能，支持链式组合和灵活配置。
     *
     * 继承关系：
     * - 继承自 `transport::transmission`：提供统一的传输层接口
     * - 继承自 `std::enable_shared_from_this`：支持安全的共享指针管理
     *
     * 装饰器特性：
     * - 透明增强：对外提供与底层传输层相同的接口，内部添加协议处理逻辑
     * - 链式组合：可与其他装饰器（如 TLS、压缩）组合，形成处理管道
     * - 动态配置：支持运行时配置凭据验证器，适应不同认证需求
     *
     * 所有权模型：
     * - 持有 `next_layer_` 的独占所有权（unique_ptr）
     * - 生命周期与 trojan_stream 对象绑定
     * - close() 后 next_layer_ 仍有效，可再次使用
     * - 析构时自动释放底层资源
     *
     * 协议支持：
     * - 命令：`command::connect`（需 enable_tcp=true）、`command::udp_associate`（需 enable_udp=true）
     * - 地址类型：IPv4、IPv6、域名地址
     * - 凭据格式：56 字节固定长度，通常为密码的 SHA224 哈希
     * - 数据格式：协议头部后跟随原始负载，无额外封装
     *
     * 线程/协程边界：
     * - 所有方法必须在同一 strand 内调用
     * - 不支持并发访问，调用者需保证顺序执行
     *
     * @note 线程安全：单个实例非线程安全，应在同一协程或 `strand` 内使用
     * @note 生命周期：依赖底层传输层的生命周期，需确保底层传输层有效
     * @note 性能考虑：协议头部处理增加固定开销，建议用于中大型数据传输
     *
     * @warning 加密警告：本类不提供加密功能，必须与 TLS 等加密传输层组合使用
     * @warning 认证警告：未提供凭据验证器时，任何凭据都会通过，存在安全风险
     */
    class trojan_stream : public transport::transmission, public std::enable_shared_from_this<trojan_stream>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 底层传输层智能指针（必须已建立连接）
         * @param cfg 协议配置
         * @param credential_verifier 用户凭据验证回调函数（可选，默认无验证）
         * @details 构造 Trojan 协议装饰器，包装底层传输层并配置凭据验证器。
         * 构造后对象处于就绪状态，可立即开始协议握手或数据读写操作。
         *
         * 所有权转移：
         * - 构造函数通过 unique_ptr 获取底层传输层的所有权
         * - 调用者不应再使用原指针
         *
         * @note 连接状态：底层传输层必须已建立连接，否则后续操作将失败
         */
        explicit trojan_stream(transport::transmission_pointer next_layer,
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
         * @details 完整的 Trojan 协议握手流程，包括凭据验证、协议头部解析和命令检查。
         *
         * 状态机流程：
         *
         * 输入条件：next_layer_ 已建立连接
         *
         * 状态转换：
         * 1. [初始] -> 凭据读取
         *    - 读取 56 字节用户凭据
         *    - 调用验证器检查凭据有效性
         *
         * 2. [凭据验证完成] -> 头部解析
         *    - 读取 CRLF 分隔符
         *    - 读取命令和地址类型
         *    - 读取目标地址和端口
         *
         * 3. [头部解析完成] -> 命令检查
         *    - 根据 config 检查命令允许/拒绝
         *
         * 4. [命令检查完成] -> 返回结果
         *    - 成功：返回 request 对象，form 字段已根据命令设置
         *    - 失败：返回错误码
         *
         * 失败行为：
         * - 凭据验证失败：返回 auth_failed
         * - 协议格式错误：返回 protocol_error
         * - 网络错误：返回对应的网络错误码
         * - 命令拒绝：返回 forbidden
         *
         * @return `net::awaitable<std::pair<gist::code, request>>` 握手结果和请求信息
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

            // 命令检查：根据配置决定允许/拒绝
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
         * @brief 执行 Trojan 握手（使用预读数据）
         * @param preread_data 预读的数据
         * @return net::awaitable<std::pair<gist::code, request>> 握手结果和请求信息
         */
        auto handshake_preread(std::span<const std::byte> preread_data) -> net::awaitable<std::pair<gist::code, request>>
        {
            std::array<std::uint8_t, 1024> buffer;
            std::size_t offset = 0;

            // 复制预读数据到缓冲区
            if (!preread_data.empty())
            {
                const auto copy_size = std::min(preread_data.size(), buffer.size());
                std::memcpy(buffer.data(), preread_data.data(), copy_size);
                offset = copy_size;
            }

            auto read_exact = [this, &buffer, &offset](std::span<std::byte> out) -> net::awaitable<std::pair<gist::code, std::size_t>>
            {
                std::size_t total = 0;
                // 先从缓冲区读取
                while (total < out.size() && offset < 1024)
                {
                    out[total] = static_cast<std::byte>(buffer[offset]);
                    total++;
                    offset++;
                }
                // 剩余从网络读取
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
                std::array<std::byte, 2> crlf_buf;
                auto [read_ec, n] = co_await read_exact(crlf_buf);
                if (gist::failed(read_ec) || n != 2)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                auto ec_crlf = wire::decode_crlf(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(crlf_buf.data()), 2));
                if (gist::failed(ec_crlf))
                {
                    co_return std::pair{ec_crlf, request{}};
                }
            }

            {
                std::array<std::byte, 2> cmd_atyp_buf;
                auto [read_ec, n] = co_await read_exact(cmd_atyp_buf);
                if (gist::failed(read_ec) || n != 2)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                auto [ec_header, header] = wire::decode_cmd_atyp(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(cmd_atyp_buf.data()), 2));
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
                    std::array<std::byte, 4> addr_buf;
                    auto [read_ec2, n2] = co_await read_exact(addr_buf);
                    if (gist::failed(read_ec2) || n2 != 4)
                    {
                        co_return std::pair{gist::failed(read_ec2) ? read_ec2 : gist::code::bad_message, request{}};
                    }
                    auto [ec, addr] = wire::parse_ipv4(std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(addr_buf.data()), 4));
                    if (gist::failed(ec))
                    {
                        co_return std::pair{ec, request{}};
                    }
                    dest_addr = addr;
                    addr_len = 4;
                    break;
                }
                case address_type::ipv6:
                {
                    std::array<std::byte, 16> addr_buf;
                    auto [read_ec2, n2] = co_await read_exact(addr_buf);
                    if (gist::failed(read_ec2) || n2 != 16)
                    {
                        co_return std::pair{gist::failed(read_ec2) ? read_ec2 : gist::code::bad_message, request{}};
                    }
                    auto [ec, addr] = wire::parse_ipv6(std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(addr_buf.data()), 16));
                    if (gist::failed(ec))
                    {
                        co_return std::pair{ec, request{}};
                    }
                    dest_addr = addr;
                    addr_len = 16;
                    break;
                }
                case address_type::domain:
                {
                    std::byte len_byte;
                    auto [read_ec2, n2] = co_await read_exact(std::span<std::byte>(&len_byte, 1));
                    if (gist::failed(read_ec2) || n2 != 1)
                    {
                        co_return std::pair{gist::failed(read_ec2) ? read_ec2 : gist::code::bad_message, request{}};
                    }
                    std::uint8_t domain_len = static_cast<std::uint8_t>(len_byte);

                    std::array<std::uint8_t, 256> domain_buf;
                    domain_buf[0] = domain_len;
                    auto [read_ec3, n3] = co_await read_exact(std::span<std::byte>(
                        reinterpret_cast<std::byte *>(domain_buf.data() + 1), domain_len));
                    if (gist::failed(read_ec3) || n3 != domain_len)
                    {
                        co_return std::pair{gist::failed(read_ec3) ? read_ec3 : gist::code::bad_message, request{}};
                    }
                    auto [ec, addr] = wire::parse_domain(std::span<const std::uint8_t>(domain_buf.data(), 1 + domain_len));
                    if (gist::failed(ec))
                    {
                        co_return std::pair{ec, request{}};
                    }
                    dest_addr = addr;
                    addr_len = 1 + domain_len;
                    break;
                }
                default:
                    co_return std::pair{gist::code::unsupported_address, request{}};
                }

                std::array<std::byte, 2> port_buf;
                auto [read_ec4, n4] = co_await read_exact(port_buf);
                if (gist::failed(read_ec4) || n4 != 2)
                {
                    co_return std::pair{gist::failed(read_ec4) ? read_ec4 : gist::code::bad_message, request{}};
                }
                auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(port_buf.data()), 2));
                if (gist::failed(ec_port))
                {
                    co_return std::pair{ec_port, request{}};
                }

                std::array<std::byte, 2> final_crlf_buf;
                auto [read_ec5, n5] = co_await read_exact(final_crlf_buf);
                if (gist::failed(read_ec5) || n5 != 2)
                {
                    co_return std::pair{gist::failed(read_ec5) ? read_ec5 : gist::code::bad_message, request{}};
                }
                auto ec_final_crlf = wire::decode_crlf(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(final_crlf_buf.data()), 2));
                if (gist::failed(ec_final_crlf))
                {
                    co_return std::pair{ec_final_crlf, request{}};
                }

                request req;
                req.cmd = header.cmd;
                req.destination_address = dest_addr;
                req.port = port;
                std::copy(credential.begin(), credential.end(), req.credential.begin());

                // 命令检查
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
         * @details 释放后 trojan_stream 不再持有传输层，不应再调用其方法
         */
        transport::transmission_pointer release()
        {
            return std::move(next_layer_);
        }

    private:
        // next_layer_ 所有权说明：
        // - 构造时通过 unique_ptr 转移所有权
        // - 生命周期与 trojan_stream 对象绑定
        // - close() 后 next_layer_ 仍有效，可再次使用
        // - 析构时自动释放底层资源
        transport::transmission_pointer next_layer_;
        config config_;
        std::function<bool(std::string_view)> verifier_;
    };

    using trojan_stream_ptr = std::shared_ptr<trojan_stream>;

    inline trojan_stream_ptr make_trojan_stream(transport::transmission_pointer next_layer, const config &cfg = {},
                                                std::function<bool(std::string_view)> credential_verifier = nullptr)
    {
        return std::make_shared<trojan_stream>(std::move(next_layer), cfg, std::move(credential_verifier));
    }

} // namespace ngx::protocol::trojan
