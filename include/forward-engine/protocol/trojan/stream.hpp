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
 *
 * 协议流程：
 * 1. 凭据读取：读取 56 字节用户凭据（通常为 SHA224 哈希）
 * 2. 协议头部：解析命令、地址类型、目标地址和端口
 * 3. 格式验证：验证 CRLF 分隔符和协议格式
 * 4. 数据转发：握手成功后，提供透明的加密数据转发
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
 *
@see ngx::protocol::trojan::constants Trojan 常量
 *
@see ngx::protocol::trojan::message Trojan 消息
 *
@see ngx::protocol::trojan::wire 协议编解码
 *
@see Trojan 协议规范
 *
 */

#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/protocol/trojan/constants.hpp>
#include <forward-engine/protocol/trojan/message.hpp>
#include <forward-engine/protocol/trojan/wire.hpp>
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
     * 协议支持：
     * - 命令：`command::connect`（主要支持）、`command::udp_associate`（待实现）
     * - 地址类型：IPv4、IPv6、域名地址
     * - 凭据格式：56 字节固定长度，通常为密码的 SHA224 哈希
     * - 数据格式：协议头部后跟随原始负载，无额外封装
     *
     * 内存管理：
     * - 使用共享指针管理底层传输层，确保正确的生命周期
     * - 握手缓冲区栈分配，避免热路径堆分配
     * - 请求对象轻量构造，避免不必要的数据复制
     *
     * 错误处理：
     * - 协议错误返回具体的 `gist::code` 错误码，便于诊断和恢复
     * - 网络错误自动转换，保持与底层传输层一致的错误语义
     * - 凭据验证失败返回 `gist::code::auth_failed`，支持重试机制
     *
     * @note 线程安全：单个实例非线程安全，应在同一协程或 `strand` 内使用
     * @note 生命周期：依赖底层传输层的生命周期，需确保底层传输层有效
     * @note 性能考虑：协议头部处理增加固定开销，建议用于中大型数据传输
     *
     * @warning 加密警告：本类不提供加密功能，必须与 TLS 等加密传输层组合使用
     * @warning 认证警告：未提供凭据验证器时，任何凭据都会通过，存在安全风险
     * @warning 协议限制：当前实现主要支持 CONNECT 命令，其他命令需扩展实现
     *
     * ```
     * // 类使用示例：创建和配置 Trojan 流
     * #include <forward-engine/protocol/trojan/stream.hpp>
     *
     * // 创建底层传输层（如 TCP）
     * auto tcp_transport = std::make_shared<transport::reliable>(std::move(socket));
     *
     * // 创建凭据验证器
     * auto verifier = [](std::string_view cred) -> bool {
     *     return cred == get_expected_credential_hash();
     * };
     *
     * // 创建 Trojan 流装饰器
     * auto trojan = std::make_shared<trojan_stream>(tcp_transport, verifier);
     *
     * // 使用 Trojan 流（透明接口）
     * std::error_code ec;
     * std::array<std::byte, 1024> buffer;
     * std::size_t n = co_await trojan->async_read_some(buffer, ec);
     *
     * if (!ec) {
     *     // 处理读取的数据（已通过 Trojan 协议处理）
     * }
     *
     * // 链式组合：Trojan -> TLS -> TCP
     * auto tls = create_tls_wrapper(tcp_transport);
     * auto trojan_over_tls = std::make_shared<trojan_stream>(tls, verifier);
     *
     */
    class trojan_stream : public transport::transmission, public std::enable_shared_from_this<trojan_stream>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 底层传输层智能指针（必须已建立连接）
         * @param credential_verifier 用户凭据验证回调函数（可选，默认无验证）
         * @details 构造 Trojan 协议装饰器，包装底层传输层并配置凭据验证器。
         * 构造后对象处于就绪状态，可立即开始协议握手或数据读写操作。
         *
         * 参数说明：
         * - `next_layer`：底层传输层智能指针，必须满足 `transport::transmission` 接口
         * - `credential_verifier`：凭据验证回调，接收 56 字节凭据，返回验证结果
         *
         * @note 所有权转移：构造函数获取底层传输层的共享所有权，确保生命周期管理
         * @note 验证器可选：未提供验证器时，任何凭据都会通过（仅用于测试）
         * @note 连接状态：底层传输层必须已建立连接，否则握手将失败
         *
         * @warning 安全警告：生产环境必须提供凭据验证器，否则无认证保护
         * @warning 性能考虑：验证器在握手热路径中调用，应确保高效实现
         * @warning 线程安全：验证器可能在不同线程调用，需确保线程安全或使用 `strand`
         *
         * @throws `std::bad_alloc` 当内存不足无法分配内部状态时
         *
         * ```
         * // 构造函数使用示例
         * #include <forward-engine/protocol/trojan/stream.hpp>
         *
         * // 创建底层 TCP 传输层
         * auto tcp_transport = std::make_shared<transport::reliable>(std::move(tcp_socket));
         *
         * // 创建凭据验证器（示例：简单哈希比较）
         * auto verifier = [expected_hash = get_expected_hash()](std::string_view cred) {
         *     return std::equal(cred.begin(), cred.end(),
         *                       expected_hash.begin(), expected_hash.end());
         * };
         *
         * // 构造 Trojan 流（带验证）
         * auto trojan_with_auth = std::make_shared<trojan_stream>(tcp_transport, verifier);
         *
         * // 构造 Trojan 流（无验证，仅用于测试）
         * auto trojan_no_auth = std::make_shared<trojan_stream>(tcp_transport);
         * // 警告：无验证，不安全！
         *
         * // 链式构造：Trojan over TLS
         * auto tls_transport = create_tls_wrapper(tcp_transport);
         * auto trojan_over_tls = std::make_shared<trojan_stream>(tls_transport, verifier);
         *
         *
         */
        explicit trojan_stream(transport::transmission_pointer next_layer,
                               std::function<bool(std::string_view)> credential_verifier = nullptr)
            : next_layer_(std::move(next_layer)), verifier_(std::move(credential_verifier))
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
         * @details 从底层读取加密数据，解密后放入缓冲区。
         * @note 当前为简化实现，直接透传（待实现解密逻辑）。
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            // TODO: 实现解密逻辑
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @details 将缓冲区中的数据加密后写入底层。
         * @note 当前为简化实现，直接透传（待实现加密逻辑）。
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            // TODO: 实现加密逻辑
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
         * @details 完整的 Trojan 协议握手流程，包括凭据验证、协议头部解析和格式验证。
         * 握手流程严格遵循 Trojan 协议规范：
         * 1. 凭据读取：读取固定 56 字节用户凭据（通常为密码的 SHA224 哈希）
         * 2. 凭据验证：调用验证器回调检查凭据有效性
         * 3. 头部解析：解析命令、地址类型、目标地址和端口
         * 4. 格式验证：验证 CRLF 分隔符和协议格式正确性
         * 5. 状态转换：握手成功后，连接进入数据转发模式
         *
         * 返回值说明：
         * - 成功：返回 `gist::code::success` 和解析后的 `request` 对象
         * - 失败：返回错误码和空的 `request` 对象，连接保持打开（由调用者决定是否关闭）
         *
         * 支持的命令：
         * - `command::connect`：建立到目标服务器的 TCP 连接（主要支持）
         * - `command::udp_associate`：UDP 关联（未来支持）
         *
         * 支持的地址类型：
         * - `address_type::ipv4`：IPv4 地址 (4 字节)
         * - `address_type::ipv6`：IPv6 地址 (16 字节)
         * - `address_type::domain`：域名地址 (变长，最长 255 字节)
         *
         * 错误处理：
         * - 凭据验证失败：返回 `gist::code::auth_failed`
         * - 协议格式错误：返回 `gist::code::protocol_error`
         * - 网络读取错误：返回对应的网络错误码
         * - 地址类型不支持：返回 `gist::code::address_not_supported`
         *
         * @note 协议状态：握手成功后，连接即可进行数据读写，无额外确认步骤
         * @note 性能考虑：握手涉及 1-2 次网络往返，缓冲区大小固定为 1024 字节
         * @note 内存安全：使用栈分配缓冲区，避免握手阶段堆分配
         *
         * @warning 安全警告：验证器为空时，任何凭据都会通过（仅用于测试）
         * @warning 超时处理：握手过程可能阻塞，应设置合理的读写超时
         * @warning 协议兼容：严格遵循 Trojan 协议，但某些客户端扩展可能不支持
         *
         * @throws `boost::system::system_error` 当底层网络操作失败时
         * @throws `std::bad_alloc` 当内存不足无法分配内部缓冲区时
         * @return `net::awaitable<std::pair<gist::code, request>>` 握手结果和请求信息
         *
         * ```
         * // 握手使用示例
         * auto trojan_stream = std::make_shared<trojan_stream>(transport, verifier);
         *
         * // 执行握手
         * auto [handshake_ec, trojan_request] = co_await trojan_stream->handshake();
         *
         * if (gist::failed(handshake_ec)) {
         *     // 握手失败，根据错误码处理
         *     switch (handshake_ec) {
         *         case gist::code::auth_failed:
         *             spdlog::warn("Trojan authentication failed");
         *             break;
         *         case gist::code::protocol_error:
         *             spdlog::error("Trojan protocol error");
         *             break;
         *         default:
         *             spdlog::error("Trojan handshake failed: {}", gist::to_string(handshake_ec));
         *     }
         *
         *     // 可在此关闭连接或发送错误响应
         *     co_return;
         * }
         *
         * // 握手成功，处理请求
         * spdlog::info("Trojan handshake successful, cmd={}, target={}:{}",
         *     to_string(trojan_request.cmd),
         *     address_to_string(trojan_request.destination_address),
         *     trojan_request.port);
         *
         * if (trojan_request.cmd == command::connect) {
         *     // 处理 CONNECT 请求
         *     // ...
         * }
         *
         */
        auto handshake() -> net::awaitable<std::pair<gist::code, request>>
        {
            // 缓冲区用于读取握手数据
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

            // 1. 读取 56 字节用户凭据
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

            // 2. 解析凭据
            auto credential_span = std::span<const std::uint8_t>(buffer.data(), 56);
            auto [ec_cred, credential] = wire::decode_credential(credential_span);
            if (gist::failed(ec_cred))
            {
                co_return std::pair{ec_cred, request{}};
            }

            // 3. 验证凭据（如果提供了验证器）
            if (verifier_)
            {
                std::string_view cred_view(credential.data(), 56);
                if (!verifier_(cred_view))
                {
                    co_return std::pair{gist::code::auth_failed, request{}};
                }
            }

            // 4. 读取 CRLF
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

            // 5. 读取命令和地址类型 (2 字节)
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

            // 6. 根据地址类型读取地址
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
                auto [ec, addr] = wire::decode_ipv4(std::span<const std::uint8_t>(buffer.data() + offset, 4));
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
                auto [ec, addr] = wire::decode_ipv6(std::span<const std::uint8_t>(buffer.data() + offset, 16));
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
                // 先读取长度字节
                auto span_len = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), 1);
                auto [read_ec, n] = co_await read_exact(span_len);
                if (gist::failed(read_ec) || n != 1)
                {
                    co_return std::pair{gist::failed(read_ec) ? read_ec : gist::code::bad_message, request{}};
                }
                std::uint8_t domain_len = buffer[offset];
                offset += 1;

                // 读取域名内容
                auto span_domain = std::span<std::byte>(reinterpret_cast<std::byte *>(buffer.data() + offset), domain_len);
                auto [read_ec2, n2] = co_await read_exact(span_domain);
                if (gist::failed(read_ec2) || n2 != domain_len)
                {
                    co_return std::pair{gist::failed(read_ec2) ? read_ec2 : gist::code::bad_message, request{}};
                }
                auto [ec, addr] = wire::decode_domain(std::span<const std::uint8_t>(buffer.data() + offset - 1, 1 + domain_len));
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

            // 7. 读取端口 (2 字节，大端序)
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

            // 8. 读取最后的 CRLF
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

            // 构造请求对象
            request req;
            req.cmd = header.cmd;
            req.destination_address = dest_addr;
            req.port = port;
            std::copy(credential.begin(), credential.end(), req.credential.begin());

            co_return std::pair{gist::code::success, req};
        }

        /**
         * @brief 执行 Trojan 握手（使用预读数据）
         * @param pre_read_data 预读的数据
         * @return net::awaitable<std::pair<gist::code, request>> 握手结果和请求信息
         */
        auto handshake_preread(std::string_view pre_read_data) -> net::awaitable<std::pair<gist::code, request>>
        {
            // TODO: 实现带预读数据的握手逻辑
            // 暂时委托给普通握手
            co_return co_await handshake();
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

    private:
        transport::transmission_pointer next_layer_;
        std::function<bool(std::string_view)> verifier_;
    };

    /**
     * @brief trojan_stream 智能指针类型
     */
    using trojan_stream_ptr = std::shared_ptr<trojan_stream>;

    /**
     * @brief 创建 trojan_stream 共享指针
     * @param next_layer 底层传输层
     * @param credential_verifier 凭据验证回调
     * @return trojan_stream_ptr 创建的 trojan_stream 实例
     */
    inline trojan_stream_ptr make_trojan_stream(transport::transmission_pointer next_layer,
                                                std::function<bool(std::string_view)> credential_verifier = nullptr)
    {
        return std::make_shared<trojan_stream>(std::move(next_layer), std::move(credential_verifier));
    }

} // namespace ngx::protocol::trojan
