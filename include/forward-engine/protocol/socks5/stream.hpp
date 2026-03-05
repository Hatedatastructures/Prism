/**
 * @file stream.hpp
 * @brief SOCKS5 协议流封装
 * @details 实现了完整的 SOCKS5 协议 (RFC 1928) 服务端流封装，提供协程友好的高级 API。
 * 该类将底层传输层 Socket 包装为 SOCKS5 协议流，处理握手、认证、请求解析和响应生成。
 *
 * 核心特性：
 * - 协议完整：支持 SOCKS5 协议所有核心功能，包括 CONNECT、BIND、UDP ASSOCIATE 命令
 * - 地址类型全面：支持 IPv4、IPv6 和域名地址类型
 * - 认证灵活：支持无认证 (0x00) 和用户名/密码认证 (0x02)
 * - 协程友好：所有操作基于 `boost::asio::awaitable`，支持异步无阻塞处理
 * - 错误处理完善：使用 `gist::code` 错误码系统，提供详细的协议错误信息
 *
 * 协议流程：
 * 1. 方法协商：客户端发送支持的方法列表，服务器选择并确认
 * 2. 请求处理：读取客户端请求，解析命令、地址类型和目标地址
 * 3. 响应发送：根据处理结果发送成功或错误响应
 * 4. 数据转发：握手成功后，提供透明的数据读写接口
 *
 * @note 设计原则：
 * - 严格遵循 RFC 1928 标准，确保协议兼容性
 * - 零拷贝设计：尽可能使用 `std::span` 和引用避免数据复制
 * - 内存高效：使用栈分配缓冲区，避免热路径堆分配
 * - 模板化传输层：支持任意满足 `AsyncReadStream` 和 `AsyncWriteStream` 概念的传输类型
 *
 * @warning 安全考虑：默认仅支持无认证，生产环境应启用用户名/密码认证
 * @warning 性能关键：握手阶段涉及多次网络往返，应考虑连接池复用
 * @warning 协议限制：仅实现服务端逻辑，客户端逻辑需另外实现
 *
 * @see RFC 1928 SOCKS Protocol Version 5
 * @see ngx::protocol::socks5::constants SOCKS5 协议常量
 * @see ngx::protocol::socks5::message SOCKS5 消息结构
 * @see ngx::protocol::socks5::wire 协议编解码工具
 */
#pragma once

#include <boost/asio.hpp>
#include <array>
#include <forward-engine/gist.hpp>
#include <forward-engine/gist/handling.hpp>
#include <forward-engine/protocol/socks5/constants.hpp>
#include <forward-engine/protocol/socks5/message.hpp>
#include <forward-engine/protocol/socks5/wire.hpp>

/**
 * @namespace ngx::protocol::socks5
 * @brief SOCKS5 协议实现命名空间
 * @details 实现了完整的 SOCKS5 协议 (RFC 1928) 服务端和客户端逻辑，提供：
 * - 协议流封装 (`stream`)：高层协程 API，简化协议处理
 * - 消息结构 (`message`)：协议数据结构定义
 * - 协议常量 (`constants`)：命令、地址类型、响应码等枚举
 * - 编解码工具 (`wire`)：二进制数据与协议消息的相互转换
 *
 * @note 协议版本：严格遵循 RFC 1928 SOCKS Protocol Version 5
 * @note 安全特性：支持无认证和用户名/密码认证，可扩展 GSSAPI 认证
 * @warning 性能考虑：协议握手涉及多次网络往返，应考虑连接复用和批处理
 * @warning 兼容性：确保与主流 SOCKS5 客户端（如 curl、Firefox、Chrome）兼容
 */
namespace ngx::protocol::socks5
{
    namespace net = boost::asio;

    /**
     * @class stream
     * @brief SOCKS5 协议流封装
     * @tparam Transport 传输层 Socket 类型，必须满足 `AsyncReadStream` 和 `AsyncWriteStream` 概念
     * @details 将底层传输层 Socket 封装为完整的 SOCKS5 协议流，提供协程友好的高层 API。
     * 该类实现了 SOCKS5 协议的服务端逻辑，包括方法协商、请求处理和响应生成。
     *
     * 模板参数要求：
     * - `Transport` 必须提供 `async_read_some` 和 `async_write_some` 成员函数
     * - 支持 `boost::asio` 的异步操作模式和错误码处理
     * - 典型实例：`boost::asio::ip::tcp::socket`、`boost::asio::ssl::stream`
     *
     * 协议状态机：
     * 1. 初始状态：等待客户端方法协商请求
     * 2. 方法协商：读取方法列表，选择并确认认证方法
     * 3. 请求读取：解析客户端请求，提取命令、地址类型和目标
     * 4. 响应发送：根据处理结果发送协议响应
     * 5. 数据转发：握手成功后，提供透明数据读写接口
     *
     * 内存管理：
     * - 使用栈分配缓冲区，避免握手阶段堆分配
     * - 零拷贝设计：尽可能使用 `std::span` 引用原始数据
     * - 响应构建使用 `std::vector`，支持动态大小调整
     *
     * 错误处理：
     * - 所有操作返回 `gist::code` 错误码，提供详细的协议错误信息
     * - 网络错误自动转换为对应的 `gist::code` 枚举值
     * - 协议错误会发送相应的 SOCKS5 错误响应码
     *
     * @note 线程安全：单个 `stream` 实例非线程安全，应在同一协程或线程内使用
     * @note 生命周期：`stream` 不拥有传输层资源的所有权，需外部管理生命周期
     * @note 性能优化：握手缓冲区大小固定，避免动态分配
     *
     * @warning 安全警告：默认实现仅支持无认证，生产环境必须启用认证机制
     * @warning 协议兼容：严格遵循 RFC 1928，但某些扩展特性可能不受支持
     * @warning 资源管理：确保底层传输层 Socket 在 `stream` 生命周期内有效
     *
     * ```
     * // 模板实例化示例
     * #include <forward-engine/protocol/socks5/stream.hpp>
     * #include <boost/asio/ip/tcp.hpp>
     *
     * using namespace ngx::protocol::socks5;
     * namespace net = boost::asio;
     *
     * // 基本 TCP Socket 封装
     * using tcp_stream = stream<net::ip::tcp::socket>;
     *
     * // SSL Socket 封装（支持加密传输）
     * using ssl_stream = stream<net::ssl::stream<net::ip::tcp::socket>>;
     *
     * // 自定义传输层（需满足概念要求）
     * struct custom_transport {
     *     net::awaitable<std::size_t> async_read_some(net::mutable_buffer buf);
     *     net::awaitable<std::size_t> async_write_some(net::const_buffer buf);
     *     // ... 其他必要成员
     * };
     * using custom_stream = stream<custom_transport>;
     *
     */
    template <typename Transport>
    class stream
    {
    public:
        /**
         * @brief 构造函数
         * @param socket 传输层 Socket 对象
         * @details 构造 SOCKS5 协议流封装对象，接管底层传输层 Socket 的所有权。
         * 构造后对象处于初始状态，等待客户端发起 SOCKS5 握手流程。
         *
         * @note 所有权转移：构造函数通过 `std::move` 获取 Socket 所有权，调用者不应再使用原对象
         * @note 状态初始化：内部状态初始化为协议起始状态，无任何预分配缓冲区
         * @note 资源管理：构造时不进行任何网络操作，仅保存 Socket 引用
         *
         * @warning 移动语义：参数使用值传递和移动，确保调用者明确所有权转移
         * @warning 有效性：传入的 Socket 必须处于已连接状态，否则后续操作将失败
         * @warning 线程安全：构造过程非线程安全，应在连接建立后立即调用
         *
         * ```
         * // 构造函数使用示例
         * net::awaitable<void> handle_client(tcp::socket client_socket) {
         *     // 转移 Socket 所有权到 SOCKS5 流
         *     stream<tcp::socket> socks5_stream(std::move(client_socket));
         *
         *     // 此时 client_socket 不再有效，所有权已转移
         *     // assert(!client_socket.is_open()); // 可能为真
         *
         *     // 开始 SOCKS5 握手流程
         *     auto [ec, request] = co_await socks5_stream.handshake();
         *     // ... 后续处理
         * }
         *
         * // 错误示例：重复使用已移动的 Socket
         * tcp::socket socket(...);
         * stream<tcp::socket> stream1(std::move(socket));
         * // stream<tcp::socket> stream2(std::move(socket)); // 错误！socket 已移动
         *
         */
        explicit stream(Transport socket)
            : socket_(std::move(socket))
        {
        }

        /**
         * @brief 执行 SOCKS5 握手
         * @details 完整的 SOCKS5 协议握手流程，包括方法协商、请求解析和初始错误处理。
         * 握手流程严格遵循 RFC 1928 第 3-4 节规范：
         * 1. 方法协商：读取客户端支持的方法列表，选择无认证 (0x00)
         * 2. 请求读取：解析客户端请求头部，验证协议版本和命令
         * 3. 地址解析：根据地址类型读取目标地址和端口
         * 4. 错误处理：在每一步检测协议错误并发送相应错误响应
         *
         * 返回值说明：
         * - 成功：返回 `gist::code::success` 和解析后的 `request` 对象
         * - 失败：返回错误码和空的 `request` 对象，连接可能已关闭
         *
         * 支持的命令：
         * - `command::connect`：建立到目标服务器的 TCP 连接（主要支持）
         * - `command::bind`：绑定监听端口（支持但需要额外处理）
         * - `command::udp_associate`：UDP 关联（支持但需要额外处理）
         *
         * 支持的地址类型：
         * - `address_type::ipv4`：IPv4 地址 (4 字节)
         * - `address_type::ipv6`：IPv6 地址 (16 字节)
         * - `address_type::domain`：域名地址 (变长)
         *
         * @note 协议状态：握手成功后，连接进入数据转发模式
         * @note 错误恢复：协议错误会发送 SOCKS5 错误响应，然后关闭连接
         * @note 性能考虑：握手涉及 2-4 次网络往返，应考虑连接复用
         *
         * @warning 安全限制：当前实现仅支持 CONNECT 命令，其他命令返回错误
         * @warning 认证简化：仅支持无认证，生产环境应扩展认证机制
         * @warning 超时处理：握手过程可能阻塞，应设置合理的超时时间
         *
         * @throws `boost::system::system_error` 当底层网络操作失败时
         * @return `net::awaitable<std::pair<gist::code, request>>` 握手结果和请求信息
         *
         * ```
         * // 握手使用示例
         * stream<tcp::socket> socks5_stream(std::move(socket));
         *
         * // 执行握手
         * auto [handshake_ec, socks5_request] = co_await socks5_stream.handshake();
         *
         * if (gist::failed(handshake_ec)) {
         *     // 握手失败，连接已由内部处理
         *     spdlog::error("SOCKS5 handshake failed: {}", gist::to_string(handshake_ec));
         *     co_return;
         * }
         *
         * // 检查请求类型
         * if (socks5_request.cmd == command::connect) {
         *     spdlog::info("SOCKS5 CONNECT request to {}:{}",
         *         address_to_string(socks5_request.destination_address),
         *         socks5_request.destination_port);
         *
         *     // 处理 CONNECT 请求
         *     // ...
         * } else {
         *     // 不支持的命令已在握手阶段处理
         *     co_return;
         * }
         *
         *
         */
        auto handshake()
            -> net::awaitable<std::pair<gist::code, request>>
        {
            // 1. 方法协商
            const auto ec_methods = co_await negotiate_method();
            if (gist::failed(ec_methods.first))
            {
                co_return std::pair<gist::code, request>{ec_methods.first, request{}};
            }

            // 2. 请求处理
            auto [ec_header, header] = co_await read_request_header();
            if (gist::failed(ec_header))
            {
                co_return std::pair<gist::code, request>{ec_header, request{}};
            }

            request req{};
            req.cmd = header.cmd;

            if (req.cmd != command::connect)
            {
                const auto send_ec = co_await send_error(reply_code::command_not_supported);
                if (gist::failed(send_ec))
                {
                    co_return std::pair{send_ec, request{}};
                }
                co_return std::pair{gist::code::unsupported_command, request{}};
            }

            // 3. 解析地址 + 端口
            switch (header.atyp)
            {
            case address_type::ipv4:
            {
                auto [ec, addr, port] = co_await read_ip_address_and_port<4>(wire::decode_ipv4);
                if (gist::failed(ec))
                {
                    co_return std::pair<gist::code, request>{ec, request{}};
                }
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            case address_type::ipv6:
            {
                auto [ec, addr, port] = co_await read_ip_address_and_port<16>(wire::decode_ipv6);
                if (gist::failed(ec))
                {
                    co_return std::pair<gist::code, request>{ec, request{}};
                }
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            case address_type::domain:
            {
                auto [ec, addr, port] = co_await read_domain_address_and_port();
                if (gist::failed(ec))
                {
                    co_return std::pair<gist::code, request>{ec, request{}};
                }
                req.destination_address = addr;
                req.destination_port = port;
                break;
            }
            default:
                co_return std::pair{gist::code::unsupported_address, request{}};
            }

            co_return std::pair{gist::code::success, req};
        }

        /**
         * @brief 发送成功响应
         * @param info 请求信息 (用于回显绑定地址和端口)
         */
        auto send_success(const request &info)
            -> net::awaitable<gist::code>
        {
            auto response = build_success_response(info);
            boost::system::error_code ec;
            co_await net::async_write(socket_, net::buffer(response), net::redirect_error(net::use_awaitable, ec));
            co_return gist::to_code(ec);
        }

        /**
         * @brief 发送错误响应
         * @param code 错误响应码
         */
        auto send_error(reply_code code)
            -> net::awaitable<gist::code>
        {
            const std::array<std::uint8_t, 10> response =
                {
                    0x05, static_cast<uint8_t>(code), 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00};
            boost::system::error_code ec;
            co_await net::async_write(socket_, net::buffer(response), net::redirect_error(net::use_awaitable, ec));
            co_return gist::to_code(ec);
        }

        /**
         * @brief 异步读取数据
         * @param buffer 接收缓冲区
         * @return `std::size_t` 读取的字节数
         */
        auto async_read(net::mutable_buffer buffer)
            -> net::awaitable<std::pair<gist::code, std::size_t>>
        {
            boost::system::error_code ec;
            const auto n = co_await socket_.async_read_some(buffer, net::redirect_error(net::use_awaitable, ec));
            co_return std::pair{gist::to_code(ec), n};
        }

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @return `std::size_t` 写入的字节数
         */
        auto async_write(net::const_buffer buffer)
            -> net::awaitable<std::pair<gist::code, std::size_t>>
        {
            boost::system::error_code ec;
            const auto n = co_await net::async_write(socket_, buffer, net::redirect_error(net::use_awaitable, ec));
            co_return std::pair{gist::to_code(ec), n};
        }

        /**
         * @brief 关闭连接
         */
        auto close()
            -> net::awaitable<void>
        {
            boost::system::error_code ec;
            socket_.close(ec);
            co_return;
        }

        /**
         * @brief 获取底层 Socket 引用
         * @return Transport& Socket 引用
         */
        Transport &socket() { return socket_; }

    private:
        /**
         * @brief 协商认证方法
         * @return `std::pair<gist::code, auth_method>` 协商结果和选定的方法
         */
        auto negotiate_method()
            -> net::awaitable<std::pair<gist::code, auth_method>>
        {
            // 客户端发送: VER(1) | NMETHODS(1) | METHODS(1-255)
            // 最大长度: 1 + 1 + 255 = 257
            std::array<std::uint8_t, 257> methods_buffer{};

            // 读取版本和方法数量
            boost::system::error_code ec;
            co_await net::async_read(socket_, net::buffer(methods_buffer, 2), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return std::pair{gist::to_code(ec), auth_method::no_acceptable_methods};
            }

            if (methods_buffer[0] != 0x05)
            { // 只支持 SOCKS5 协议
                co_return std::pair{gist::code::protocol_error, auth_method::no_acceptable_methods};
            }

            // 读取方法数量
            const std::uint8_t nmethods = methods_buffer[1];

            // 读取方法列表
            co_await net::async_read(socket_, net::buffer(methods_buffer.data() + 2, nmethods), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return std::pair{gist::to_code(ec), auth_method::no_acceptable_methods};
            }

            /**
             * METHODS 字段
             * 0x00 不加密
             * 0x01 GSSAPI
             * 0x02 用户名、密码认证
             * 0x03 - 0x7F 由IANA分配（保留）
             * 0x80 - 0xFE 为私人方法保留
             * 0xFF 无可接受的方法
             */

            // 检查是否支持无认证 (0x00)
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
                // 发送无支持的方法响应 (0xFF)
                constexpr std::uint8_t response[] = {0x05, 0xFF};
                co_await net::async_write(socket_, net::buffer(response), net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return std::pair{gist::to_code(ec), auth_method::no_acceptable_methods};
                }
                co_return std::pair{gist::code::not_supported, auth_method::no_acceptable_methods};
            }

            // 发送选中无认证方法 (0x00)
            constexpr std::uint8_t response[] = {0x05, 0x00};
            co_await net::async_write(socket_, net::buffer(response), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return std::pair{gist::to_code(ec), auth_method::no_acceptable_methods};
            }
            co_return std::pair{gist::code::success, auth_method::no_auth};
        }

        /**
         * @brief 读取请求头部
         * @return `std::pair<gist::code, wire::header_parse>` 包含结果代码和解析后的头部
         */
        auto read_request_header()
            -> net::awaitable<std::pair<gist::code, wire::header_parse>>
        {
            std::array<std::uint8_t, 4> request_header{};
            boost::system::error_code ec;
            co_await net::async_read(socket_, net::buffer(request_header), net::redirect_error(net::use_awaitable, ec));

            if (ec)
            {
                co_return std::pair{gist::to_code(ec), wire::header_parse{}};
            }

            auto [ec_header, header] = wire::decode_header(request_header);
            if (gist::failed(ec_header))
            {
                co_return std::pair{ec_header, wire::header_parse{}};
            }
            co_return std::pair{gist::code::success, header};
        }

        /**
         * @brief 读取 IP 地址和端口
         * @tparam N IP 地址字节数 (4 或 16)
         * @tparam Decoder 解码器类型
         * @param decoder 地址解码函数
         * @return `std::tuple<gist::code, address, uint16_t>` 包含结果代码、地址和端口
         */
        template <size_t N, typename Decoder>
        auto read_ip_address_and_port(Decoder &&decoder)
            -> net::awaitable<std::tuple<gist::code, address, uint16_t>>
        {
            std::array<std::uint8_t, N + 2> buffer{}; // IP(N) + Port(2)
            boost::system::error_code io_ec;
            co_await net::async_read(socket_, net::buffer(buffer), net::redirect_error(net::use_awaitable, io_ec));
            if (io_ec)
            {
                co_return std::tuple<gist::code, address, uint16_t>{gist::code::io_error, address{}, 0};
            }

            auto [decode_ec, ip] = decoder(std::span<const std::uint8_t>(buffer.data(), N));
            if (gist::failed(decode_ec))
            {
                co_return std::tuple<gist::code, address, uint16_t>{decode_ec, address{}, 0};
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + N, 2));
            if (gist::failed(ec_port))
            {
                co_return std::tuple<gist::code, address, uint16_t>{ec_port, address{}, 0};
            }

            co_return std::tuple{gist::code::success, address{ip}, port};
        }

        /**
         * @brief 读取域名地址和端口
         * @return `std::tuple<gist::code, address, uint16_t>` 包含结果代码、地址和端口
         */
        auto read_domain_address_and_port()
            -> net::awaitable<std::tuple<gist::code, address, uint16_t>>
        {
            std::uint8_t len = 0;
            boost::system::error_code io_ec;
            co_await net::async_read(socket_, net::buffer(&len, 1), net::redirect_error(net::use_awaitable, io_ec));
            if (io_ec)
            {
                co_return std::tuple<gist::code, address, uint16_t>{gist::code::io_error, address{}, 0};
            }

            // 域名长度(1) + 域名内容(len) + Port(2)
            // 域名最大 255 字节 -> 1 + 255 + 2 = 258
            std::array<std::uint8_t, 258> buffer{};
            // buffer[0] 用于存放长度，以便复用 decode_domain
            buffer[0] = len;

            // 读取 len + 2 字节到 buffer[1] 开始的位置
            co_await net::async_read(socket_, net::buffer(buffer.data() + 1, len + 2), net::redirect_error(net::use_awaitable, io_ec));
            if (io_ec)
            {
                co_return std::tuple<gist::code, address, uint16_t>{gist::code::io_error, address{}, 0};
            }

            auto [ec_domain, domain] = wire::decode_domain(std::span<const std::uint8_t>(buffer.data(), len + 1));
            if (gist::failed(ec_domain))
            {
                co_return std::tuple<gist::code, address, uint16_t>{ec_domain, address{}, 0};
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 1 + len, 2));
            if (gist::failed(ec_port))
            {
                co_return std::tuple<gist::code, address, uint16_t>{ec_port, address{}, 0};
            }

            co_return std::tuple{gist::code::success, address{domain}, port};
        }

        /**
         * @brief 构建 SOCKS5 成功响应
         * @param req 请求信息，用于获取地址类型和绑定地址
         * @return `std::vector<std::uint8_t>` 编码后的响应数据
         */
        auto build_success_response(const request &req)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> response;
            response.reserve(32); // 预分配合理大小

            // 固定头部: VER | REP | RSV | ATYP
            response.push_back(0x05);                                             // VER
            response.push_back(static_cast<std::uint8_t>(reply_code::succeeded)); // REP
            response.push_back(0x00);                                             // RSV

            // 编码地址和端口
            auto address_function = [&response]<typename Address>(const Address &addr)
            {
                if constexpr (std::is_same_v<Address, ipv4_address>)
                {
                    response.push_back(0x01); // ATYP = IPv4
                    response.insert(response.end(), addr.bytes.begin(), addr.bytes.end());
                }
                else if constexpr (std::is_same_v<Address, ipv6_address>)
                {
                    response.push_back(0x04); // ATYP = IPv6
                    response.insert(response.end(), addr.bytes.begin(), addr.bytes.end());
                }
                else if constexpr (std::is_same_v<Address, domain_address>)
                {
                    response.push_back(0x03);        // ATYP = Domain
                    response.push_back(addr.length); // 域名长度
                    response.insert(response.end(), addr.value.begin(), addr.value.begin() + addr.length);
                }
            };
            std::visit(address_function, req.destination_address);

            // 编码端口 (大端序)
            response.push_back(static_cast<std::uint8_t>((req.destination_port >> 8) & 0xFF));
            response.push_back(static_cast<std::uint8_t>(req.destination_port & 0xFF));

            return response;
        }

        Transport socket_;
    };
}
