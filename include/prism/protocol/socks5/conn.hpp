/**
 * @file conn.hpp
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

#include <prism/account/directory.hpp>
#include <prism/account/entry.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/socks5/config.hpp>
#include <prism/protocol/socks5/constants.hpp>
#include <prism/protocol/socks5/framing.hpp>
#include <prism/protocol/socks5/packet.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <atomic>
#include <charconv>
#include <functional>


namespace psm::stats::traffic { class traffic_state; }

namespace psm::protocol::socks5
{

    namespace net = boost::asio;
    using shared_transmission = psm::transport::shared_transmission;

    // 路由回调函数类型，用于根据目标地址选择本地端点
    using route_callback = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

    /**
     * @struct relay_context
     * @brief UDP 数据报中继上下文，聚合 socket 和回调引用
     * @details 将 relay_single_datagram 的多个引用参数收敛为单一结构，
     * 避免函数参数超过 3 个。ingress/egress socket 和路由回调跨数据报复用，
     * target_buffer 作为编码缓冲区跨数据报复用。
     */
    struct relay_context
    {
        net::ip::udp::socket &ingress;  ///< 入站 UDP socket
        net::ip::udp::socket &egress;   ///< 出站 UDP socket（惰性打开，跨数据报复用）
        route_callback &route_cb;       ///< 路由回调函数
        memory::vector<std::byte> &target_buf; ///< 目标缓冲区（接收回包复用）
    }; // struct relay_context

    /**
     * @class conn
     * @brief SOCKS5 协议中继器
     * @details 将底层传输层封装为完整的 SOCKS5 协议中继，提供协程友好的
     * 高层 API。该类实现了 SOCKS5 协议的服务端逻辑，包括方法协商、请求
     * 处理和响应生成。conn 对象持有 next_layer_ 的独占所有权，其生命
     * 周期与 conn 对象绑定。调用 close() 后 next_layer_ 仍有效，可
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
    class conn : public psm::transport::transmission, public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 已经建立连接的底层传输层智能指针
         * @param cfg SOCKS5 协议配置
         * @param account_dir 账户目录指针，用于认证验证（可为空）
         * @details 构造 SOCKS5 协议中继对象，接管底层传输层的所有权。
         * 构造后对象处于初始状态，等待客户端发起 SOCKS5 握手流程。
         * @warning 构造函数通过独占智能指针获取底层传输层的所有权，
         * 调用者不应再使用原指针
         * @note 底层传输层必须已建立连接，否则后续操作将失败
         */
        explicit conn(shared_transmission next_layer, const config &cfg = {},
                       psm::account::directory *account_dir = nullptr)
            : next_layer_(std::move(next_layer)), config_(cfg), acct_dir_(account_dir)
        {
        }

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         * @details 返回底层传输层的执行器，用于协程调度和异步操作。
         */
        [[nodiscard]] auto executor() const -> executor_type override
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
        [[nodiscard]] auto async_read_some(const std::span<std::byte> buffer, std::error_code &ec)
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
        [[nodiscard]] auto async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
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
        [[nodiscard]] auto async_associate(const request &request_info, route_callback route_callback) const
            -> net::awaitable<fault::code>;

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
        [[nodiscard]] auto handshake()
            -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 发送成功响应
         * @param info 请求信息，用于回显绑定地址和端口
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 构建并发送 SOCKS5 成功响应，包含绑定地址和端口信息。
         * 响应格式遵循 RFC 1928 规范。
         */
        [[nodiscard]] auto send_success(const request &info) const
            -> net::awaitable<fault::code>;

        /**
         * @brief 发送错误响应
         * @param code 错误码
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 构建并发送 SOCKS5 错误响应，使用固定格式的错误报文。
         * 响应中地址字段填充为零。
         */
        [[nodiscard]] auto send_error(reply_code code) const
            -> net::awaitable<fault::code>;

        /**
         * @brief 获取内层传输指针（装饰器链导航）
         * @return transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输层引用
         * @return transport::transmission& 底层传输层引用
         * @warning 调用前应确保 is_valid() 返回 true
         */
        [[nodiscard]] auto underlying() noexcept -> psm::transport::transmission &
        {
            return *next_layer_;
        }

        /**
         * @brief 获取底层传输层常量引用
         * @return const transport::transmission& 底层传输层常量引用
         * @warning 调用前应确保 is_valid() 返回 true
         */
        [[nodiscard]] auto underlying() const noexcept -> const psm::transport::transmission &
        {
            return *next_layer_;
        }

        /**
         * @brief 检查底层传输层是否有效
         * @return bool true 表示有效，false 表示已被 release() 转移
         * @details 检查 next_layer_ 指针是否有效，用于判断是否可以
         * 安全调用读写方法。
         */
        [[nodiscard]] auto is_valid() const noexcept -> bool
        {
            return next_layer_ != nullptr;
        }

        /**
         * @brief 释放底层传输层所有权
         * @return transport::shared_transmission 底层传输层指针
         * @details 释放底层传输层的所有权并返回指针。释放后 is_valid()
         * 返回 false，不应再调用读写方法。用于将底层连接转移给
         * 其他组件管理。
         */
        [[nodiscard]] auto release() -> shared_transmission
        {
            return std::move(next_layer_);
        }

        /**
         * @brief 设置流量统计状态
         * @param t 流量统计指针
         * @param p 协议类型
         */
        void set_traffic(stats::traffic::traffic_state *t, psm::connect::protocol_type p) noexcept
        {
            traffic_ = t;
            proto_ = p;
        }

    private:
        /**
         * @brief 打开并绑定 UDP 数据报端口
         * @return net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
         * 错误码与已绑定 socket
         * @details 使用当前执行器创建会话级 UDP socket，并绑定到
         * bind_port 指定的端口。若 bind_port 为 0，由系统
         * 自动分配端口。socket 绑定成功后可用于接收 UDP 数据报。
         */
        [[nodiscard]] auto bind_datagram_port() const
            -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;

        /**
         * @brief 发送 UDP_ASSOCIATE 成功响应
         * @param request_info 原始请求信息
         * @param local_endpoint 本地 UDP 端点
         * @return net::awaitable<fault::code> 异步操作，完成后返回错误码
         * @details 将本地 UDP 绑定地址写入 SOCKS5 响应的 BND.ADDR 和
         * BND.PORT 字段，供客户端后续向该地址发送 UDP 数据报。
         */
        [[nodiscard]] auto send_assoc_ok(const request &request_info, const net::ip::udp::endpoint &local_endpoint) const
            -> net::awaitable<fault::code>;

        /**
         * @brief UDP_ASSOCIATE 主循环
         * @param ingress_socket 入站 UDP socket
         * @param route_callback 路由回调函数
         * @return net::awaitable<void> 异步操作
         * @details 持续读取客户端发往 ingress 的 UDP 数据报，并逐包转发。
         * 当 socket 被取消时（控制面关闭触发），协程退出。循环内部
         * 处理 SOCKS5 UDP 报头解析、路由查询、数据转发和响应封装。
         * 出站 socket 在循环外创建，跨数据报复用，避免逐包创建开销。
         */
        auto associate_loop(net::ip::udp::socket &ingress_socket, route_callback &route_callback, net::steady_timer &idle_timer) const
            -> net::awaitable<void>;

        /**
         * @brief 转发单个 SOCKS5 UDP 数据报
         * @param ctx 中继上下文（聚合 ingress/egress socket、路由回调、目标缓冲区）
         * @param ingress_packet 入站数据包
         * @param client_endpoint 客户端端点
         * @return net::awaitable<void> 异步操作
         * @details 处理流程包括解码 SOCKS5 UDP 报头、调用路由回调解析
         * 目标端点、发送 payload 到目标并等待回包、将回包重新封装为
         * SOCKS5 UDP 数据报回写客户端。出站 socket 通过惰性打开模式
         * 复用，首次调用时自动 open，后续调用直接复用。
         */
        [[nodiscard]] auto relay_datagram(relay_context ctx,
                                   std::span<const std::byte> ingress_packet,
                                   const net::ip::udp::endpoint &client_endpoint) const
            -> net::awaitable<void>;

        /**
         * @brief 监听控制面关闭并停止 UDP 数据面
         * @param ingress_socket 入站 UDP socket
         * @return net::awaitable<void> 异步操作
         * @details 控制连接任意读结束（EOF 或错误）后，取消并关闭
         * ingress socket，驱动 UDP 主循环快速退出。这是 UDP_ASSOCIATE
         * 的标准终止机制。
         */
        auto wait_ctrl_close(net::ip::udp::socket &ingress_socket) const
            -> net::awaitable<void>;

        /**
         * @brief 将端点转换为地址结构
         * @param endpoint UDP 端点
         * @return address 地址变体
         * @details 根据 IP 地址版本自动选择 IPv4 或 IPv6 地址类型，
         * 将端点地址转换为 SOCKS5 地址格式。
         */
        [[nodiscard]] static auto ep_to_addr(const net::ip::udp::endpoint &endpoint)
            -> address
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
         * @details 读取客户端发送的方法协商请求，验证协议版本，根据
         * 配置和客户端支持的方法选择认证方式。当 enable_auth 为 true
         * 且账户目录可用时，优先选择用户名/密码认证 (0x02)；否则
         * 选择无认证 (0x00)。若启用认证但客户端不支持任何认证方法，
         * 则拒绝连接。
         */
        [[nodiscard]] auto negotiated_authentication()
            -> net::awaitable<std::pair<fault::code, auth_method>>;

        /**
         * @brief 执行 RFC 1929 用户名/密码认证子协商
         * @return net::awaitable<std::pair<fault::code, bool>> 错误码与认证结果
         * @details 读取客户端发送的用户名/密码认证请求，解析后使用
         * SHA224 对密码进行哈希，通过 account::directory 验证凭证
         * 并获取连接租约。认证失败时不暴露具体原因，仅返回失败状态。
         */
        [[nodiscard]] auto password_auth()
            -> net::awaitable<std::pair<fault::code, bool>>;

        /**
         * @brief 读取请求头部
         * @return net::awaitable<std::pair<fault::code, wire::header_parse>>
         * 包含结果错误码和解析后的头部
         * @details 读取 4 字节的请求头部（VER + CMD + RSV + ATYP），
         * 并解析为结构化的头部信息。头部包含命令类型和地址类型，
         * 用于后续的地址读取和命令处理。
         */
        [[nodiscard]] auto read_req_hdr() const
            -> net::awaitable<std::pair<fault::code, wire::header_parse>>;

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
        template <std::size_t N, typename Decoder>
        [[nodiscard]] auto read_address(const Decoder &decoder)
            -> net::awaitable<std::tuple<fault::code, address, std::uint16_t>>
        {
            std::array<std::uint8_t, N + 2> buffer{};
            std::error_code io_ec;
            co_await recv_impl(std::span(reinterpret_cast<std::byte *>(buffer.data()), N + 2), io_ec);
            if (io_ec)
            {
                co_return std::tuple<fault::code, address, std::uint16_t>{fault::code::io_error, address{}, 0};
            }

            auto [decode_ec, ip] = decoder(std::span<const std::uint8_t>(buffer.data(), N));
            if (fault::failed(decode_ec))
            {
                co_return std::tuple<fault::code, address, std::uint16_t>{decode_ec, address{}, 0};
            }

            auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + N, 2));
            if (fault::failed(ec_port))
            {
                co_return std::tuple<fault::code, address, std::uint16_t>{ec_port, address{}, 0};
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
        [[nodiscard]] auto read_domain() const
            -> net::awaitable<std::tuple<fault::code, address, std::uint16_t>>;

        /**
         * @brief 解析命令并检查是否允许
         * @param deadline 握手超时定时器
         * @param cmd SOCKS5 命令
         * @param req 请求结构体，成功时填充 transport 字段
         * @return fault::code 错误码
         * @details 验证命令是否被配置允许，不允许时发送错误响应。
         */
        [[nodiscard]] auto resolve_command(net::steady_timer &deadline, command cmd, request &req) const
            -> net::awaitable<fault::code>;

        /**
         * @brief 解析目标地址
         * @param deadline 握手超时定时器
         * @param atyp 地址类型
         * @param req 请求结构体，成功时填充地址和端口
         * @return fault::code 错误码
         * @details 根据 atyp 读取并解析目标地址，填充到 req 中。
         */
        [[nodiscard]] auto resolve_address(net::steady_timer &deadline, address_type atyp, request &req)
            -> net::awaitable<fault::code>;

        /**
         * @brief 构建 SOCKS5 成功响应
         * @param req 请求信息，用于获取地址类型和绑定地址
         * @param buffer 输出缓冲区，大小至少 262 字节
         * @return std::size_t 实际写入的字节数
         * @details 构建符合 RFC 1928 规范的成功响应报文。响应格式为
         * VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(变长) + BND.PORT(2)。
         * 根据地址类型写入不同格式的地址数据。
         */
        [[nodiscard]] static auto build_ok_resp(const request &req, std::span<std::uint8_t> buffer)
            -> std::size_t;

        /**
         * @brief 异步读取实现（内部）
         * @param buffer 要读取的字节数组
         * @param ec 错误码引用，用于存储读取错误信息
         * @return net::awaitable<std::size_t> 读取的字节数
         * @details 直接透传到底层传输层的 async_read_some 方法。
         * 注意 C++20 的 span 的 const 是针对 span 本身，不针对
         * std::byte，如果为 const std::byte 则不能写入数据。
         */
        [[nodiscard]] auto recv_impl(const std::span<std::byte> buffer, std::error_code &ec) const
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
        [[nodiscard]] auto send_impl(std::span<const std::byte> buffer, std::error_code &ec) const
            -> net::awaitable<std::size_t>;

        shared_transmission next_layer_;                    // 底层传输层指针，所有权通过 unique_ptr 管理
        config config_;                                     // SOCKS5 协议配置，构造时传入，运行时只读
        psm::account::directory *acct_dir_; // 账户目录指针，用于认证验证，不持有所有权
        psm::account::lease account_lease_;          // 账户连接租约，认证成功后持有，会话结束时释放
        stats::traffic::traffic_state *traffic_{nullptr};
        psm::connect::protocol_type proto_{psm::connect::protocol_type::unknown};
        mutable std::atomic<std::uint64_t> udp_uplink_{0};
        mutable std::atomic<std::uint64_t> udp_downlink_{0};
    };

    /**
     * @brief SOCKS5 中继器共享智能指针
     * @details 使用 shared_ptr 管理 conn 对象生命周期，支持协程
     * 上下文中的异步保活。通过 shared_from_this 实现安全回调。
     */
    using shared_conn = std::shared_ptr<conn>;

    /**
     * @brief 创建 SOCKS5 中继器对象
     * @param next_layer 底层传输层指针
     * @param cfg SOCKS5 协议配置
     * @param account_dir 账户目录指针，用于认证验证（可为空）
     * @return shared_conn 中继器对象共享指针
     * @details 工厂函数，封装 std::make_shared 调用，简化对象创建。
     */
    [[nodiscard]] inline shared_conn make_conn(shared_transmission next_layer, const config &cfg = {},
                                   psm::account::directory *account_dir = nullptr)
    {
        return std::make_shared<conn>(std::move(next_layer), cfg, account_dir);
    }

}
