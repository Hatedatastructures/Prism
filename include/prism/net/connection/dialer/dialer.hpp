/**
 * @file dialer.hpp
 * @brief 连接拨号器
 * @details 统一拨号入口：管理 DNS 解析、反向路由表、正向代理目标配置
 *          和拨号超时。连接建立（connect）、端点竞速（race）、UDP 数据报
 *          （datagram/resolve_dgram）均为成员函数——依赖经构造注入，
 *          不再逐函数传参。所有连接返回 shared_transmission（RAII 所有权）。
 * @note 该类不是线程安全的，应在单个 strand 上下文中使用
 * @warning 反向路由表在运行期间可被修改，调用方需确保线程安全
 */
#pragma once

#include <prism/net/transport/transmission.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/net/connection/target.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>


namespace psm::connect
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using shared_transmission = transport::shared_transmission;

    /**
     * @struct dialer_options
     * @brief 拨号器构造选项
     * @details 封装拨号器构造所需的全部参数，将构造函数参数收敛到结构体。
     */
    struct dialer_options
    {
        net::io_context &ioc;                      ///< IO 上下文，用于创建执行器和定时器
        dns::config dns_cfg;              ///< DNS 解析器配置
        std::chrono::milliseconds dial_timeout{300};  ///< 拨号超时（毫秒）
        memory::resource_pointer mr = memory::current_resource(); ///< 内存资源，用于内部存储分配
    };

    /**
     * @class dialer
     * @brief 连接拨号器
     * @details 管理反向路由映射、正向代理目标配置和 DNS 解析，提供
     *          统一的连接建立接口。支持反向路由（域名 → 预配置后端）、
     *          正向路由（DNS 解析 + TCP 连接）、端点竞速和 UDP 数据报。
     */
    class dialer
    {
    public:
        /**
         * @struct string_hash
         * @brief 透明字符串哈希函数对象
         * @details 支持对 std::string_view 和 memory::string 进行
         * 哈希计算，无需进行类型转换。通过 is_transparent 类型别名
         * 启用透明查找特性。
         */
        struct string_hash
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view value) const noexcept
                -> std::size_t
            {
                return std::hash<std::string_view>{}(value);
            }

            [[nodiscard]] auto operator()(const memory::string &value) const noexcept
                -> std::size_t
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        };

        /**
         * @struct string_equal
         * @brief 透明字符串相等比较函数对象
         * @details 支持对 std::string_view 和 memory::string 进行混合比较。
         */
        struct string_equal
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view left, const std::string_view right) const noexcept
                -> bool
            {
                return left == right;
            }

            [[nodiscard]] auto operator()(const memory::string &left, const std::string_view right) const noexcept
                -> bool
            {
                return std::string_view(left) == right;
            }

            [[nodiscard]] auto operator()(const std::string_view left, const memory::string &right) const noexcept
                -> bool
            {
                return left == std::string_view(right);
            }

            [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept
                -> bool
            {
                return left == right;
            }
        };

        /**
         * @brief 透明哈希映射模板别名
         * @details 支持使用 string_view 和 memory::string 混合查找的哈希表。
         */
        template <typename Value>
        using hash_map = memory::unordered_map<memory::string, Value, string_hash, string_equal>;

        using reverse_map = hash_map<tcp::endpoint>; // 反向路由表类型

        /**
         * @brief 构造拨号器
         * @details 初始化 DNS 解析器、反向路由表。
         * @param opts 拨号器构造选项（IO 上下文、DNS 配置、拨号超时、内存资源）
         */
        explicit dialer(dialer_options opts);

        /**
         * @brief 设置正向代理的默认上游端点
         * @details 配置后，正向代理请求将转发到该端点而非直接连接目标。
         * @param host 上游服务器主机名
         * @param port 上游服务器端口
         */
        void set_endpoint(std::string_view host, std::uint16_t port);

        /**
         * @brief 添加反向代理路由规则
         * @details 将指定主机名的请求路由到给定的目标端点。
         * @param host 匹配的主机名
         * @param ep 目标 TCP 端点
         */
        void add_route(std::string_view host, const tcp::endpoint &ep);

        /**
         * @brief 建立到目标的连接
         * @details 按目标路由策略拨号：反向路由（target.positive == false）
         *          查反向路由表直连；正向路由做 IP 字面量检查，必要时
         *          DNS 解析后竞速连接。IPv6 禁用时拒绝 IPv6 字面量。
         * @param t 目标（主机 + 端口 + 路由策略）
         * @param trace 日志上下文
         * @return 结果码 + 可靠传输（失败时空）
         */
        [[nodiscard]] auto connect(const target &t, std::shared_ptr<diagnose::context> trace = nullptr)
            -> net::awaitable<std::pair<fault::code, shared_transmission>>;

        /**
         * @brief 端点竞速连接（Happy Eyeballs）
         * @details 对候选端点列表并发连接，第一个成功的连接获胜。
         * @param endpoints 候选端点列表（按优先级排序）
         * @param trace 日志上下文
         * @return 成功连接，或空（全部失败时）
         */
        [[nodiscard]] auto race(std::span<const tcp::endpoint> endpoints, std::shared_ptr<diagnose::context> trace = nullptr)
            -> net::awaitable<shared_transmission>;

        /**
         * @brief 建立 UDP 数据报套接字
         * @details 解析目标地址（字面量或 DNS）并创建 UDP 套接字。
         * @param host 目标主机名
         * @param port 目标服务端口
         * @return 结果码 + UDP 套接字
         */
        [[nodiscard]] auto datagram(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;

        /**
         * @brief 解析数据报目标端点
         * @details 仅返回解析后的端点信息，不创建套接字。
         * @param host 目标主机名
         * @param port 目标服务端口
         * @return 结果码 + UDP 端点
         */
        [[nodiscard]] auto resolve_dgram(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;

        /**
         * @brief 查询是否禁用了 IPv6
         * @return 禁用 IPv6 返回 true，否则返回 false
         */
        [[nodiscard]] auto ipv6_disabled() const noexcept
            -> bool { return dns_->ipv6_disabled(); }

        /**
         * @brief 获取拨号超时
         * @return 拨号超时（毫秒）
         */
        [[nodiscard]] auto dial_timeout() const noexcept
            -> std::chrono::milliseconds { return dial_timeout_; }

        /**
         * @brief 获取 DNS 解析器引用
         * @return DNS 解析器引用
         */
        [[nodiscard]] auto dns() noexcept
            -> dns::resolver & { return *dns_; }
        [[nodiscard]] auto dns() const noexcept
            -> const dns::resolver & { return *dns_; }

        /**
         * @brief 获取执行器
         * @return 执行器
         */
        [[nodiscard]] auto executor() const noexcept
            -> net::any_io_executor { return executor_; }

        /**
         * @brief 获取正向代理主机名
         * @return 正向代理主机名的 optional 引用
         */
        [[nodiscard]] auto positive_host() const noexcept
            -> const std::optional<memory::string> & { return positive_host_; }

        /**
         * @brief 获取正向代理端口
         * @return 正向代理端口
         */
        [[nodiscard]] auto positive_port() const noexcept
            -> std::uint16_t { return positive_port_; }

    private:
        /**
         * @brief 拨号到指定端点（RAII）
         * @details 创建 reliable 传输，用定时器竞速实现超时保护。
         * @param ep 目标端点
         * @param trace 日志上下文
         * @return 结果码 + reliable 传输（失败时空）
         */
        [[nodiscard]] auto dial_endpoint(const tcp::endpoint &ep, std::shared_ptr<diagnose::context> trace)
            -> net::awaitable<std::pair<fault::code, shared_transmission>>;

        /**
         * @brief 反向路由拨号
         * @details 通过反向路由表查找目标端点并建立连接。
         * @param host 目标主机名
         * @return 结果码 + 可靠传输
         */
        [[nodiscard]] auto async_reverse(std::string_view host)
            -> net::awaitable<std::pair<fault::code, shared_transmission>>;

        std::chrono::milliseconds dial_timeout_{300};       // 拨号超时
        memory::resource_pointer mr_;                       // 内存资源
        std::unique_ptr<dns::resolver> dns_;       // DNS 解析器
        reverse_map reverse_map_;                           // 反向路由表
        net::any_io_executor executor_;                     // 执行器（用于创建 UDP socket）
        std::optional<memory::string> positive_host_;       // 正向代理主机名
        std::uint16_t positive_port_{0};                    // 正向代理端口
    };

} // namespace psm::connect
