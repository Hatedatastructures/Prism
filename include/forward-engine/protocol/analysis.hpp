/**
 * @file analysis.hpp
 * @brief 协议分析与识别
 * @details 提供协议探测、目标地址解析等静态辅助方法，是代理系统协议栈的核心组件。
 * 该模块负责解析客户端请求、识别应用层协议类型、提取目标地址信息，
 * 为路由决策提供关键输入数据。
 *
 * 核心功能：
 * 1. 协议探测：通过预读数据识别 HTTP、SOCKS5、TLS 等协议；
 * 2. 地址解析：从 HTTP 请求或字符串中提取目标主机和端口；
 * 3. 协议转换：将协议类型枚举转换为可读字符串。
 *
 * 设计原则：
 * - 无状态性：所有方法都是静态的，不维护内部状态；
 * - 高性能：使用 `std::string_view` 避免数据拷贝；
 * - 内存安全：使用项目自定义的 `memory::string` 管理内存；
 * - 错误容忍：解析失败时返回合理默认值，不抛出异常。
 *
 * 使用场景：
 * - 在 `agent::handler` 中检测客户端协议类型；
 * - 在 `agent::distributor` 中解析目标地址用于路由；
 * - 在日志和监控中输出协议类型信息。
 *
 * 协议支持：
 * - HTTP/1.1：通过请求行和 Host 头识别；
 * - SOCKS5：通过版本号和认证方法识别；
 * - TLS：通过 ClientHello 报文头识别；
 * - Trojan/Obscura：作为 TLS 子协议处理。
 *
 * @note 所有方法都是线程安全的，可并发调用。
 * @warning 协议探测基于预读数据，可能因数据不足而返回 `unknown`。
 * @see agent::handler, agent::distributor, protocol::http
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http.hpp>

namespace ngx::protocol
{
    /**
     * @brief 协议类型枚举
     * @details 标识当前连接所使用的应用层协议类型，用于协议探测和路由决策。
     * 该枚举涵盖了代理系统支持的所有主要协议类型。
     *
     * 枚举值说明：
     * - `unknown`：未知协议，无法识别或数据不足；
     * - `http`：HTTP/1.1 协议，用于 Web 代理和反向代理；
     * - `socks5`：SOCKS5 协议，用于通用 Socket 代理；
     * - `tls`：TLS 协议，包含标准 TLS 及 Trojan、Obscura 等子协议。
     *
     * 设计考虑：
     * - 使用 `enum class` 提供类型安全，避免隐式转换；
     * - 值顺序固定，可用于 switch 语句优化；
     * - 预留扩展空间，未来可添加新协议类型。
     *
     * 使用约定：
     * - 协议探测失败时返回 `unknown`；
     * - 路由决策根据协议类型选择不同的处理管道；
     * - 日志输出使用 `to_string_view()` 转换为可读字符串。
     *
     * @note TLS 协议是一个通用类别，包含多种基于 TLS 的代理协议。
     * @warning 不要依赖枚举值的具体数值，仅使用符号名称。
     */
    enum class protocol_type
    {
        unknown, ///< 未知协议，无法识别或数据不足
        http,    ///< HTTP/1.1 协议，用于 Web 代理和反向代理
        socks5,  ///< SOCKS5 协议，用于通用 Socket 代理
        tls      ///< TLS 协议，包含标准 TLS 及 Trojan、Obscura 等子协议
    }; // enum class protocol_type

    /**
     * @brief 将协议类型转换为字符串视图
     * @details 将 `protocol_type` 枚举值转换为可读的字符串表示，用于日志输出、调试和监控。
     * 该函数提供编译时已知的字符串字面量，无运行时分配开销。
     *
     * 映射关系：
     * - `protocol_type::unknown` → `"unknown"`；
     * - `protocol_type::http` → `"http"`；
     * - `protocol_type::socks5` → `"socks5"`；
     * - `protocol_type::tls` → `"tls"`；
     * - 其他值 → `"unknown"`（安全回退）。
     *
     * 设计特性：
     * - `inline`：建议编译器内联展开，消除函数调用开销；
     * - `constexpr` 潜力：未来可标记为 `constexpr`（当前使用 `switch` 限制）；
     * - 无异常：不抛出任何异常，适合所有上下文使用；
     * - 线程安全：纯函数，无状态，可并发调用。
     *
     * 性能优化：
     * - 使用 `switch` 语句实现高效跳转表；
     * - 返回编译时常量字符串字面量，无拷贝开销；
     * - 默认分支提供安全回退，防止未定义行为。
     *
     * 使用场景：
     * - 日志记录：`log::info("协议类型: {}", to_string_view(type))`；
     * - 调试输出：在调试器中查看协议类型；
     * - 监控指标：将协议类型作为标签导出。
     *
     * @param type 协议类型枚举值
     * @return `std::string_view` 协议类型的字符串表示，指向编译时常量
     * @note 返回的字符串视图指向静态存储期的字符串字面量，生命周期与程序相同。
     * @warning 不要修改返回的字符串视图内容，它是只读的。
     * @see protocol_type, analysis::detect()
     */
    inline auto to_string_view(const protocol_type type) -> std::string_view
    {
        switch (type)
        {
        case protocol_type::unknown:
            return "unknown";
        case protocol_type::http:
            return "http";
        case protocol_type::socks5:
            return "socks5";
        case protocol_type::tls:
            return "tls";
        default:
            return "unknown";
        }
    }

    /**
     * @brief 协议分析器
     * @details 提供协议探测和目标地址解析的静态方法，是代理系统协议栈的核心分析组件。
     * 该结构体包含一系列静态方法，用于解析客户端请求、提取目标地址、识别协议类型。
     *
     * 设计特性：
     * - 无状态：所有方法都是静态的，不维护任何实例状态；
     * - 线程安全：纯函数操作，可安全并发调用；
     * - 内存高效：使用 `memory::string` 和 `std::string_view` 避免不必要的拷贝；
     * - 错误容忍：解析失败时返回合理默认值，不抛出异常。
     *
     * 核心功能：
     * 1. 地址解析：从 HTTP 请求或字符串中提取目标主机和端口；
     * 2. 协议探测：通过预读数据识别应用层协议类型；
     * 3. 目标封装：将解析结果封装为 `target` 结构体，供路由系统使用。
     *
     * 使用流程：
     * 1. `agent::handler` 调用 `detect()` 识别客户端协议；
     * 2. 根据协议类型调用相应的 `resolve()` 方法提取目标地址；
     * 3. 将 `target` 结构体传递给 `agent::distributor` 进行路由决策。
     *
     * @note 包含针对 HTTP 和 Obscura 的特定解析逻辑。
     * @warning 协议探测基于有限的数据，可能因数据不足而返回 `unknown`。
     * @see protocol_type, agent::handler, agent::distributor
     */
    struct analysis
    {

        /**
         * @brief 目标地址信息
         * @details 封装了解析出的目标主机、端口以及是否需要正向代理，是路由决策的关键输入。
         * 该结构体使用项目自定义的 `memory::string` 管理内存，确保与线程局部内存池兼容。
         *
         * 成员说明：
         * - `host`：目标主机名或 IP 地址，使用 `memory::string` 存储；
         * - `port`：目标端口号，使用 `memory::string` 存储（默认为 "80"）；
         * - `positive`：是否为正向代理请求，影响路由选择逻辑。
         *
         * 路由语义：
         * - 当 `positive` 为 `true` 时，表示客户端请求使用正向代理；
         * - 当 `positive` 为 `false` 时，表示普通请求或反向代理请求；
         * - `agent::distributor` 根据此标志选择正向或反向路由。
         *
         * 内存管理：
         * - 构造函数接受 `memory::resource_pointer` 参数；
         * - 成员字符串使用相同的内存资源分配内存；
         * - 默认使用 `memory::current_resource()`（通常为线程局部池）。
         *
         * @note 端口默认值为 "80"（HTTP 默认端口）。
         * @warning `host` 和 `port` 字符串可能为空，调用者应检查有效性。
         * @see analysis::resolve(), agent::distributor
         */
        struct target
        {
            /**
             * @brief 构造目标对象
             * @details 创建目标地址信息对象，初始化主机和端口字符串。
             * 构造函数设置端口默认值为 "80"，这是 HTTP 协议的默认端口。
             *
             * @param mr 内存资源指针，用于初始化 `host` 和 `port` 字符串的内存分配器
             */
            explicit target(memory::resource_pointer mr = memory::current_resource())
                : host(mr), port(mr)
            {
                port.assign("80");
            }

            memory::string host;  ///< 目标主机名或 IP 地址
            memory::string port;  ///< 目标端口号（字符串形式）
            bool positive{false}; ///< 是否为正向代理请求
        };

        /**
         * @brief 从 HTTP 请求中解析目标地址
         * @details 解析 HTTP 请求，提取目标主机和端口信息。
         * 该方法支持 HTTP/1.1 的绝对 URI 格式和 Host 头字段。
         *
         * 解析策略：
         * 1. 检查请求行是否包含绝对 URI（如 `http://example.com/path`）；
         * 2. 如果绝对 URI 存在，从中提取主机和端口；
         * 3. 否则从 Host 头字段提取主机和端口；
         * 4. 如果 Host 头缺少端口，使用协议默认端口（HTTP 为 80，HTTPS 为 443）。
         *
         * 特殊处理：
         * - 支持 HTTP 代理请求的 `CONNECT` 方法；
         * - 处理 `Host: example.com:8080` 格式的端口指定；
         * - 自动识别是否为正向代理请求（基于请求格式）。
         *
         * 性能优化：
         * - 使用 `std::string_view` 避免数据拷贝；
         * - 仅解析必要部分，不解析整个请求；
         * - 内存分配通过 `memory::resource_pointer` 控制。
         *
         * @param req HTTP 请求对象，包含请求行和头部字段
         * @param mr 内存资源指针，用于分配结果字符串的内存，为空时使用默认资源
         * @return `target` 解析出的目标信息，包含主机、端口和正向代理标志
         * @note 如果解析失败，返回的目标对象可能包含空字符串。
         * @warning 请求对象必须包含有效的 HTTP 请求数据。
         * @see http::request, target, resolve(std::string_view)
         */
        static auto resolve(const http::request &req, memory::resource_pointer mr = nullptr)
            -> target;

        /**
         * @brief 从字符串解析目标地址
         * @details 解析 "host:port" 格式的字符串，提取主机和端口信息。
         * 该方法用于解析 SOCKS5、TLS 等协议中的目标地址字段。
         *
         * 字符串格式：
         * - 基本格式：`example.com:8080`；
         * - IPv4 地址：`192.168.1.1:80`；
         * - IPv6 地址：`[2001:db8::1]:443`（IPv6 地址必须用方括号括起）；
         * - 默认端口：如果省略端口，使用默认值 "80"。
         *
         * 解析规则：
         * 1. 查找最后一个 ':' 字符作为端口分隔符；
         * 2. 处理 IPv6 地址的方括号语法；
         * 3. 验证端口号为有效的数字（1-65535）；
         * 4. 主机名转换为小写（规范化）。
         *
         * 错误处理：
         * - 格式错误：返回空主机和默认端口；
         * - 无效端口：返回默认端口 "80"；
         * - 内存不足：抛出 `std::bad_alloc`。
         *
         * @param host_port "host:port" 格式的字符串，可能包含 IPv6 地址
         * @param mr 内存资源指针，用于分配结果字符串的内存，为空时使用默认资源
         * @return `target` 解析出的目标信息，包含主机、端口和正向代理标志（通常为 false）
         * @note 对于非 HTTP 协议，`positive` 标志通常为 `false`。
         * @warning IPv6 地址必须用方括号括起，否则解析可能失败。
         * @see target, resolve(const http::request&), parse()
         */
        static auto resolve(std::string_view host_port, memory::resource_pointer mr = nullptr)
            -> target;

        /**
         * @brief 探测协议类型
         * @details 通过预读的数据判断连接所使用的应用层协议类型。
         * 该方法采用"白名单检测法"，依次检查是否符合已知协议特征。
         *
         * 探测算法：
         * 1. HTTP 检测：检查是否以 `GET`、`POST`、`CONNECT` 等 HTTP 方法开头；
         * 2. SOCKS5 检测：检查第一个字节是否为 `0x05`（SOCKS5 版本号）；
         * 3. TLS 检测：检查是否以 `0x16`（TLS Handshake）开头，且第二个字节为 `0x03`（TLS 1.0+）；
         * 4. 默认：如果不匹配任何已知协议，返回 `unknown`。
         *
         * 检测优先级：
         * - HTTP 优先于 SOCKS5，因为 HTTP 前缀更短；
         * - TLS 检测需要更多数据（至少 5 字节）；
         * - 匹配立即返回，不继续检测其他协议。
         *
         * 数据要求：
         * - HTTP：至少需要 3 字节（如 `GET`）；
         * - SOCKS5：至少需要 1 字节（版本号）；
         * - TLS：至少需要 5 字节（记录头 + 握手类型）。
         *
         * 局限性：
         * - 基于前缀匹配，可能误判（如巧合匹配）；
         * - 需要足够的数据长度，否则返回 `unknown`；
         * - 无法区分 TLS 子协议（Trojan、Obscura 等）。
         *
         * @param peek_data 预读的数据，通常是连接的前几个字节
         * @return `protocol_type` 检测到的协议类型，可能是 `unknown`、`http`、`socks5` 或 `tls`
         * @note 采用"白名单检测法"：只要符合 HTTP 特征则认为是 HTTP，符合 SOCKS5 特征则认为是 SOCKS5，否则根据上下文判断。
         * @warning 探测结果基于有限数据，后续数据可能推翻当前判断。
         * @see protocol_type, to_string_view(), agent::handler::detect_from_transmission()
         */
        static auto detect(std::string_view peek_data)
            -> protocol_type;

    private:
        /**
         * @brief 解析主机端口字符串（内部实现）
         * @details 将 "host:port" 格式的字符串解析为独立的主机和端口组件。
         * 该方法是 `resolve(std::string_view)` 的内部实现，处理 IPv6 地址等复杂情况。
         *
         * 解析步骤：
         * 1. 处理 IPv6 地址的方括号语法；
         * 2. 查找端口分隔符 ':'（考虑 IPv6 地址中的冒号）；
         * 3. 提取主机部分（去除方括号）；
         * 4. 提取端口部分并验证有效性；
         * 5. 将结果存储到提供的字符串引用中。
         *
         * 错误处理：
         * - 如果解析失败，`host` 和 `port` 可能被清空或设置为默认值；
         * - 不抛出异常，错误通过输出参数状态表示。
         *
         * @param src 源字符串，格式为 "host:port" 或 "[ipv6]:port"
         * @param host 输出参数，存储解析出的主机名或 IP 地址
         * @param port 输出参数，存储解析出的端口号
         * @note 该方法是 `static` 和 `private` 的，仅供内部使用。
         * @warning 主机和端口字符串必须使用相同的内存资源分配器。
         * @see resolve(std::string_view)
         */
        static auto parse(std::string_view src, memory::string &host, memory::string &port)
            -> void;
    }; // struct analysis
} // namespace ngx::protocol
