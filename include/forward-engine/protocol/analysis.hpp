/**
 * @file analysis.hpp
 * @brief 协议分析与识别
 * @details 提供协议探测、目标地址解析等静态辅助方法，是代理系统协议栈
 * 的核心组件。该模块负责解析客户端请求、识别应用层协议类型、提取目标
 * 地址信息，为路由决策提供关键输入数据。核心功能包括协议探测、地址解析
 * 和协议转换。协议探测通过预读数据识别 HTTP、SOCKS5、TLS 等协议。地址
 * 解析从 HTTP 请求或字符串中提取目标主机和端口。协议转换将协议类型枚举
 * 转换为可读字符串。设计原则包括无状态性、高性能、内存安全和错误容忍。
 * 所有方法都是静态的，不维护内部状态。使用 std::string_view 避免数据拷贝。
 * 使用项目自定义的 memory::string 管理内存。解析失败时返回合理默认值，
 * 不抛出异常。
 * @note 所有方法都是线程安全的，可并发调用。
 * @warning 协议探测基于预读数据，可能因数据不足而返回 unknown。
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http.hpp>

/**
 * @namespace ngx::protocol
 * @brief 协议处理模块
 * @details 该命名空间包含所有协议相关的实现，包括协议分析、帧定义、
 * HTTP、SOCKS5、Trojan 等协议的完整实现。模块设计遵循零拷贝和高性能
 * 原则，所有协议处理器都使用 PMR 内存池管理内存，确保热路径无堆分配。
 */
namespace ngx::protocol
{
    /**
     * @enum protocol_type
     * @brief 协议类型枚举
     * @details 标识当前连接所使用的应用层协议类型，用于协议探测和路由
     * 决策。该枚举涵盖了代理系统支持的所有主要协议类型。使用 enum class
     * 提供类型安全，避免隐式转换。值顺序固定，可用于 switch 语句优化。
     * 预留扩展空间，未来可添加新协议类型。协议探测失败时返回 unknown。
     * 路由决策根据协议类型选择不同的处理管道。日志输出使用 to_string_view
     * 转换为可读字符串。
     * @note TLS 协议是一个通用类别，包含多种基于 TLS 的代理协议。
     * @warning 不要依赖枚举值的具体数值，仅使用符号名称。
     */
    enum class protocol_type
    {
        unknown,
        http,
        socks5,
        tls
    };

    /**
     * @brief 将协议类型转换为字符串视图
     * @details 将 protocol_type 枚举值转换为可读的字符串表示，用于日志
     * 输出、调试和监控。该函数提供编译时已知的字符串字面量，无运行时
     * 分配开销。映射关系为 unknown 对应 "unknown"，http 对应 "http"，
     * socks5 对应 "socks5"，tls 对应 "tls"，其他值安全回退到 "unknown"。
     * 函数设计为 inline 建议编译器内联展开，消除函数调用开销。无异常，
     * 适合所有上下文使用。纯函数，无状态，可并发调用。使用 switch 语句
     * 实现高效跳转表，返回编译时常量字符串字面量，无拷贝开销。
     * @param type 协议类型枚举值
     * @return std::string_view 协议类型的字符串表示，指向编译时常量
     * @note 返回的字符串视图指向静态存储期的字符串字面量，生命周期与
     * 程序相同。
     * @warning 不要修改返回的字符串视图内容，它是只读的。
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
     * @struct analysis
     * @brief 协议分析器
     * @details 提供协议探测和目标地址解析的静态方法，是代理系统协议栈
     * 的核心分析组件。该结构体包含一系列静态方法，用于解析客户端请求、
     * 提取目标地址、识别协议类型。设计特性包括无状态、线程安全、内存
     * 高效和错误容忍。所有方法都是静态的，不维护任何实例状态。纯函数
     * 操作，可安全并发调用。使用 memory::string 和 std::string_view
     * 避免不必要的拷贝。解析失败时返回合理默认值，不抛出异常。核心功能
     * 包括地址解析、协议探测和目标封装。地址解析从 HTTP 请求或字符串中
     * 提取目标主机和端口。协议探测通过预读数据识别应用层协议类型。目标
     * 封装将解析结果封装为 target 结构体，供路由系统使用。
     * @note 包含针对 HTTP 和 Obscura 的特定解析逻辑。
     * @warning 协议探测基于有限的数据，可能因数据不足而返回 unknown。
     */
    struct analysis
    {
        /**
         * @struct target
         * @brief 目标地址信息
         * @details 封装了解析出的目标主机、端口以及是否需要正向代理，
         * 是路由决策的关键输入。该结构体使用项目自定义的 memory::string
         * 管理内存，确保与线程局部内存池兼容。路由语义方面，当 positive
         * 为 true 时表示客户端请求使用正向代理，当 positive 为 false 时
         * 表示普通请求或反向代理请求。agent::distribution::router 根据
         * 此标志选择正向或反向路由。内存管理方面，构造函数接受
         * memory::resource_pointer 参数，成员字符串使用相同的内存资源
         * 分配内存，默认使用 memory::current_resource()。
         * @note 端口默认值为 "80"，即 HTTP 默认端口。
         * @warning host 和 port 字符串可能为空，调用者应检查有效性。
         */
        struct target
        {
            /**
             * @brief 构造目标对象
             * @details 创建目标地址信息对象，初始化主机和端口字符串。
             * 构造函数设置端口默认值为 "80"，这是 HTTP 协议的默认端口。
             * @param mr 内存资源指针，用于初始化 host 和 port 字符串的
             * 内存分配器
             */
            explicit target(memory::resource_pointer mr = memory::current_resource())
                : host(mr), port(mr)
            {
                port.assign("80");
            }

            // 目标主机名或 IP 地址
            memory::string host;
            // 目标端口号，字符串形式
            memory::string port;
            // 是否为正向代理请求
            bool positive{false};
        };

        /**
         * @brief 从 HTTP 请求中解析目标地址
         * @details 解析 HTTP 请求，提取目标主机和端口信息。该方法支持
         * HTTP/1.1 的绝对 URI 格式和 Host 头字段。解析策略为首先检查
         * 请求行是否包含绝对 URI，如果存在则从中提取主机和端口，否则
         * 从 Host 头字段提取。如果 Host 头缺少端口，使用协议默认端口。
         * 支持 HTTP 代理请求的 CONNECT 方法，处理带端口的 Host 头格式，
         * 自动识别是否为正向代理请求。使用 std::string_view 避免数据
         * 拷贝，仅解析必要部分，内存分配通过 memory::resource_pointer
         * 控制。
         * @param req HTTP 请求对象，包含请求行和头部字段
         * @param mr 内存资源指针，用于分配结果字符串的内存，为空时使用
         * 默认资源
         * @return target 解析出的目标信息，包含主机、端口和正向代理标志
         * @note 如果解析失败，返回的目标对象可能包含空字符串。
         * @warning 请求对象必须包含有效的 HTTP 请求数据。
         */
        static auto resolve(const http::request &req, memory::resource_pointer mr = nullptr)
            -> target;

        /**
         * @brief 从字符串解析目标地址
         * @details 解析 "host:port" 格式的字符串，提取主机和端口信息。
         * 该方法用于解析 SOCKS5、TLS 等协议中的目标地址字段。支持基本
         * 格式如 example.com:8080，IPv4 地址如 192.168.1.1:80，IPv6
         * 地址如 [2001:db8::1]:443，省略端口时使用默认值 "80"。解析规则
         * 为查找最后一个冒号作为端口分隔符，处理 IPv6 地址的方括号语法，
         * 验证端口号有效性，主机名转换为小写。格式错误返回空主机和默认
         * 端口，无效端口返回默认端口 "80"。
         * @param host_port "host:port" 格式的字符串，可能包含 IPv6 地址
         * @param mr 内存资源指针，用于分配结果字符串的内存，为空时使用
         * 默认资源
         * @return target 解析出的目标信息，包含主机、端口和正向代理标志
         * @note 对于非 HTTP 协议，positive 标志通常为 false。
         * @warning IPv6 地址必须用方括号括起，否则解析可能失败。
         */
        static auto resolve(std::string_view host_port, memory::resource_pointer mr = nullptr)
            -> target;

        /**
         * @brief 探测协议类型
         * @details 通过预读的数据判断连接所使用的应用层协议类型。该方法
         * 采用白名单检测法，依次检查是否符合已知协议特征。探测算法首先
         * 检查是否以 GET、POST、CONNECT 等 HTTP 方法开头，然后检查第一
         * 个字节是否为 0x05 即 SOCKS5 版本号，最后检查是否以 0x16 即
         * TLS Handshake 开头且第二个字节为 0x03 即 TLS 1.0+。如果不匹配
         * 任何已知协议，返回 unknown。检测优先级为 HTTP 优先于 SOCKS5，
         * TLS 检测需要更多数据。HTTP 至少需要 3 字节，SOCKS5 至少需要
         * 1 字节，TLS 至少需要 5 字节。基于前缀匹配可能误判，需要足够的
         * 数据长度，无法区分 TLS 子协议。
         * @param peek_data 预读的数据，通常是连接的前几个字节
         * @return protocol_type 检测到的协议类型
         * @note 采用白名单检测法，符合特征即认为是该协议。
         * @warning 探测结果基于有限数据，后续数据可能推翻当前判断。
         */
        static auto detect(std::string_view peek_data)
            -> protocol_type;

    private:
        /**
         * @brief 解析主机端口字符串
         * @details 将 "host:port" 格式的字符串解析为独立的主机和端口组件。
         * 该方法是 resolve(std::string_view) 的内部实现，处理 IPv6 地址
         * 等复杂情况。解析步骤包括处理 IPv6 地址的方括号语法，查找端口
         * 分隔符，提取主机部分，提取端口部分并验证有效性，将结果存储到
         * 提供的字符串引用中。如果解析失败，host 和 port 可能被清空或
         * 设置为默认值，不抛出异常。
         * @param src 源字符串，格式为 "host:port" 或 "[ipv6]:port"
         * @param host 输出参数，存储解析出的主机名或 IP 地址
         * @param port 输出参数，存储解析出的端口号
         * @note 该方法是 static 和 private 的，仅供内部使用。
         * @warning 主机和端口字符串必须使用相同的内存资源分配器。
         */
        static auto parse(std::string_view src, memory::string &host, memory::string &port)
            -> void;
    };
}
