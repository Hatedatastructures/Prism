/**
 * @file analysis.hpp
 * @brief 协议分析与识别
 * @details 提供协议探测、目标地址解析等静态辅助方法。
 */
#pragma once

#include <string_view>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/http.hpp>

namespace ngx::protocol
{
    /**
     * @brief 协议类型枚举
     * @details 标识当前连接所使用的应用层协议类型。
     */
    enum class protocol_type
    {
        unknown, // 未知协议
        http,    // HTTP 协议
        socks5,  // SOCKS5 协议
        tls      // TLS 协议 (包含 Trojan 和 Obscura)
    }; // enum class protocol_type

    /**
     * @brief 协议分析器
     * @details 提供协议探测和目标地址解析的静态方法。
     * @note 包含针对 HTTP 和 Obscura 的特定解析逻辑。
     */
    struct analysis
    {

        /**
         * @brief 目标地址信息
         * @details 封装了解析出的目标主机、端口以及是否需要正向代理。
         */
        struct target
        {
            /**
             * @brief 构造目标对象
             * @param mr 内存资源指针
             */
            explicit target(memory::resource_pointer mr = memory::current_resource())
                : host(mr), port(mr)
            {
                port.assign("80");
            }

            memory::string host; // 目标主机名或 IP
            memory::string port; // 目标端口号
            bool forward_proxy{false}; // 是否为正向代理请求
        };

        /**
         * @brief 从 HTTP 请求中解析目标地址
         * @param req HTTP 请求对象
         * @param mr 内存资源指针
         * @return target 解析出的目标信息
         */
        static auto resolve(const http::request &req, memory::resource_pointer mr = nullptr)
            -> target;

        /**
         * @brief 从字符串解析目标地址
         * @param host_port "host:port" 格式的字符串
         * @param mr 内存资源指针
         * @return target 解析出的目标信息
         */
        static auto resolve(std::string_view host_port, memory::resource_pointer mr = nullptr)
            -> target;

        /**
         * @brief 探测协议类型
         * @details 通过预读的数据判断协议类型。
         * @note 采用“白名单检测法”：只要符合 HTTP 特征则认为是 HTTP，符合 SOCKS5 特征则认为是 SOCKS5，否则根据上下文判断。
         * @param peek_data 预读的数据
         * @return protocol_type 检测到的协议类型
         */
        static auto detect(std::string_view peek_data)
            -> protocol_type;

    private:
        static auto parse(std::string_view src, memory::string &host, memory::string &port)
            -> void;
    }; // class analysis
} // namespace ngx::protocol
