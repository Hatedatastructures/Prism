#pragma once

#include <string_view>
#include <memory/container.hpp>
#include <http.hpp>

namespace ngx::agent
{
    namespace http = ngx::http;

    /**
     * @brief 协议类型枚举
     * @note 协议类型包括 HTTP 和 Obscura（非 HTTP 流量）。
     */
    enum class protocol_type
    {
        unknown,
        http,
        obscura // 非 HTTP 流量都归为此类
    }; // enum class protocol_type

    /**
     * @brief 通过预读的数据判断协议类型
     * @note 由于 obscura 没有提供静态检测方法，我们采用“白名单检测法”：
     * 只要看起来像 HTTP，就是 HTTP；否则认为是 Obscura/自定义协议。
     */

    struct analysis
    {

        /**
         * @brief 解析后的目标信息
         * @note 包含主机名、端口号和是否为正向代理的标志。
         */
        struct target
        {
            explicit target(memory::resource_pointer mr = memory::current_resource())
                : host(mr), port(mr)
            {
                port.assign("80");
            }

            memory::string host;
            memory::string port;
            bool forward_proxy{false};
        };

        static target resolve(const http::request &req, memory::resource_pointer mr = nullptr);
        static target resolve(std::string_view host_port, memory::resource_pointer mr = nullptr);
        static protocol_type detect(std::string_view peek_data);

    private:
        static void parse(std::string_view src, memory::string &host, memory::string &port);
    }; // class analysis
} // namespace ngx::agent
