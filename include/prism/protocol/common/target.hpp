/**
 * @file target.hpp
 * @brief 目标地址信息结构体
 * @details 封装解析出的目标主机、端口以及是否使用正向代理标志，
 * 是路由决策的关键输入。该结构体使用项目自定义的 memory::string
 * 管理内存，确保与线程局部内存池兼容。
 */
#pragma once

#include <prism/memory/container.hpp>


namespace psm::protocol
{

    /**
     * @struct target
     * @brief 目标地址信息
     * @details 封装了解析出的目标主机、端口以及是否需要正向代理，
     * 是路由决策的关键输入。该结构体使用项目自定义的 memory::string
     * 管理内存，确保与线程局部内存池兼容。路由语义方面，当 positive
     * 为 true 时表示客户端请求使用正向代理，当 positive 为 false 时
     * 表示普通请求或反向代理请求。psm::resolve::router 根据
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

        /// 目标主机名或 IP 地址
        memory::string host;
        /// 目标端口号，字符串形式
        memory::string port;
        /// 是否为正向代理请求
        bool positive{false};
    };

} // namespace psm::protocol
