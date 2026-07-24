/**
 * @file target.hpp
 * @brief 连接目标地址信息
 * @details 封装目标主机、端口以及正向代理标志。原位于
 *          protocol/common/target.hpp，下沉到 net/ 以解除 net → proto 的
 *          循环依赖。
 */
#pragma once

#include <prism/foundation/memory/container.hpp>


namespace psm::connect
{

/**
 * @struct target
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
        : host(mr)
        , port(mr)
    {
        port.assign("80");
    }

    memory::string host;
    memory::string port;
    bool           positive{false};
};

} // namespace psm::connect
