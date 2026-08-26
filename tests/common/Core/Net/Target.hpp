/**
 * @file Target.hpp
 * @brief 连接目标地址信息
 * @details 封装目标主机、端口以及正向代理标志。原位于
 *          Protocol/common/Target.hpp，下沉到 net/ 以解除 net → proto 的
 *          循环依赖。
 */
#pragma once

#include <common/Core/Memory/Container.hpp>

namespace Preview::Network
{

    /**
 * @struct Target
 * @brief 目标地址信息
 * @details 封装了解析出的目标主机、端口以及是否需要正向代理。
 */
    struct Target
    {
        /**
     * @brief 构造目标对象
     * @param mr 内存资源指针
     */
        explicit Target(Preview::Memory::ResourcePointer mr = Preview::Memory::CurrentResource()) : Host(mr), Port(mr)
        {
            Port.assign("80");
        }

        Preview::Memory::string Host;
        Preview::Memory::string Port;
        bool positive{false};
    };

} // namespace Preview::Network
