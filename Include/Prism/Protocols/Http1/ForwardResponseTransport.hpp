/**
 * @file ForwardResponseTransport.hpp
 * @brief HTTP/1.1 源站响应定界传输的公开构造契约。
 * @details 完整消息的最后字节正常返回，下一次读取返回 clean EOF；关闭、取消和半关
 *          由定界传输委托给内层连接。
 */

#pragma once

#include <memory>

#include <Prism/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11
{
    /**
     * @struct ForwardResponseTransportOptions
     * @brief 构造响应定界传输所需的拥有数据。
     */
    struct ForwardResponseTransportOptions final
    {
        SharedTransmission Inner;
        ForwardResponseFramingOptions Framing;
    };

    /**
     * @brief 构造源站响应定界传输。
     * @param Options 内层源站连接与请求响应语义。
     * @return 定界后的传输；Inner 为空时返回空指针。
     */
    [[nodiscard]] auto MakeForwardResponseTransport(ForwardResponseTransportOptions Options)
        -> SharedTransmission;
} // namespace Prism::Http11
