/**
 * @file Dgram.hpp
 * @brief TrustTunnel datagram session 的公开 request/result 类型。
 * @details 帧读写、取消与最终关闭由 Detail::Dgram 唯一拥有。
 */
#pragma once

#include <Preview/Transport/Transmission.hpp>

#include <memory>

namespace Preview::Trusttunnel
{

    /** @brief TrustTunnel datagram session 构造的按值冷路径输入。 */
    struct DgramRequest final
    {
        SharedTransmission Upstream;
    };

    namespace Detail
    {
        class Dgram;
    }

    using SharedDgram = std::shared_ptr<Detail::Dgram>;

} // namespace Preview::Trusttunnel