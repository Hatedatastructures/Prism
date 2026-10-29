/**
 * @file Transport.hpp
 * @brief HTTP/1.1 首请求边界传输的公开构造契约。
 * @details framing、Upgrade 与半关闭状态由传输 owner 保管；借用缓冲区仅在
 *          对应 completion 返回前有效。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11
{
    /**
     * @enum ForwardBodyMode
     * @brief 首个 HTTP/1.1 请求的消息体边界。
     */
    enum class ForwardBodyMode : std::uint8_t
    {
        None,
        ContentLength,
        Chunked,
    };

    /**
     * @struct ForwardRequestOptions
     * @brief 构造首请求边界传输所需的拥有数据。
     * @details Header、Preread 与其同次读取终态均转移所有权；调用方必须先复制消息定界值。
     *          AwaitUpgrade 为 true 时，首请求完成后只在上游完整响应 101 后进入隧道。
     *          PrereadFailure 在预读字节耗尽后交付；剩余请求 body 不足时沿用 body-end 错误映射。
     */
    struct ForwardRequestOptions final
    {
        SharedTransmission Inner;
        std::string Header;
        std::vector<std::byte> Preread;
        Fault::Failure PrereadFailure;
        ForwardBodyMode BodyMode{ForwardBodyMode::None};
        std::uint64_t ContentLength{0};
        bool AwaitUpgrade{false};
    };

    /**
     * @brief 构造有界首请求转发传输。
     * @param Options 首请求头、预读数据与 framing 所有权。
     * @return 新传输；读到首请求边界返回 clean EOF，错误通过传输错误码返回。
     * @note 写方向始终委托内层，以便 clean EOF 后继续传递下游响应；Close/Cancel
     *       负责内层最终关闭/取消，Executor 与内层一致。
     */
    [[nodiscard]] auto MakeForwardRequestTransport(ForwardRequestOptions Options)
        -> SharedTransmission;
} // namespace Prism::Http11
