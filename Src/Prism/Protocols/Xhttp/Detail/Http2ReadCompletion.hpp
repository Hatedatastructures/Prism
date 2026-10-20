/**
 * @file Http2ReadCompletion.hpp
 * @brief XHTTP HTTP/2 已完成读取的字节消费边界。
 * @details 先验证并喂入同次读取交付的字节，再返回原终态；Feed 错误优先于读取终态。
 */

#pragma once

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Types.hpp>

#include <cstddef>
#include <span>

namespace Prism::Xhttp::Detail
{

    struct Http2ReadStep final
    {
        Prism::Fault::Failure Failure{};
        bool ReadTerminal{false};
    };

    /**
     * @brief 对端 EOF 携带的 DATA 先排空，再交付后续 HTTP/2 输出写失败。
     * @details 仅成功消费输入后的 EOF 保留接收队列；解析错误与其它写失败仍立即终止。
     */
    template <typename Transport>
    auto NotifyHttp2OutputFailure(
        Transport &Owner,
        const Http2ReadStep &Read,
        const Prism::Fault::Failure Failure) -> void
    {
        if (Read.ReadTerminal && Read.Failure.Code == Prism::Fault::Code::Eof)
        {
            Owner.NotifyReadTerminal(Failure);
            return;
        }
        Owner.NotifyError(Prism::Fault::ToNative(Failure));
    }

    /**
     * @brief 消费 HTTP/2 读取完成中的已交付字节并返回终态。
     * @param Session 持有 HTTP/2 解析状态的会话。
     * @param Buffer 与读取结果对应的缓冲区。
     * @param Read 同次读取的已交付字节数和终态。
     * @return 越界或 Feed 错误优先返回；成功消费后保留原读取终态及其来源。
     * @details 调用者仍拥有 buffer 和 Session，并负责 EOF、取消、错误通知及底层关闭。
     */
    [[nodiscard]] auto ProcessHttp2ReadCompletion(
        Prism::Http2::H2Session &Session,
        std::span<const std::byte> Buffer,
        const Prism::IoResult &Read) -> Http2ReadStep;

} // namespace Prism::Xhttp::Detail
