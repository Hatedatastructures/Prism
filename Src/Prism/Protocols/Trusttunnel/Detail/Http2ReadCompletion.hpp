/**
 * @file Http2ReadCompletion.hpp
 * @brief TrustTunnel HTTP/2 driver 的单次读取完成处理。
 */
#pragma once

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;

    /** @brief 同一次读取的借用缓冲窗口与 typed completion。 */
    struct Http2ReadCompletion final
    {
        std::span<const std::byte> Buffer;
        Prism::IoResult Result{};
    };

    /** @brief 一次 HTTP/2 输入步骤的继续/终态与首个失败。 */
    struct Http2ReadStep final
    {
        bool Terminal{false};
        Prism::Fault::Failure Failure{};
        bool ReadTerminal{false};
    };

    /**
     * @brief 先消费同次读取的 HTTP/2 字节，再返回关联终态。
     * @details 缓冲仅借用到协程完成；不关闭 session、wire 或传输。原生读错误优先于
     *          同次解析/写出错误；成功消费输入后的底层终态可延后交给接收队列。
     */
    [[nodiscard]] auto ProcessHttp2ReadCompletion(
        const Http2ReadCompletion &Completion,
        const std::shared_ptr<H2::Session> &Session,
        const std::shared_ptr<Http2WireWriter> &Wire)
        -> Net::awaitable<Http2ReadStep>;
}
