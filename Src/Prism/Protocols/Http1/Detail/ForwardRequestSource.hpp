/**
 * @file ForwardRequestSource.hpp
 * @brief 首请求 framing 使用的有界预读与上游字节源 owner。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http1/Detail/ForwardRequestFraming.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11::Detail
{
    /**
     * @brief 拥有预读与单次上游读取缓冲，按请求 framing 顺序交付字节。
     * @details 本对象持有内部缓冲；目标 span 由外层传输借用到对应 completion 返回。
     */
    class ForwardRequestSource final
    {
    public:
        /** @brief 接管唯一内层传输、已预读字节与其同次终态。 */
        ForwardRequestSource(
            SharedTransmission Inner,
            std::vector<std::byte> Preread,
            Fault::Failure PrereadFailure)
            : Inner_(std::move(Inner)), Preread_(std::move(Preread)),
              SourceFailure_(std::move(PrereadFailure))
        {
        }

        /** @brief 提供同一个内层传输供状态 owner 执行写入及控制操作。 */
        [[nodiscard]] auto Inner() const noexcept -> const SharedTransmission &
        {
            return Inner_;
        }

        /** @brief 清除关闭后不再可读的预读与上游缓冲。 */
        auto Clear() noexcept -> void
        {
            Preread_.clear();
            PrereadOffset_ = 0;
            SourceOffset_ = 0;
            SourceSize_ = 0;
            SourceFailure_ = {};
        }

        /** @brief 将仍未消费的预读和单次读取残余按顺序拷入目标缓冲。 */
        auto CopyBuffered(std::span<std::byte> Buffer) -> std::size_t;

        /** @brief 缓冲全部消费后交付同次终态；尚有字节时保持原错误供后续交付。 */
        [[nodiscard]] auto TakeTerminalFailure() noexcept -> Fault::Failure;

        /** @brief 获取一个 framing 字节，并保留关联的终态读取失败。 */
        [[nodiscard]] auto ReadRawByte(std::byte &Byte, Fault::Failure &Failure)
            -> boost::asio::awaitable<bool>;

        /** @brief 按 Content-Length 读取字节并更新剩余长度与 typed 终态。 */
        [[nodiscard]] auto ReadContentLength(
            std::span<std::byte> Buffer,
            std::uint64_t &Remaining,
            Fault::Failure &Failure) -> boost::asio::awaitable<std::size_t>;

        /** @brief 按当前 chunk 剩余长度读取负载；缓冲字节耗尽后先交付其终态再结束。 */
        [[nodiscard]] auto ReadChunkData(
            std::span<std::byte> Buffer,
            std::uint64_t &Remaining,
            Fault::Failure &Failure) -> boost::asio::awaitable<std::size_t>;

    private:
        [[nodiscard]] static auto ProtocolFailure(Error Value) -> Fault::Failure;

        [[nodiscard]] auto FillSource(Fault::Failure &Failure)
            -> boost::asio::awaitable<bool>;

        SharedTransmission Inner_;
        std::vector<std::byte> Preread_;
        std::array<std::byte, 4096> SourceBuffer_{};
        std::size_t PrereadOffset_{0};
        std::size_t SourceOffset_{0};
        std::size_t SourceSize_{0};
        Fault::Failure SourceFailure_;
    };
} // namespace Prism::Http11::Detail
