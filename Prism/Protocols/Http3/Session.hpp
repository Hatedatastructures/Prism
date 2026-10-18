/**
 * @file Session.hpp
 * @brief HTTP/3 请求、数据、响应和输出确认的正式会话能力。
 * @details 调用者只接触拥有型事件、响应和 QUIC stream 标识；nghttp3 状态与回调
 *          保留在本模块 Detail。Session 固定一个内存资源，不拥有 QUIC stream 关闭权。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http3/Detail/SessionContract.hpp>
#include <Prism/Protocols/Http3/Detail/SessionLifecycle.hpp>
#include <Prism/Protocols/Http3/Detail/SessionInput.hpp>
#include <Prism/Protocols/Http3/Detail/SessionOutput.hpp>
#include <Prism/Protocols/Http3/Detail/SessionCallbacks.hpp>

namespace Prism::Http3
{
    using OutPacket = Detail::OutPacket;

    /**
     * @class Session
     * @brief 无传输绑定的 HTTP/3 请求/响应帧会话。
     * @details Feed 借用输入至调用结束，返回事件拥有解码字段和数据；PumpOutput
     *          返回拥有的 stream 数据，调用方按实际 QUIC stream 写入并逐字节确认。
     *          nghttp3 连接句柄、状态与 C callbacks 均为本 owner 私有。
     */
    class Session final
    {
    public:
        explicit Session(Prism::Memory::ResourcePointer Resource = nullptr)
            : Engine_(Resource)
        {
        }

        Session(const Session &) = delete;
        auto operator=(const Session &) -> Session & = delete;
        Session(Session &&) = delete;
        auto operator=(Session &&) -> Session & = delete;

        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool
        {
            return Engine_.Init(std::move(OpenUniStream));
        }

        [[nodiscard]] auto Feed(
            const std::int64_t StreamId,
            const std::span<const std::byte> Data,
            const bool Fin) -> Fault::Code
        {
            return Engine_.Feed(StreamId, Data, Fin);
        }

        [[nodiscard]] auto Feed(
            const std::int64_t StreamId,
            std::vector<std::byte> Data,
            const bool Fin) -> Fault::Code
        {
            return Engine_.Feed(StreamId, std::move(Data), Fin);
        }

        [[nodiscard]] auto TakeEvent() -> std::optional<ServerEvent>
        {
            return Engine_.TakeEvent();
        }

        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &Output) -> bool
        {
            return Engine_.PumpOutput(Output);
        }

        auto AddWriteOffset(const std::int64_t StreamId, const std::size_t Written) -> void
        {
            Engine_.AddWriteOffset(StreamId, Written);
        }

        [[nodiscard]] auto SubmitResponse(ResponseHead Response) -> Fault::Code
        {
            return Engine_.SubmitResponse(std::move(Response));
        }

        /** @brief 删除私有 nghttp3 状态和等待事件，不关闭 QUIC streams。 */
        auto Close() noexcept -> void
        {
            Engine_.Close();
        }

        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return Engine_.IsOpen();
        }

        /** @brief 读取原生帧引擎是否已初始化，不返回第三方连接句柄。 */
        [[nodiscard]] auto Native() const noexcept -> bool
        {
            return Engine_.IsOpen();
        }

    private:
        Detail::Session Engine_;
    };
}
