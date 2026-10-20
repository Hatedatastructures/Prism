/**
 * @file Session.hpp
 * @brief HTTP/3 请求、数据、响应和输出确认的正式会话能力。
 * @details Feed 借用输入至调用结束，返回事件拥有解码字段和数据；PumpOutput
 *          返回拥有的 stream 数据，调用方按实际 QUIC stream 写入并逐字节确认。
 *          HTTP/3 frame engine 由本模块唯一拥有，Session 不关闭 QUIC streams。
 */
#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Http3/Auth.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Http3
{
    struct OutPacket final
    {
        std::int64_t StreamId{0};
        Prism::Memory::Vector<std::byte> Data;
        bool Fin{false};

        explicit OutPacket(Prism::Memory::ResourcePointer Resource)
            : Data(Prism::Memory::EffectiveMr(Resource))
        {
        }
    };

    namespace Detail
    {
        class Session;
    }

    /**
     * @class Session
     * @brief 无传输绑定的 HTTP/3 请求/响应帧会话。
     * @details HTTP/3 状态和 nghttp3 callbacks 由编译单元拥有；session 固定一个内存资源。
     */
    class Session final
    {
    public:
        explicit Session(Prism::Memory::ResourcePointer Resource = nullptr);
        ~Session() noexcept;
        Session(const Session &) = delete;
        auto operator=(const Session &) -> Session & = delete;
        Session(Session &&) = delete;
        auto operator=(Session &&) -> Session & = delete;

        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool;
        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::span<const std::byte> Data,
            bool Fin) -> Fault::Code;
        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::vector<std::byte> Data,
            bool Fin) -> Fault::Code;
        [[nodiscard]] auto TakeEvent() -> std::optional<ServerEvent>;
        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &Output) -> bool;
        auto AddWriteOffset(std::int64_t StreamId, std::size_t Written) -> void;
        [[nodiscard]] auto SubmitResponse(ResponseHead Response) -> Fault::Code;
        auto Close() noexcept -> void;
        [[nodiscard]] auto IsOpen() const noexcept -> bool;
        /** @brief 查询会话是否开放，与 IsOpen 返回相同状态。 */
        [[nodiscard]] auto Native() const noexcept -> bool;

    private:
        std::unique_ptr<Detail::Session> Engine_;
    };
}
