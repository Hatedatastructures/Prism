/**
 * @file State.hpp
 * @brief HTTP/1.1 首请求 framing、Upgrade 门控与半关闭状态 owner。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http1/Forward/Request/Detail/Framing.hpp>
#include <Prism/Protocols/Http1/Forward/Request/Transport.hpp>
#include <Prism/Protocols/Http1/Forward/Request/Detail/Source.hpp>
#include <Prism/Protocols/Http1/Forward/Request/Detail/Upgrade.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11::Detail
{
    using IoFailure = Prism::Fault::Failure;

    /**
     * @brief 独占保存首请求 body framing、Upgrade gate 与终态失败的状态 owner。
     * @details 外层 Transmission 持有本对象直到活动读写 completion 返回；本对象只借用输入 span。
     */
    class ForwardRequestState final
    {
    public:
        explicit ForwardRequestState(ForwardRequestOptions Options);

        /** @brief 返回内层传输的真实执行器。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Source_.Inner()->Executor();
        }

        /** @brief 返回共享持有的内层传输导航视图。 */
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission *
        {
            return Source_.Inner().get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission *
        {
            return Source_.Inner().get();
        }

        /** @brief 真实写半关闭：先提交 Upgrade 半关闭事实，再转交底层载体。 */
        auto StartWriteShutdown(Prism::Transmission::Completion Handler) -> void;

        /** @brief 清除本地转发状态并交付底层关闭。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;

        /** @brief 记录取消事实并取消底层挂起操作；不宣称已经关闭。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult;

        /** @brief 数据面部分读取实现，由正式前门复用。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>;

        /** @brief 数据面部分写入实现，由正式前门复用。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>;

        /** @brief 查询底层连接及本地 close 状态。 */
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return Source_.Inner() && Source_.Inner()->IsOpen() && !Closed_;
        }

    private:
        [[nodiscard]] static auto ProtocolFailure(const Prism::Error Value) -> IoFailure;

        auto CopyHeader(std::span<std::byte> Buffer) -> std::size_t;

        auto Fail(IoFailure Failure, IoFailure &Output) -> void;

        [[nodiscard]] auto ReadLine(IoFailure &Failure) -> Net::awaitable<bool>;

        auto QueueLine() -> void;

        [[nodiscard]] auto ReadChunked(std::span<std::byte> Buffer,
                                       IoFailure &Failure)
            -> Net::awaitable<std::size_t>;

        /** @brief 先交付已有隧道字节；部分读不为填满缓冲额外等待上游或后续 EOF。 */
        [[nodiscard]] auto ReadTunnel(std::span<std::byte> Buffer,
                                      IoFailure &Failure,
                                      std::size_t Prefix) -> Net::awaitable<std::size_t>;

        [[nodiscard]] auto ReadAfterBody(std::span<std::byte> Buffer,
                                         IoFailure &Failure)
            -> Net::awaitable<std::size_t>;

        ForwardRequestSource Source_;
        std::vector<std::byte> Header_;
        std::vector<std::byte> Output_;
        std::vector<std::byte> Line_;
        std::size_t HeaderOffset_{0};
        std::size_t OutputOffset_{0};
        std::uint64_t Remaining_{0};
        std::uint64_t ChunkRemaining_{0};
        ForwardBodyMode BodyMode_{ForwardBodyMode::None};
        ChunkState ChunkState_{ChunkState::SizeLine};
        IoFailure Failure_;
        bool SourceEof_{false}; ///< chunked 正文末尾已消费 EOF，读隧道不得再次访问内层。
        bool AwaitUpgrade_{false};
        bool Closed_{false};
        UpgradeGate Upgrade_;
    };
} // namespace Prism::Http11::Detail
