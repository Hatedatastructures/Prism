/**
 * @file NativeServer.hpp
 * @brief 原生 QUIC streams 上的 HTTP/3 服务端会话能力。
 * @details 公开 typed request/data/raw-stream events 和会话生命周期；nghttp3、driver 和事件队列由 Detail owner 持有。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http3/Server.hpp>
#include <Prism/Protocols/Http3/ServerFactory.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http3
{
    namespace Net = boost::asio;

    enum class NativeServerSessionStage : std::uint8_t
    {
        RunStarted, OpenHttp3Streams, InitializeHttp3, NewStream, DataEvent,
        RequestEvent, SubmitResponse, DrainOutput, Error, RunFinished,
    };

    struct NativeServerSessionEvent final
    {
        NativeServerSessionStage Stage{NativeServerSessionStage::RunStarted};
        Prism::Fault::Code Status{Prism::Fault::Code::Success};
        std::int64_t StreamId{-1};
    };

    using NativeServerSessionObserver = std::function<void(NativeServerSessionEvent)>;

    [[nodiscard]] constexpr auto NativeServerSessionStageName(
        const NativeServerSessionStage Stage) noexcept -> std::string_view
    {
        switch (Stage)
        {
        case NativeServerSessionStage::RunStarted: return "RunStarted";
        case NativeServerSessionStage::OpenHttp3Streams: return "OpenHttp3Streams";
        case NativeServerSessionStage::InitializeHttp3: return "InitializeHttp3";
        case NativeServerSessionStage::NewStream: return "NewStream";
        case NativeServerSessionStage::DataEvent: return "DataEvent";
        case NativeServerSessionStage::RequestEvent: return "RequestEvent";
        case NativeServerSessionStage::SubmitResponse: return "SubmitResponse";
        case NativeServerSessionStage::DrainOutput: return "DrainOutput";
        case NativeServerSessionStage::Error: return "Error";
        case NativeServerSessionStage::RunFinished: return "RunFinished";
        }
        return "Unknown";
    }

    /** @brief 单个 QUIC owner 的 HTTP/3 流准入、事件处理与生命周期观察配置。 */
    struct NativeServerSessionOptions final
    {
        Net::any_io_executor Executor{};
        ServerOptions Http{};
        /** @brief 在 Executor 上创建单向控制流，返回拥有型 provider 或完整失败原因。 */
        std::function<Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                                   Prism::Fault::Failure>>()>
            OpenUnidirectional;
        /** @brief 在 Executor 上接收 peer 单向流，成功时将 provider 所有权交给 session。 */
        std::function<Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                                   Prism::Fault::Failure>>()>
            AcceptUnidirectional;
        /** @brief 在 Executor 上接收 peer 双向流；对端 FIN 只关闭该流接收方向。 */
        std::function<Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                                   Prism::Fault::Failure>>()>
            AcceptBidirectional;
        EventHandler OnEvent{};
        NativeServerSessionObserver Observer{};
        std::size_t MaxConcurrentStreams{64};
        std::shared_ptr<ServerFactory> Factory{std::make_shared<ServerFactory>()};
    };

    namespace Detail
    {
        class NativeServerSessionOwner;
    }

    /** @brief 拥有单个 HTTP/3 会话的 QUIC 流收发与类型化事件分发。 */
    class NativeServerSession final
    {
    public:
        explicit NativeServerSession(NativeServerSessionOptions Options);
        ~NativeServerSession() noexcept;
        NativeServerSession(const NativeServerSession &) = delete;
        auto operator=(const NativeServerSession &) -> NativeServerSession & = delete;
        NativeServerSession(NativeServerSession &&) = delete;
        auto operator=(NativeServerSession &&) -> NativeServerSession & = delete;

        /**
         * @brief 在 options executor 上处理 HTTP/3 控制、请求和 stream 事件。
         * @return 首个协议、原生 I/O、控制或 callback 异常原因，含 Native。
         * @note 取消/异常会请求本 session 关闭；远端单流 FIN 只结束该流读取，
         *       Close 与 Drain 负责连接及所有 stream 的最终关闭和物理退休。
         */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 请求在所属 executor 上关闭全部流与连接；成功仅表示关闭命令已接管。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;

        /** @brief 等待 Run、stream 活动和底层 QUIC 实际退栈；保留首个完整失败。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto ProtocolReady() const noexcept -> bool;

        /** @brief 仅当 engine、所有受管 stream 和后台任务都已物理释放时返回 true。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        std::shared_ptr<Detail::NativeServerSessionOwner> Owner_;
    };
}

#include <Prism/Protocols/Http3/Detail/NativeServer.hpp>

namespace Prism::Http3
{
    inline NativeServerSession::NativeServerSession(NativeServerSessionOptions Options)
        : Owner_(std::make_shared<Detail::NativeServerSessionOwner>(std::move(Options)))
    {
    }

    inline NativeServerSession::~NativeServerSession() noexcept
    {
        if (Owner_)
        {
            (void)Owner_->Close();
        }
    }

    inline auto NativeServerSession::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::Canceled});
        }
        co_return co_await Owner->Run();
    }

    inline auto NativeServerSession::Close() -> Prism::Transmission::ControlResult
    {
        if (!Owner_)
        {
            return {};
        }
        return Owner_->Close();
    }

    inline auto NativeServerSession::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        co_return co_await Owner->Drain();
    }

    inline auto NativeServerSession::ProtocolReady() const noexcept -> bool
    {
        return Owner_ && Owner_->ProtocolReady();
    }

    inline auto NativeServerSession::IsRetired() const noexcept -> bool
    {
        return !Owner_ || Owner_->IsRetired();
    }
}
