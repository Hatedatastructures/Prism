/**
 * @file NativeClient.hpp
 * @brief 原生 QUIC 上的 HTTP/3 请求客户端能力。
 * @details 公开请求/stream 操作和完成观察；nghttp3、事件队列与后台读循环由 Detail owner 持有。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>
#include <memory>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Http3/Auth.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Http3
{
    namespace Net = boost::asio;

    /** @brief 原生 HTTP/3 client 的固定 executor、QUIC owner 和随机源。 */
    struct NativeClientSessionOptions final
    {
        Net::any_io_executor Executor{};
        std::shared_ptr<Preview::Quic::Client> Connection{};
        Preview::Quic::RandomSource Random{};
        std::size_t MaxConcurrentStreams{64};
    };

    namespace Detail
    {
        class NativeClientSessionOwner;
    }

    /**
     * @class NativeClientSession
     * @brief 拥有 HTTP/3 请求处理、读任务与关联 QUIC 连接的异步客户端 owner。
     * @details Close 封止后续操作并请求 QUIC 关闭；Drain 等待请求、接受与读循环和 native QUIC 退栈。
     */
    class NativeClientSession final
    {
    public:
        explicit NativeClientSession(NativeClientSessionOptions Options);
        ~NativeClientSession() noexcept;
        NativeClientSession(const NativeClientSession &) = delete;
        auto operator=(const NativeClientSession &) -> NativeClientSession & = delete;
        NativeClientSession(NativeClientSession &&) = delete;
        auto operator=(NativeClientSession &&) -> NativeClientSession & = delete;

        /**
         * @brief 提交一个 HTTP/3 请求并返回响应头。
         * @param Request 按值接收的请求头和 FIN 语义；协程取得其所有权。
         * @return 响应头，或保留 Native 的首个协议/传输失败。
         * @note I/O 固定运行在 Options.Executor；取消或异常关闭本 client，
         *       ResponseFin 标明响应是否随头部结束。
         */
        [[nodiscard]] auto SendRequest(RequestHead Request)
            -> Net::awaitable<std::expected<ResponseHead, Preview::Fault::Failure>>;

        /**
         * @brief 打开并移交一个本端发起的 QUIC 双向 stream。
         * @return 成功时调用者取得唯一 stream owner；失败时返回完整 typed 原因。
         * @note I/O 使用本 session executor；取消/异常关闭本 client，最终连接关闭由
         *       Close 请求并由 Drain 等待 QUIC 与所有受管 stream 物理退休。
         */
        [[nodiscard]] auto OpenBidirectionalStream()
            -> Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,
                                            Preview::Fault::Failure>>;
        [[nodiscard]] auto Close() -> Preview::Transmission::ControlResult;
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>;
        [[nodiscard]] auto HandshakeReady() const noexcept -> bool;
        [[nodiscard]] auto ProtocolReady() const noexcept -> bool;
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        std::shared_ptr<Detail::NativeClientSessionOwner> Owner_;
    };
}

#include <Preview/Protocols/Http3/Detail/NativeClient.hpp>

namespace Preview::Http3
{
    inline NativeClientSession::NativeClientSession(NativeClientSessionOptions Options)
        : Owner_(std::make_shared<Detail::NativeClientSessionOwner>(std::move(Options)))
    {
    }

    inline NativeClientSession::~NativeClientSession() noexcept
    {
        if (Owner_)
        {
            (void)Owner_->Close();
        }
    }

    inline auto NativeClientSession::SendRequest(RequestHead Request)
        -> Net::awaitable<std::expected<ResponseHead, Preview::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::InvalidArgument});
        }
        co_return co_await Owner->SendRequest(std::move(Request));
    }

    inline auto NativeClientSession::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,
                                        Preview::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::InvalidArgument});
        }
        co_return co_await Owner->OpenBidirectionalStream();
    }

    inline auto NativeClientSession::Close() -> Preview::Transmission::ControlResult
    {
        if (!Owner_)
        {
            return {};
        }
        return Owner_->Close();
    }

    inline auto NativeClientSession::Drain()
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        const auto Owner = Owner_;
        if (!Owner)
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        co_return co_await Owner->Drain();
    }

    inline auto NativeClientSession::HandshakeReady() const noexcept -> bool
    {
        return Owner_ && Owner_->HandshakeReady();
    }

    inline auto NativeClientSession::ProtocolReady() const noexcept -> bool
    {
        return Owner_ && Owner_->ProtocolReady();
    }

    inline auto NativeClientSession::IsRetired() const noexcept -> bool
    {
        return !Owner_ || Owner_->IsRetired();
    }
}
