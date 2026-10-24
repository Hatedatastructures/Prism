/**
 * @file NativeClient.hpp
 * @brief 原生 QUIC 上的 HTTP/3 请求客户端能力。
 * @details 公开请求/stream 操作和完成观察；nghttp3、事件队列与后台读循环由 Detail owner 持有。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <expected>
#include <memory>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http3/Auth.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http3
{
    namespace Net = boost::asio;

    /** @brief 原生 HTTP/3 client 的固定 executor、QUIC owner 和随机源。 */
    struct NativeClientSessionOptions final
    {
        Net::any_io_executor Executor{};
        std::shared_ptr<Prism::Quic::Client> Connection{};
        Prism::Quic::RandomSource Random{};
        std::size_t MaxConcurrentStreams{64};
    };

    namespace Detail
    {
        class NativeClientSessionOwner;
    }

    /**
     * @class NativeClientSession
     * @brief 拥有 HTTP/3 请求处理、读任务与关联 QUIC 连接的异步客户端 owner。
     * @details Close 封止后续操作并请求 QUIC 关闭；Drain 等待请求、接受与读循环和 native QUIC 退栈，
     *          并释放 nghttp3 连接和回调资源。析构只请求 Close，不等价于物理 Drain；创建 owner
     *          必须在 NativeClientSession 生命周期结束前等待 Drain 成功，确保任务、QUIC 与 nghttp3 退役。
     */
    class NativeClientSession final
    {
    public:
        explicit NativeClientSession(NativeClientSessionOptions Options);
        /** @brief 请求 Close；不等待异步任务和 native 资源的物理退役。 */
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
            -> Net::awaitable<std::expected<ResponseHead, Prism::Fault::Failure>>;

        /**
         * @brief 打开并移交一个本端发起的 QUIC 双向 stream。
         * @return 成功时调用者取得唯一 stream owner；失败时返回完整 typed 原因。
         * @note I/O 使用本 session executor；取消/异常关闭本 client，最终连接关闭由
         *       Close 请求并由 Drain 等待 QUIC 与所有受管 stream 物理退休。
         */
        [[nodiscard]] auto OpenBidirectionalStream()
            -> Net::awaitable<std::expected<Prism::Quic::SharedStreamProvider,
                                            Prism::Fault::Failure>>;
        /** @brief 封止请求并请求关联 QUIC 关闭；成功只表示关闭命令已接管。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult;
        /** @brief 等待请求、读任务、QUIC 与 nghttp3 资源真实退役；最终 owner 必须等待此回执。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto HandshakeReady() const noexcept -> bool;
        [[nodiscard]] auto ProtocolReady() const noexcept -> bool;
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        std::shared_ptr<Detail::NativeClientSessionOwner> Owner_;
    };
}
