/**
 * @file FrameWriteGate.hpp
 * @brief WebSocket 连接唯一帧写入门闩。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Fault/Failure.hpp>

namespace Prism::Ws::Detail
{

    namespace Net = boost::asio;

    /** @brief 持有整帧发送权；析构时归还唯一写入令牌。 */
    class FrameWritePermit final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        struct State final
        {
            explicit State(Net::any_io_executor Executor);

            std::shared_ptr<Signal> Available;
            std::atomic<bool> Closed{false};
        };

        explicit FrameWritePermit(std::shared_ptr<State> Owner) noexcept;

        friend class FrameWriteGate;

    public:
        FrameWritePermit(const FrameWritePermit &) = delete;
        auto operator=(const FrameWritePermit &) -> FrameWritePermit & = delete;

        FrameWritePermit(FrameWritePermit &&Other) noexcept;

        auto operator=(FrameWritePermit &&Other) noexcept -> FrameWritePermit &;

        ~FrameWritePermit() noexcept;

    private:
        auto Release() noexcept -> void;

        std::shared_ptr<State> Owner_;
    };

    /** @brief 以有界并发 channel 串行化完整 WebSocket 帧写入。 */
    class FrameWriteGate final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        using State = FrameWritePermit::State;

    public:
        explicit FrameWriteGate(Net::any_io_executor Executor);

        FrameWriteGate(const FrameWriteGate &) = delete;
        auto operator=(const FrameWriteGate &) -> FrameWriteGate & = delete;

        [[nodiscard]] auto Acquire()
            -> Net::awaitable<std::expected<FrameWritePermit, Prism::Fault::Failure>>;

        auto Close() noexcept -> void;

    private:
        std::shared_ptr<State> State_;
    };

} // namespace Prism::Ws::Detail
