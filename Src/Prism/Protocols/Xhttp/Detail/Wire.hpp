/**
 * @file Wire.hpp
 * @brief XHTTP 物理字节串行写入 owner。
 * @details h2 driver、响应头和数据回调共享一个实例，所有写入按提交顺序
 *          排队，并由同一个执行器完成。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstddef>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    /**
     * @class WireWriter
     * @brief XHTTP 底层字节串行写入器
     * @details Sink 由拥有物理连接的调用方提供。写入失败保留 Failure/Native，
     *          关闭写入器并完成排队请求；Drain 等待 detached writer 退栈。
     * @note Write/Close/Drain 及失败回调必须在构造时的 executor 上调用。
     */
    class WireWriter final : public Prism::Contract::CarrierActivity,
                              public std::enable_shared_from_this<WireWriter>
    {
    private:
        using Completion = Net::experimental::channel<
            void(boost::system::error_code, Prism::Fault::Failure)>;
        using IdleChannel = Net::experimental::channel<
            void(boost::system::error_code, Prism::Fault::Failure)>;

    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using Sink = std::function<Net::awaitable<WriteResult>(std::span<const std::byte>)>;
        using FailureCallback = std::function<void(Prism::Fault::Failure)>;

        WireWriter(Net::any_io_executor Executor,
                   Sink SinkFunction,
                   FailureCallback FailureFunction = {});

        WireWriter(const WireWriter &) = delete;
        auto operator=(const WireWriter &) -> WireWriter & = delete;

        [[nodiscard]] auto Write(std::span<const std::byte> Data)
            -> Net::awaitable<WriteResult>;

        /** @brief 停止接收新写入并失败完成所有排队请求。 */
        void Close();

        auto Seal() noexcept -> void override
        {
            Close();
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        /**
         * @brief 查询串行 writer 是否已完成物理退栈。
         * @return 已封止且无活动协程、请求队列或当前写入时为真；历史写入 Failure 不改变物理事实。
         */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 等待 writer coroutine 与已接纳写入在原 executor 全部退栈。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

    private:
        struct RequestState final
        {
            RequestState(Net::any_io_executor Executor, std::span<const std::byte> Data);

            std::vector<std::byte> Data;
            Completion Done;
        };

        void Start();

        void FailQueued(Prism::Fault::Failure Failure, bool Record);

        auto RecordFailure(Prism::Fault::Failure Failure) -> void;

        auto SignalIdle() -> void;

        auto MarkRetiredIfDrained() noexcept -> void;

        auto Loop() -> Net::awaitable<void>;

        auto CompleteLoop(std::exception_ptr Exception) noexcept -> void;

        Net::any_io_executor Ex_;
        Sink Sink_;
        FailureCallback Failure_;
        std::deque<std::shared_ptr<RequestState>> Queue_;
        std::shared_ptr<IdleChannel> Idle_;
        std::atomic_bool Retired_{false};
        bool WriterRunning_{false};
        bool Closed_{false};
        bool FailureNotified_{false};
        Prism::Fault::Failure FirstFailure_{};
        std::shared_ptr<RequestState> ActiveRequest_;

        void NotifyFailure(Prism::Fault::Failure Failure) noexcept;
    };

} // namespace Prism::Xhttp::Detail
