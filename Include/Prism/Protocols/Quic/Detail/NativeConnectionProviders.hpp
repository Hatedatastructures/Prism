/**
 * @file NativeConnectionProviders.hpp
 * @brief 原生 QUIC stream 与 datagram provider 接口。
 */
#pragma once

#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>
#include <Prism/Protocols/Quic/Detail/NativeStreamActivity.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Quic::Detail
{
    class NativeStream final : public StreamProvider, public std::enable_shared_from_this<NativeStream>
    {
    public:
        NativeStream(std::weak_ptr<NativeConnection> OwnerValue,
                     std::shared_ptr<StreamState> StateValue);

        [[nodiscard]] auto Read(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Close() -> ControlResult override;
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }
        [[nodiscard]] auto ShutdownWrite() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;
        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> Net::awaitable<ShutdownResult> override;

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            if (State_)
            {
                return State_->Id;
            }
            return -1;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (State_)
            {
                return State_->Executor;
            }
            return Net::any_io_executor{};
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return !State_ || State_->Closed;
        }

    private:
        [[nodiscard]] static auto ReadOwned(
            NativeStreamActivity::Operation Reservation,
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        [[nodiscard]] static auto WriteOwned(
            NativeStreamActivity::Operation Reservation,
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        [[nodiscard]] static auto ShutdownOwned(
            std::shared_ptr<NativeStream> Owner,
            NativeStreamActivity::Operation Reservation)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] static auto AcknowledgementOwned(
            std::shared_ptr<NativeStream> Owner,
            NativeStreamActivity::Operation Reservation)
            -> Net::awaitable<ShutdownResult>;
        /** @brief provider、状态、关闭回执与独立 executor/PMR 的析构顺序固定。 */
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::weak_ptr<NativeConnection> Owner_;
        std::shared_ptr<StreamState> State_;
        std::shared_ptr<NativeStreamActivity> Activity_;
    };

    class NativeDatagram final : public DatagramProvider,
                                public std::enable_shared_from_this<NativeDatagram>
    {
    public:
        NativeDatagram(std::weak_ptr<NativeConnection> OwnerValue,
                       std::shared_ptr<DatagramState> StateValue);

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (State_)
            {
                return State_->Executor;
            }
            return Net::any_io_executor{};
        }

        [[nodiscard]] auto Receive(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Send(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        auto Close() -> void override;
        auto Cancel() -> void override;

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return !State_ || State_->Closed;
        }

    private:
        /** @brief 外部数据报句柄先销毁 State/channel，再释放原独立 executor owner。 */
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::weak_ptr<NativeConnection> Owner_;
        std::shared_ptr<DatagramState> State_;
    };

} // namespace Prism::Quic::Detail
