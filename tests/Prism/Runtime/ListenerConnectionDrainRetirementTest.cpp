#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;

    struct CanceledRetirementReceipt final
    {
        std::atomic<bool> AllowRetirement{true};
        std::atomic<bool> ReturnedCanceled{false};
        std::atomic<bool> UnderlyingRetired{false};
    };

    /** @brief 底层真实退休后返回取消结果，供 listener owner 核对物理回执。 */
    class RetiredCanceledActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        RetiredCanceledActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Underlying,
            std::shared_ptr<CanceledRetirementReceipt> Receipt)
            : Underlying_(std::move(Underlying)), Receipt_(std::move(Receipt))
        {
        }

        auto Seal() noexcept -> void override { Underlying_->Seal(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Underlying_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Receipt_->ReturnedCanceled.load(std::memory_order_acquire) &&
                   Receipt_->UnderlyingRetired.load(std::memory_order_acquire) &&
                   Underlying_->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            const auto Drained = co_await Underlying_->Drain();
            if (!Drained) co_return std::unexpected(Drained.error());
            Receipt_->UnderlyingRetired.store(
                Underlying_->IsRetired() &&
                    Receipt_->AllowRetirement.load(std::memory_order_acquire),
                std::memory_order_release);
            Receipt_->ReturnedCanceled.store(true, std::memory_order_release);
            co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }

    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Underlying_;
        std::shared_ptr<CanceledRetirementReceipt> Receipt_;
    };

    /** @brief listener cleanup 使用的无 I/O transport；关闭时回报已退休的取消结果。 */
    class RetiredCanceledTransmission final : public Prism::Transmission
    {
    public:
        RetiredCanceledTransmission(
            Net::any_io_executor Executor,
            std::shared_ptr<CanceledRetirementReceipt> Receipt)
            : Prism::Transmission(std::move(Executor)),
              Activity_(std::make_shared<RetiredCanceledActivity>(
                  Prism::Transmission::Activity(), std::move(Receipt)))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(
                Executor(), std::move(Handler), {0, {Prism::Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_.store(true, std::memory_order_release);
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity_;
        std::atomic<bool> Closed_{false};
    };


    TEST(ListenerConnectionDrain, AcceptsCanceledDrainAfterPhysicalRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto Receipt = std::make_shared<CanceledRetirementReceipt>();
        auto Transport = std::make_shared<RetiredCanceledTransmission>(Executor, Receipt);
        std::weak_ptr<RetiredCanceledTransmission> WeakTransport = Transport;
        auto Quota = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Quota>(
            1, Executor);
        ASSERT_TRUE(Prism::Runtime::Detail::ListenerConnectionGate::TryAcquire(Quota));
        auto Reservation = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Reservation>(
            Quota, Storage);
        auto Session = std::make_shared<Prism::Runtime::Detail::SessionAdmissionState>();
        Session->Started.store(true, std::memory_order_release);
        Session->Drained.store(true, std::memory_order_release);
        auto Drain = Prism::Runtime::Detail::ListenerConnectionDrain::Make(
            {Transport, Reservation, {}, Session});
        Transport.reset();

        Drain->Start();
        Context->Io.run();
        Storage->Collect();

        EXPECT_TRUE(Receipt->ReturnedCanceled.load(std::memory_order_acquire));
        EXPECT_TRUE(Receipt->UnderlyingRetired.load(std::memory_order_acquire));
        EXPECT_TRUE(Drain->IsRetired());
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(Quota->Drain.Active(), 0U);
        EXPECT_EQ(Storage->Pending(), 0U);

        Reservation.reset();
        Drain.reset();
        EXPECT_TRUE(WeakTransport.expired());
    }

    TEST(ListenerConnectionDrain, RetainsCanceledDrainUntilPhysicalRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto Receipt = std::make_shared<CanceledRetirementReceipt>();
        Receipt->AllowRetirement.store(false, std::memory_order_release);
        auto Transport = std::make_shared<RetiredCanceledTransmission>(Executor, Receipt);
        std::weak_ptr<RetiredCanceledTransmission> WeakTransport = Transport;
        auto Quota = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Quota>(
            1, Executor);
        ASSERT_TRUE(Prism::Runtime::Detail::ListenerConnectionGate::TryAcquire(Quota));
        auto Reservation = std::make_shared<Prism::Runtime::Detail::ListenerConnectionGate::Reservation>(
            Quota, Storage);
        auto Session = std::make_shared<Prism::Runtime::Detail::SessionAdmissionState>();
        Session->Started.store(true, std::memory_order_release);
        Session->Drained.store(true, std::memory_order_release);
        auto Drain = Prism::Runtime::Detail::ListenerConnectionDrain::Make(
            {Transport, Reservation, {}, Session});
        Transport.reset();

        Drain->Start();
        Context->Io.run();

        EXPECT_FALSE(Drain->IsRetired());
        EXPECT_FALSE(Receipt->UnderlyingRetired.load(std::memory_order_acquire));
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 1U);
        EXPECT_GT(Storage->Pending(), 0U);

        Receipt->AllowRetirement.store(true, std::memory_order_release);
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        Storage->Collect();

        EXPECT_TRUE(Receipt->ReturnedCanceled.load(std::memory_order_acquire));
        EXPECT_TRUE(Receipt->UnderlyingRetired.load(std::memory_order_acquire));
        EXPECT_TRUE(Drain->IsRetired());
        EXPECT_EQ(Quota->Active.load(std::memory_order_acquire), 0U);
        EXPECT_EQ(Storage->Pending(), 0U);

        Reservation.reset();
        Drain.reset();
        EXPECT_TRUE(Quota->Drain.IsBlocked());
        EXPECT_TRUE(WeakTransport.expired());
    }

} // namespace
