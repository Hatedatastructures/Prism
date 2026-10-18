/** @file StreamFactory.hpp @brief 按正式接入合同注入测试行为。 */
#pragma once
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <boost/asio/awaitable.hpp>
#include <atomic>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

namespace Prism::Testing
{
    class MuxSession final : public Prism::Contract::MuxSession
    {
    public:
        using RunFn = std::function<boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>(Prism::Contract::MuxRootRequest)>;
        MuxSession(Prism::SharedTransmission Transport, RunFn Function)
            : Transport_(std::move(Transport)), Function_(std::move(Function)),
              Activity_(std::make_shared<Prism::Protocols::ProtocolActivity>(Transport_->Executor())) {}
        auto Run(Prism::Contract::MuxRootRequest Request) -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            auto Reservation = Activity_->TryBegin();
            if (!Reservation) co_return std::unexpected(Reservation.error());
            const auto Result = co_await Function_(std::move(Request));
            Reservation->Complete();
            co_return Result;
        }
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        { return Activity_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }
        auto Cancel() noexcept -> void override
        {
            Activity_->Seal();
            try
            {
                if (!Transport_->Cancel()) Activity_->Block();
            }
            catch (...)
            {
                Activity_->Block();
            }
        }
        auto Close() noexcept -> void override
        {
            Activity_->Seal();
            try
            {
                const auto Canceled = Transport_->Cancel();
                const auto Closed = Transport_->Close();
                if (!Canceled || !Closed) Activity_->Block();
            }
            catch (...)
            {
                Activity_->Block();
            }
        }
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        { return Activity_->Drain(); }
    private:
        Prism::SharedTransmission Transport_;
        RunFn Function_;
        std::shared_ptr<Prism::Protocols::ProtocolActivity> Activity_;
    };
    class StreamEgress final : public Prism::Contract::StreamEgress
    {
    public:
        using ConnectFn = std::function<boost::asio::awaitable<std::expected<
            Prism::SharedTransmission, Prism::Fault::Failure>>(Prism::Network::Target)>;
        explicit StreamEgress(ConnectFn Function) : Function_(std::move(Function)) {}
        auto Connect(Prism::Network::Target Target)
            -> boost::asio::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> override
        { return Function_(std::move(Target)); }
    private:
        ConnectFn Function_;
    };
    /** @brief 仅供不运行 root 的认证测试显式注入拒绝拨号能力，生产不依赖此设施。 */
    inline auto UnavailableEgress() -> std::shared_ptr<Prism::Contract::StreamEgress>
    {
        return std::make_shared<StreamEgress>([](Prism::Network::Target)
            -> boost::asio::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        { co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported}); });
    }
    class DatagramSession final : public Prism::Contract::DatagramSession
    {
    public:
        using RunFn = std::function<boost::asio::awaitable<
            std::expected<void, Prism::Fault::Failure>>()>;
        DatagramSession(Prism::SharedTransmission Transport, RunFn Function)
            : Transport_(std::move(Transport)), Function_(std::move(Function)),
              Activity_(std::make_shared<Prism::Protocols::ProtocolActivity>(Transport_->Executor())) {}
        auto Run()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (RunStarted_.exchange(true, std::memory_order_acq_rel))
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            auto Reservation = Activity_->TryBegin();
            if (!Reservation) co_return std::unexpected(Reservation.error());
            const auto Result = co_await Function_();
            Reservation->Complete();
            co_return Result;
        }
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        { return Activity_; }
        auto Cancel() noexcept -> void override
        {
            Activity_->Seal();
            try
            {
                if (!Transport_->Cancel()) Activity_->Block();
            }
            catch (...)
            {
                Activity_->Block();
            }
        }
        auto Close() noexcept -> void override
        {
            Activity_->Seal();
            try
            {
                const auto Canceled = Transport_->Cancel();
                const auto Closed = Transport_->Close();
                if (!Canceled || !Closed) Activity_->Block();
            }
            catch (...)
            {
                Activity_->Block();
            }
        }
    private:
        Prism::SharedTransmission Transport_;
        RunFn Function_;
        std::shared_ptr<Prism::Protocols::ProtocolActivity> Activity_;
        std::atomic<bool> RunStarted_{false};
    };

    class StreamFactory final : public Prism::Contract::StreamFactory
    {
    public:
        using AcceptFn = std::function<boost::asio::awaitable<Prism::Contract::AcceptOutcome>(
            Prism::Contract::StreamAcceptInput)>;
        explicit StreamFactory(AcceptFn Function) : Function_(std::move(Function)) {}
        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> boost::asio::awaitable<Prism::Contract::AcceptOutcome> override
        {
            return Function_(std::move(Input));
        }
        auto Name() const -> std::string_view override { return "test"; }
    private:
        AcceptFn Function_;
    };
}
