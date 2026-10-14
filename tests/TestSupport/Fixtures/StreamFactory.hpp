/** @file StreamFactory.hpp @brief 按正式接入合同注入测试行为。 */
#pragma once
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Contract/Ingress/MuxSession.hpp>
#include <Preview/Contract/Services/Stream.hpp>
#include <Preview/Protocols/Common/ProtocolActivity.hpp>
#include <boost/asio/awaitable.hpp>
#include <atomic>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

namespace Preview::Testing
{
    class MuxSession final : public Preview::Contract::MuxSession
    {
    public:
        using RunFn = std::function<boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>(Preview::Contract::MuxRootRequest)>;
        MuxSession(Preview::SharedTransmission Transport, RunFn Function)
            : Transport_(std::move(Transport)), Function_(std::move(Function)),
              Activity_(std::make_shared<Preview::Protocols::ProtocolActivity>(Transport_->Executor())) {}
        auto Run(Preview::Contract::MuxRootRequest Request) -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            auto Reservation = Activity_->TryBegin();
            if (!Reservation) co_return std::unexpected(Reservation.error());
            const auto Result = co_await Function_(std::move(Request));
            Reservation->Complete();
            co_return Result;
        }
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
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
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        { return Activity_->Drain(); }
    private:
        Preview::SharedTransmission Transport_;
        RunFn Function_;
        std::shared_ptr<Preview::Protocols::ProtocolActivity> Activity_;
    };
    class StreamEgress final : public Preview::Contract::StreamEgress
    {
    public:
        using ConnectFn = std::function<boost::asio::awaitable<std::expected<
            Preview::SharedTransmission, Preview::Fault::Failure>>(Preview::Network::Target)>;
        explicit StreamEgress(ConnectFn Function) : Function_(std::move(Function)) {}
        auto Connect(Preview::Network::Target Target)
            -> boost::asio::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>> override
        { return Function_(std::move(Target)); }
    private:
        ConnectFn Function_;
    };
    /** @brief 仅供不运行 root 的认证测试显式注入拒绝拨号能力，生产不依赖此设施。 */
    inline auto UnavailableEgress() -> std::shared_ptr<Preview::Contract::StreamEgress>
    {
        return std::make_shared<StreamEgress>([](Preview::Network::Target)
            -> boost::asio::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        { co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::NotSupported}); });
    }
    class DatagramSession final : public Preview::Contract::DatagramSession
    {
    public:
        using RunFn = std::function<boost::asio::awaitable<
            std::expected<void, Preview::Fault::Failure>>()>;
        DatagramSession(Preview::SharedTransmission Transport, RunFn Function)
            : Transport_(std::move(Transport)), Function_(std::move(Function)),
              Activity_(std::make_shared<Preview::Protocols::ProtocolActivity>(Transport_->Executor())) {}
        auto Run()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (RunStarted_.exchange(true, std::memory_order_acq_rel))
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            auto Reservation = Activity_->TryBegin();
            if (!Reservation) co_return std::unexpected(Reservation.error());
            const auto Result = co_await Function_();
            Reservation->Complete();
            co_return Result;
        }
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
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
        Preview::SharedTransmission Transport_;
        RunFn Function_;
        std::shared_ptr<Preview::Protocols::ProtocolActivity> Activity_;
        std::atomic<bool> RunStarted_{false};
    };

    class StreamFactory final : public Preview::Contract::StreamFactory
    {
    public:
        using AcceptFn = std::function<boost::asio::awaitable<Preview::Contract::AcceptOutcome>(
            Preview::Contract::StreamAcceptInput)>;
        explicit StreamFactory(AcceptFn Function) : Function_(std::move(Function)) {}
        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> boost::asio::awaitable<Preview::Contract::AcceptOutcome> override
        {
            return Function_(std::move(Input));
        }
        auto Name() const -> std::string_view override { return "test"; }
    private:
        AcceptFn Function_;
    };
}
