/**
 * @file QuicAdapters.cpp
 * @brief QUIC stream/datagram Transmission 适配器实现。
 */
#include <Prism/Protocols/Quic/Datagram/Adapter.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <Prism/Protocols/Quic/Native/Stream/Detail/AdapterActivity.hpp>

#include <boost/asio/this_coro.hpp>

#include <new>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace Prism::Quic::Detail
{
    struct StreamAdapterActivity::State final
    {
        State(
            std::shared_ptr<Prism::Contract::CarrierActivity> ParentValue,
            std::shared_ptr<Prism::Contract::CarrierActivity> ProviderValue)
            : Parent(std::move(ParentValue)), Provider(std::move(ProviderValue))
        {
        }

        std::shared_ptr<Prism::Contract::CarrierActivity> Parent;
        std::shared_ptr<Prism::Contract::CarrierActivity> Provider;
    };

    StreamAdapterActivity::StreamAdapterActivity(
        std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
        std::shared_ptr<Prism::Contract::CarrierActivity> Provider)
        : State_(MakeState(std::move(Parent), std::move(Provider)))
    {
    }

    StreamAdapterActivity::~StreamAdapterActivity() = default;

    auto StreamAdapterActivity::Seal() noexcept -> void
    {
        State_->Parent->Seal();
    }

    [[nodiscard]] auto StreamAdapterActivity::Executor() const
        -> boost::asio::any_io_executor
    {
        return State_->Parent->Executor();
    }

    [[nodiscard]] auto StreamAdapterActivity::IsRetired() const noexcept -> bool
    {
        return State_->Parent->IsRetired() && State_->Provider->IsRetired();
    }

    [[nodiscard]] auto StreamAdapterActivity::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainState(State_);
    }

    [[nodiscard]] auto StreamAdapterActivity::MakeState(
        std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
        std::shared_ptr<Prism::Contract::CarrierActivity> Provider)
        -> std::shared_ptr<State>
    {
        if (!Parent || !Provider)
        {
            throw std::invalid_argument("QUIC stream activity requires both real owners");
        }
        return std::make_shared<State>(std::move(Parent), std::move(Provider));
    }

    [[nodiscard]] auto StreamAdapterActivity::DrainState(std::shared_ptr<State> Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        const auto Parent = co_await Owner->Parent->Drain();
        const auto Provider = co_await Owner->Provider->Drain();
        if (!Parent)
        {
            co_return std::unexpected(Parent.error());
        }
        if (!Provider)
        {
            co_return std::unexpected(Provider.error());
        }
        if (!Owner->Parent->IsRetired() || !Owner->Provider->IsRetired())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}

namespace Prism::Quic
{
    [[nodiscard]] auto StreamAdapter::ResolveExecutor(
        const Net::any_io_executor &Executor,
        const SharedStreamProvider &Provider) -> Net::any_io_executor
    {
        if (Provider)
        {
            const auto ProviderExecutor = Provider->Executor();
            if (ProviderExecutor) return ProviderExecutor;
        }
        if (Executor) return Executor;
        throw std::invalid_argument("StreamAdapter requires an executor");
    }

    StreamAdapter::StreamAdapter(
        Net::any_io_executor Executor,
        SharedStreamProvider Provider,
        std::optional<Prism::Fault::Failure> InitialReadTerminal)
        : Prism::Transmission(ResolveExecutor(Executor, Provider)),
          Ex_(ResolveExecutor(Executor, Provider)),
          Provider_(std::move(Provider)),
          Activity_(MakeActivity(Prism::Transmission::Activity(), Provider_)),
          InitialReadTerminal_(std::move(InitialReadTerminal))
    {
    }

    [[nodiscard]] auto StreamAdapter::MakeActivity(
        std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
        const SharedStreamProvider& Provider)
        -> std::shared_ptr<Detail::StreamAdapterActivity>
    {
        if (!Provider)
        {
            throw std::invalid_argument("QUIC stream adapter requires a provider");
        }
        const auto ProviderActivity = Provider->Activity();
        if (!ProviderActivity)
        {
            throw std::invalid_argument("QUIC stream provider requires an activity owner");
        }
        return std::make_shared<Detail::StreamAdapterActivity>(
            std::move(Parent), ProviderActivity);
    }

    [[nodiscard]] auto StreamAdapter::ReadPartial(std::span<std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        if (InitialReadTerminal_)
        {
            if (Buffer.empty()) co_return Prism::IoResult{0, {}};
            co_return Prism::IoResult{0, *InitialReadTerminal_};
        }
        if (!Provider_)
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(std::make_error_code(std::errc::bad_file_descriptor))};
        }
        std::error_code ErrorCode;
        const auto Read = co_await Provider_->Read(Buffer, ErrorCode);
        if (Read > Buffer.size())
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(make_error_code(Error::BadLength))};
        }
        if (ErrorCode)
        {
            co_return Prism::IoResult{Read, Prism::Fault::FromNative(ErrorCode)};
        }
        co_return Prism::IoResult{Read, {}};
    }

    [[nodiscard]] auto StreamAdapter::WritePartial(std::span<const std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        if (!Provider_)
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(std::make_error_code(std::errc::bad_file_descriptor))};
        }
        std::error_code ErrorCode;
        const auto Written = co_await Provider_->Write(Buffer, ErrorCode);
        if (Written > Buffer.size())
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(make_error_code(Error::BadLength))};
        }
        if (ErrorCode)
        {
            co_return Prism::IoResult{Written, Prism::Fault::FromNative(ErrorCode)};
        }
        co_return Prism::IoResult{Written, {}};
    }

    [[nodiscard]] auto StreamAdapter::CompleteWriteShutdown(
        std::shared_ptr<StreamAdapter> Owner,
        Completion Handler) -> Net::awaitable<void>
    {
        Prism::IoResult Result;
        if (!Owner->Provider_)
        {
            Result.Failure = Prism::Fault::FromNative(
                std::make_error_code(std::errc::bad_file_descriptor));
        }
        else
        {
            try
            {
                const auto Shutdown = co_await Owner->Provider_->ShutdownWrite();
                if (!Shutdown)
                {
                    Result.Failure = Shutdown.error();
                }
            }
            catch (const std::system_error &Error)
            {
                Result.Failure = Prism::Fault::FromNative(Error.code());
            }
            catch (const std::bad_alloc &)
            {
                Result.Failure = {Prism::Fault::Code::ResourceUnavailable};
            }
            catch (...)
            {
                Result.Failure = {Prism::Fault::Code::IoError};
            }
        }
        Prism::Transmission::PostResult(
            Owner->Executor(), std::move(Handler), std::move(Result));
    }

    [[nodiscard]] auto DatagramAdapter::RequireProviderExecutor(
        const SharedDatagramProvider &Provider) -> Net::any_io_executor
    {
        if (!Provider || !Provider->Executor())
            throw std::invalid_argument("DatagramAdapter requires a provider executor");
        return Provider->Executor();
    }

    [[nodiscard]] auto DatagramAdapter::ReadPartial(std::span<std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        if (!Provider_)
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(std::make_error_code(std::errc::bad_file_descriptor))};
        }
        std::error_code ErrorCode;
        const auto Received = co_await Provider_->Receive(Buffer, ErrorCode);
        if (Received > Buffer.size())
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(make_error_code(Error::BadLength))};
        }
        if (ErrorCode)
        {
            co_return Prism::IoResult{Received, Prism::Fault::FromNative(ErrorCode)};
        }
        co_return Prism::IoResult{Received, {}};
    }

    [[nodiscard]] auto DatagramAdapter::WritePartial(std::span<const std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        if (!Provider_)
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(std::make_error_code(std::errc::bad_file_descriptor))};
        }
        std::error_code ErrorCode;
        const auto Written = co_await Provider_->Send(Buffer, ErrorCode);
        if (Written > Buffer.size())
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(make_error_code(Error::BadLength))};
        }
        if (ErrorCode)
        {
            co_return Prism::IoResult{Written, Prism::Fault::FromNative(ErrorCode)};
        }
        if (Written != Buffer.size())
        {
            co_return Prism::IoResult{
                Written, Prism::Fault::FromNative(make_error_code(Error::IoError))};
        }
        co_return Prism::IoResult{Written, {}};
    }
}
