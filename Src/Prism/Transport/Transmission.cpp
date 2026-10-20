/** @file Transmission.cpp @brief typed传输前门的非模板生命周期与操作实现。 */
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Detail/TransmissionControl.hpp>
#include <boost/asio/post.hpp>

namespace Prism
{
    Transmission::Transmission(ExecutorType Executor)
        : Activity_(std::make_shared<Transport::Detail::IoActivity>(Executor)),
          Control_(std::make_shared<ControlOwner>(std::move(Executor), Activity_))
    {
    }

    Transmission::~Transmission() noexcept = default;

    auto Transmission::PostResult(ExecutorType QueueExecutor, Completion Handler, IoResult Result) -> void
    {
        Transport::Detail::PostResult(
            std::move(QueueExecutor), std::move(Handler), std::move(Result));
    }

    auto Transmission::Executor() const -> ExecutorType
    {
        return Activity_->Executor();
    }

    auto Transmission::get_executor() const -> ExecutorType
    {
        return Executor();
    }

    auto Transmission::Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity>
    {
        return Activity_;
    }

    auto Transmission::TransportType() const noexcept -> Type
    {
        if (const auto* Next = NextLayer())
            return Next->TransportType();
        return Type::Tcp;
    }

    auto Transmission::Close() -> ControlResult
    {
        auto Result = Control_->Submit(weak_from_this().lock(), ControlOwner::CloseFlag);
        if (Result && OwnsClose())
            Activity_->Seal();
        return Result;
    }

    auto Transmission::Cancel() -> ControlResult
    {
        return Control_->Submit(weak_from_this().lock(), ControlOwner::CancelFlag);
    }

    auto Transmission::SetTimeout(std::chrono::milliseconds Timeout) -> void
    {
        if (auto* Next = NextLayer())
            Next->SetTimeout(Timeout);
    }

    auto Transmission::IsOpen() const -> bool
    {
        if (const auto* Next = NextLayer())
            return Next->IsOpen();
        return false;
    }

    auto Transmission::NextLayer() noexcept -> Transmission*
    {
        return nullptr;
    }

    auto Transmission::NextLayer() const noexcept -> const Transmission*
    {
        return nullptr;
    }

    auto Transmission::Release() -> std::shared_ptr<Transmission>
    {
        return {};
    }

    auto Transmission::IoIdle() const noexcept -> bool
    {
        return Activity_->IsIdle();
    }

    auto Transmission::OwnsClose() const noexcept -> bool
    {
        return true;
    }

    auto Transmission::RequiresExternalCloseReceipt() const noexcept -> bool
    {
        return false;
    }

    auto Transmission::CloseReceipt() const noexcept
        -> std::shared_ptr<Contract::CarrierCloseReceipt>
    {
        return Control_;
    }

    auto Transmission::Ready(Completion Handler) -> ReadyCompletion
    {
        Transport::Detail::QueuedCompletion Queued(std::move(Handler));
        const auto Cancellation = Queued.Cancellation();
        return {Completion(std::move(Queued)), Cancellation};
    }

    auto Transmission::Invocation::get_executor() const noexcept -> executor_type
    {
        return Carrier->Activity_->Executor();
    }

    auto Transmission::Invocation::operator()() -> void
    {
        if (!!Cancellation.cancelled())
        {
            PostResult(Carrier->Activity_->Executor(), std::move(Handler_),
                {0, {Fault::Code::Canceled}});
            return;
        }
        Carrier->Execute(Input, std::move(Handler_));
    }

    auto Transmission::AwaitOperation(Initiation Value) -> Net::awaitable<IoResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        const auto Cancellation = co_await Net::this_coro::cancellation_state;
        if (!!Cancellation.cancelled())
        {
            co_await Net::post(Value.Fallback, Net::use_awaitable);
            co_return IoResult{0, {Fault::Code::Canceled}};
        }
        auto Token = Net::use_awaitable;
        co_return co_await Net::async_initiate<Net::use_awaitable_t<>, void(IoResult)>(
            std::move(Value), Token);
    }

    auto Transmission::AwaitShutdown(Initiation Value) -> Net::awaitable<ControlResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        const auto Result = co_await AwaitOperation(std::move(Value));
        if (Result.Failure.Failed())
            co_return std::unexpected(Result.Failure);
        co_return ControlResult{};
    }

    auto Transmission::BeginStep(IoRequest Input, Completion Handler) -> void
    {
        const auto Allocator = Net::get_associated_allocator(Handler);
        Net::post(Activity_->Executor(),
            Net::bind_allocator(Allocator,
                Invocation(weak_from_this().lock(), Input, Ready(std::move(Handler)))));
    }

    auto Transmission::Begin(IoRequest Input, Completion Handler) -> void
    {
        auto Self = weak_from_this().lock();
        if (!Self)
        {
            PostResult(Activity_->Executor(), std::move(Handler),
                {0, {Fault::Code::InvalidArgument}});
            return;
        }
        auto Reservation = Reserve(Input, Self);
        if (!Reservation)
        {
            PostResult(Activity_->Executor(), std::move(Handler),
                {0, Reservation.error()});
            return;
        }
        Completion Tracked(
            Transport::Detail::TrackedCompletion(std::move(*Reservation), std::move(Handler)));
        const auto Allocator = Net::get_associated_allocator(Tracked);
        Net::post(Activity_->Executor(),
            Net::bind_allocator(Allocator,
                Invocation(std::move(Self), Input, Ready(std::move(Tracked)))));
    }

    auto Transmission::Reserve(const IoRequest& Input, std::shared_ptr<Transmission> Carrier)
        -> std::expected<Transport::Detail::IoActivity::Operation, Fault::Failure>
    {
        if (std::holds_alternative<ShutdownRequest>(Input))
            return Activity_->TryAcquireControl(std::move(Carrier));
        return Activity_->TryAcquire(std::move(Carrier));
    }

    auto Transmission::Execute(IoRequest Input, Completion Handler) -> void
    {
        if (auto* Read = std::get_if<ReadRequest>(&Input))
        {
            if (!Read->Exact)
            {
                StartRead(Read->Buffer, std::move(Handler));
                return;
            }
            Net::async_initiate<Completion, void(IoResult)>(
                Net::co_composed<void(IoResult)>(ExactRead{}, Executor()), Handler,
                ReadInput{weak_from_this().lock(), Read->Buffer});
            return;
        }
        if (auto* Write = std::get_if<WriteRequest>(&Input))
        {
            if (!Write->Exact)
            {
                StartWrite(Write->Buffer, std::move(Handler));
                return;
            }
            Net::async_initiate<Completion, void(IoResult)>(
                Net::co_composed<void(IoResult)>(ExactWrite{}, Executor()), Handler,
                WriteInput{weak_from_this().lock(), Write->Buffer});
            return;
        }
        StartWriteShutdown(std::move(Handler));
    }

    auto Transmission::ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>
    {
        return AwaitOperation(
            Initiation{weak_from_this().lock(), ReadRequest{Buffer, false}, Activity_->Executor(), false});
    }

    auto Transmission::WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>
    {
        return AwaitOperation(
            Initiation{weak_from_this().lock(), WriteRequest{Buffer, false}, Activity_->Executor(), false});
    }

    auto Transmission::ReadExact(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>
    {
        return AwaitOperation(
            Initiation{weak_from_this().lock(), ReadRequest{Buffer, true}, Activity_->Executor(), false});
    }

    auto Transmission::WriteExact(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>
    {
        return AwaitOperation(
            Initiation{weak_from_this().lock(), WriteRequest{Buffer, true}, Activity_->Executor(), false});
    }

    auto Transmission::WriteShutdown() -> Net::awaitable<ControlResult>
    {
        return AwaitShutdown(
            Initiation{weak_from_this().lock(), ShutdownRequest{}, Activity_->Executor(), false});
    }
} // namespace Prism
