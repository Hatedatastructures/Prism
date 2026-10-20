/** @file StreamTransmission.cpp @brief Mux 虚拟流传输适配器实现。 */
#include <Prism/Protocols/Mux/Stream.hpp>

#include <boost/asio/dispatch.hpp>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>

#include <stdexcept>
#include <system_error>
#include <utility>

namespace Prism::Mux
{
    StreamTransmission::StreamTransmission(std::shared_ptr<StreamHandle<>> Handle)
        : Prism::Transmission(RequireExecutor(Handle)), Handle_(std::move(Handle))
    {
        if (!Handle_)
        {
            throw std::invalid_argument("StreamTransmission requires a StreamHandle");
        }
        const auto Tasks = Handle_->Tasks();
        if (!Tasks)
        {
            throw std::invalid_argument("StreamTransmission requires a TaskRegistry");
        }
        const auto Reclaimer = Tasks->Reclaimer();
        if (!Reclaimer)
        {
            throw std::invalid_argument("StreamTransmission requires a TaskRegistry Reclaimer");
        }
        Terminations_ = std::make_shared<Prism::Lifecycle::DrainBarrier>(Reclaimer);
    }

    auto StreamTransmission::Executor() const -> Net::any_io_executor
    {
        return Handle_->Executor();
    }

    auto StreamTransmission::StartRead(
        const std::span<std::byte> Buffer,
        Completion Handler) -> void
    {
        Initiate<ReadWork>(StreamRead{
                               std::static_pointer_cast<StreamTransmission>(
                                   Transmission::shared_from_this()),
                               Buffer},
                           std::move(Handler));
    }

    auto StreamTransmission::StartWrite(
        const std::span<const std::byte> Buffer,
        Completion Handler) -> void
    {
        Initiate<WriteWork>(StreamWrite{
                                std::static_pointer_cast<StreamTransmission>(
                                    Transmission::shared_from_this()),
                                Buffer},
                            std::move(Handler));
    }

    auto StreamTransmission::OnClose() -> ControlResult
    {
        Submit(Termination::Close);
        return {};
    }

    auto StreamTransmission::Reset() -> void
    {
        Submit(Termination::Reset);
    }

    auto StreamTransmission::StartWriteShutdown(Completion Handler) -> void
    {
        Submit(Termination::Fin);
        Prism::Transmission::PostResult(
            Executor(), std::move(Handler), Prism::IoResult{0, {}});
    }

    auto StreamTransmission::DrainTerminations()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_return co_await Terminations_->Drain();
    }

    auto StreamTransmission::OnCancel() -> ControlResult
    {
        auto Handle = Handle_;
        Net::dispatch(Handle->Executor(), [Handle]() { Handle->Cancel(); });
        return {};
    }

    auto StreamTransmission::IsOpen() const -> bool
    {
        return Handle_->IsOpen();
    }

    auto StreamTransmission::Handle() const noexcept -> std::shared_ptr<StreamHandle<>>
    {
        return Handle_;
    }

    auto StreamTransmission::RequireExecutor(
        const std::shared_ptr<StreamHandle<>> &Handle) -> Net::any_io_executor
    {
        if (!Handle)
        {
            throw std::invalid_argument("StreamTransmission requires a StreamHandle");
        }
        return Handle->Executor();
    }

    auto StreamTransmission::Finish(FinishRequest Request) -> Net::awaitable<void>
    {
        struct Completion final
        {
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            ~Completion() { Barrier->Leave(); }
        } Done{Request.Barrier};

        if (Request.Action == Termination::Fin)
        {
            co_await Request.Handle->Shutdown();
        }
        else if (Request.Action == Termination::Reset)
        {
            co_await Request.Handle->Reset();
        }
        else
        {
            co_await Request.Handle->Shutdown();
            co_await Request.Handle->Close();
        }
    }

    auto StreamTransmission::ReadPartial(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Count = co_await Handle_->ReadSome(AsU8(Buffer));
        if (Count == 0)
        {
            const auto ReadCanceled = Handle_->ConsumeReadCancellation();
            if (const auto Failure = Handle_->PeerFailure())
            {
                ErrorCode = Prism::Fault::ToNative(*Failure);
            }
            else if (Handle_->IsPeerEof())
            {
                ErrorCode = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
            }
            else if (ReadCanceled)
            {
                ErrorCode = Prism::Fault::make_error_code(Prism::Fault::Code::Canceled);
            }
            else
            {
                ErrorCode = make_error_code(Error::UnexpectedEof);
            }
        }
        else
        {
            ErrorCode.clear();
        }
        co_return Count;
    }

    auto StreamTransmission::WritePartial(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto ErrorValue = co_await Handle_->WriteAll(AsU8(Buffer));
        if (ErrorValue)
        {
            ErrorCode = ErrorValue;
            co_return 0;
        }
        ErrorCode.clear();
        co_return Buffer.size();
    }

    auto StreamTransmission::Submit(const Termination Action) -> void
    {
        const auto Handle = Handle_;
        const auto Tasks = Handle->Tasks();
        if (!Tasks)
        {
            Net::dispatch(Handle->Executor(), [Handle] { Handle->CloseOnExecutor(); });
            return;
        }
        Prism::Lifecycle::TaskRequest Request;
        Request.Context = Handle->RetirementContext();
        Request.StartOnSubmit = true;
        const auto Weak = std::weak_ptr<StreamHandle<>>(Handle);
        Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
        if (Terminations_->Enter())
        {
            if (Tasks->SpawnTracked(
                    std::move(Request), Finish({Handle, Terminations_, Action})))
            {
                return;
            }
            Terminations_->Leave();
        }
        Net::dispatch(Handle->Executor(), [Handle] { Handle->CloseOnExecutor(); });
    }
}
