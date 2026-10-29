/**
 * @file PerfTransport.cpp
 * @brief TransferPerf 模块所有者。
 */

#include "TransferPerf.hpp"
#include <Prism/Transport/Transmission.hpp>

namespace TransferPerf
{
    [[nodiscard]] auto ModeName(const IoMode Mode) -> const char *
    {
        switch (Mode)
        {
        case IoMode::Direct: return "direct-handler";
        case IoMode::AwaitableBridge: return "awaitable-bridge";
        case IoMode::ScatterGather: return "connector-scatter";
        }
        return "unknown";
    }

    class AwaitableBridge final : public Prism::Transmission
    {
    public:
        explicit AwaitableBridge(std::shared_ptr<Prism::Transport::Reliable> Inner)
            : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Executor()), Handler,
                ReadInput{std::static_pointer_cast<AwaitableBridge>(Prism::Transmission::shared_from_this()), Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Executor()), Handler,
                WriteInput{std::static_pointer_cast<AwaitableBridge>(Prism::Transmission::shared_from_this()), Buffer});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            (void)Inner_->Close();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            (void)Inner_->Cancel();
            return {};
        }
        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_->IsOpen(); }
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Inner_.get();
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<AwaitableBridge> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<AwaitableBridge> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->ReadPartial(Input.Buffer, Error);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->WritePartial(Input.Buffer, Error);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            const auto Read = co_await Inner_->ReadSome(Buffer);
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            co_return Read.Bytes;
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            const auto Write = co_await Inner_->WriteSome(Buffer);
            ErrorCode = Prism::Fault::ToNative(Write.Failure);
            co_return Write.Bytes;
        }
        std::shared_ptr<Prism::Transport::Reliable> Inner_;
    };

    [[nodiscard]] auto MakeEndpoint(
        const IoMode Mode,
        std::shared_ptr<Prism::Transport::Reliable> Reliable) -> IoEndpoint
    {
        IoEndpoint Result;
        Result.Reliable = std::move(Reliable);
        if (Mode == IoMode::AwaitableBridge)
        {
            Result.Bridge = std::make_shared<AwaitableBridge>(Result.Reliable);
        }
        else if (Mode == IoMode::ScatterGather)
        {
            Result.Scatter = std::make_unique<Prism::Transport::Connector>(Result.Reliable);
        }
        return Result;
    }

    [[nodiscard]] auto AwaitBridgeWrite(
        const std::shared_ptr<AwaitableBridge> &Bridge,
        std::span<const std::byte> Buffer)
        -> Net::awaitable<std::pair<boost::system::error_code, std::size_t>>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Completion = std::make_shared<IoCompletion>(Executor, 1);
        static_cast<Prism::Transmission &>(*Bridge).WriteSome(
            Buffer,
            [Completion](Prism::IoResult Result)
            { (void)Completion->try_send(Prism::Transport::Detail::ToAsioFailure(Result.Failure), Result.Bytes); });
        boost::system::error_code CompletionError;
        const auto Count = co_await Completion->async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        co_return std::pair{CompletionError, Count};
    }

    [[nodiscard]] auto AwaitBridgeRead(
        const std::shared_ptr<AwaitableBridge> &Bridge,
        std::span<std::byte> Buffer)
        -> Net::awaitable<std::pair<boost::system::error_code, std::size_t>>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Completion = std::make_shared<IoCompletion>(Executor, 1);
        static_cast<Prism::Transmission &>(*Bridge).ReadSome(
            Buffer,
            [Completion](Prism::IoResult Result)
            { (void)Completion->try_send(Prism::Transport::Detail::ToAsioFailure(Result.Failure), Result.Bytes); });
        boost::system::error_code CompletionError;
        const auto Count = co_await Completion->async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        co_return std::pair{CompletionError, Count};
    }

    [[nodiscard]] auto AwaitDirectWrite(
        const std::shared_ptr<Prism::Transport::Reliable> &Reliable,
        std::span<const std::byte> Buffer) -> Net::awaitable<std::pair<boost::system::error_code, std::size_t>>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Completion = std::make_shared<IoCompletion>(Executor, 1);
        Reliable->WriteSome(Buffer,
            [Completion](Prism::IoResult Result)
            { (void)Completion->try_send(Prism::Transport::Detail::ToAsioFailure(Result.Failure), Result.Bytes); });
        boost::system::error_code CompletionError;
        const auto Count = co_await Completion->async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        co_return std::pair{CompletionError, Count};
    }

    [[nodiscard]] auto AwaitDirectRead(
        const std::shared_ptr<Prism::Transport::Reliable> &Reliable,
        std::span<std::byte> Buffer) -> Net::awaitable<std::pair<boost::system::error_code, std::size_t>>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Completion = std::make_shared<IoCompletion>(Executor, 1);
        Reliable->ReadSome(Buffer,
            [Completion](Prism::IoResult Result)
            { (void)Completion->try_send(Prism::Transport::Detail::ToAsioFailure(Result.Failure), Result.Bytes); });
        boost::system::error_code CompletionError;
        const auto Count = co_await Completion->async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        co_return std::pair{CompletionError, Count};
    }

    [[nodiscard]] auto ToTransferError(
        const boost::system::error_code ErrorCode,
        ErrorProjection *Diagnostic = nullptr) -> std::error_code
    {
        if (!ErrorCode)
        {
            return {};
        }
        const auto FaultCode = Prism::Fault::ToCode(ErrorCode);
        if (Diagnostic)
        {
            Diagnostic->RawCategory = ErrorCode.category().name();
            Diagnostic->RawMessage = ErrorCode.message();
            Diagnostic->RawValue = ErrorCode.value();
        }
        return Prism::Fault::make_error_code(FaultCode);
    }

    [[nodiscard]] auto EndpointWrite(
        IoEndpoint &Endpoint,
        const IoMode Mode,
        std::span<const std::byte> Buffer)
        -> Net::awaitable<std::pair<std::error_code, std::size_t>>
    {
        const auto FragmentSize = (std::min)(Endpoint.FragmentBytes, Buffer.size());
        const auto Fragment = Buffer.first(FragmentSize);
        if (Mode == IoMode::Direct)
        {
            const auto [ErrorCode, Count] = co_await AwaitDirectWrite(Endpoint.Reliable, Fragment);
            co_return std::pair{ToTransferError(ErrorCode), Count};
        }
        if (Mode == IoMode::AwaitableBridge)
        {
            const auto [ErrorCode, Count] = co_await AwaitBridgeWrite(Endpoint.Bridge, Fragment);
            co_return std::pair{ToTransferError(ErrorCode), Count};
        }
        const auto Split = Fragment.size() / 2;
        const std::array<Net::const_buffer, 2> Buffers{
            Net::buffer(Fragment.data(), Split),
            Net::buffer(Fragment.data() + Split, Fragment.size() - Split)};
        boost::system::error_code ErrorCode;
        const auto Count = co_await Endpoint.Scatter->async_write_some(
            Buffers, Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return std::pair{ToTransferError(ErrorCode), Count};
    }

    [[nodiscard]] auto EndpointRead(const EndpointReadRequest &Request)
        -> Net::awaitable<std::pair<std::error_code, std::size_t>>
    {
        const auto FragmentSize =
            (std::min)(Request.Endpoint.FragmentBytes, Request.Buffer.size());
        auto Fragment = Request.Buffer.first(FragmentSize);
        if (Request.Mode == IoMode::Direct)
        {
            const auto [ErrorCode, Count] = co_await AwaitDirectRead(
                Request.Endpoint.Reliable, Fragment);
            co_return std::pair{ToTransferError(ErrorCode, Request.Diagnostic), Count};
        }
        if (Request.Mode == IoMode::AwaitableBridge)
        {
            const auto [ErrorCode, Count] = co_await AwaitBridgeRead(
                Request.Endpoint.Bridge, Fragment);
            co_return std::pair{ToTransferError(ErrorCode, Request.Diagnostic), Count};
        }
        const auto Split = Fragment.size() / 2;
        const std::array<Net::mutable_buffer, 2> Buffers{
            Net::buffer(Fragment.data(), Split),
            Net::buffer(Fragment.data() + Split, Fragment.size() - Split)};
        boost::system::error_code ErrorCode;
        const auto Count = co_await Request.Endpoint.Scatter->async_read_some(
            Buffers, Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return std::pair{ToTransferError(ErrorCode, Request.Diagnostic), Count};
    }

    struct PreflightReadResult final
    {
        std::error_code Error;
        std::size_t Count{0};
        ErrorProjection Projection;
    };

    [[nodiscard]] auto IsCancellationError(const std::error_code &ErrorCode) -> bool
    {
        return ErrorCode == std::make_error_code(std::errc::operation_canceled) ||
               Prism::Fault::ToCode(ErrorCode) == Prism::Fault::Code::Canceled ||
               ErrorCode.value() == boost::asio::error::operation_aborted;
    }

    [[nodiscard]] auto IsEofError(const std::error_code &ErrorCode) -> bool
    {
        return Prism::Fault::ToCode(ErrorCode) == Prism::Fault::Code::Eof ||
               ErrorCode.value() == boost::asio::error::eof;
    }

    using PreflightEndpointChannel =
        Net::experimental::channel<void(boost::system::error_code, std::shared_ptr<IoEndpoint>)>;
    using PreflightServerExitChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct PreflightReadState final
    {
        IoEndpoint Endpoint;
        IoMode Mode;
        std::shared_ptr<GateChannel> Started;
        std::shared_ptr<PreflightReadResult> Result;
        std::shared_ptr<std::array<std::byte, 8>> Buffer;
    };

    struct PreflightServerRequest final
    {
        std::shared_ptr<Net::ip::tcp::acceptor> Acceptor;
        std::shared_ptr<PreflightEndpointChannel> Ready;
        std::shared_ptr<PreflightServerExitChannel> Exited;
        IoMode Mode{IoMode::Direct};
    };

    auto RunPreflightServer(PreflightServerRequest Request) -> Net::awaitable<void>
    {
        try
        {
            Net::ip::tcp::socket Socket(Request.Acceptor->get_executor());
            boost::system::error_code AcceptError;
            co_await Request.Acceptor->async_accept(
                Socket, Net::redirect_error(Net::use_awaitable, AcceptError));
            if (AcceptError)
            {
                (void)Request.Ready->try_send(
                    AcceptError, std::shared_ptr<IoEndpoint>{});
            }
            else
            {
                auto Endpoint = std::make_shared<IoEndpoint>(MakeEndpoint(
                    Request.Mode, std::make_shared<Prism::Transport::Reliable>(
                                      std::move(Socket))));
                (void)Request.Ready->try_send(
                    boost::system::error_code{}, std::move(Endpoint));
            }
        }
        catch (...)
        {
            (void)Request.Ready->try_send(
                boost::system::errc::make_error_code(boost::system::errc::io_error),
                std::shared_ptr<IoEndpoint>{});
        }
        (void)Request.Exited->try_send(boost::system::error_code{});
    }

    auto RunPreflightRead(
        std::shared_ptr<PreflightReadState> State) -> Net::awaitable<void>
    {
        (void)State->Started->try_send(boost::system::error_code{});
        try
        {
            const auto [Error, Count] = co_await EndpointRead(EndpointReadRequest{
                State->Endpoint, State->Mode, *State->Buffer, &State->Result->Projection});
            State->Result->Error = Error;
            State->Result->Count = Count;
        }
        catch (...)
        {
            State->Result->Error = std::make_error_code(std::errc::io_error);
            State->Result->Count = 0;
            throw;
        }
    }

    [[nodiscard]] auto RunPreflightCase(
        const IoMode Mode,
        const bool CancelClient) -> Net::awaitable<bool>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Acceptor = std::make_shared<Net::ip::tcp::acceptor>(
            Executor, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor->local_endpoint().port();
        const auto ServerReady = std::make_shared<PreflightEndpointChannel>(Executor, 1);
        const auto ServerExited = std::make_shared<PreflightServerExitChannel>(Executor, 1);
        Net::co_spawn(
            Executor,
            RunPreflightServer(PreflightServerRequest{
                Acceptor, ServerReady, ServerExited, Mode}),
            Net::detached);

        auto ClientReliable = std::make_shared<Prism::Transport::Reliable>(Executor);
        const auto ConnectError = co_await ClientReliable->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Port));
        if (ConnectError)
        {
            boost::system::error_code CloseError;
            Acceptor->close(CloseError);
            (void)co_await ServerReady->async_receive(Net::use_awaitable);
            (void)co_await ServerExited->async_receive(Net::use_awaitable);
            co_return false;
        }
        boost::system::error_code ServerReadyError;
        auto ServerEndpoint = co_await ServerReady->async_receive(
            Net::redirect_error(Net::use_awaitable, ServerReadyError));
        if (ServerReadyError || !ServerEndpoint)
        {
            (void)ClientReliable->Close();
            boost::system::error_code CloseError;
            Acceptor->close(CloseError);
            (void)co_await ServerExited->async_receive(Net::use_awaitable);
            co_return false;
        }
        auto ClientEndpoint = MakeEndpoint(Mode, std::move(ClientReliable));
        const auto ReadStarted = std::make_shared<GateChannel>(Executor, 1);
        const auto ReadDone = std::make_shared<GateChannel>(Executor, 1);
        const auto ReadResult = std::make_shared<PreflightReadResult>();
        const auto ReadState = std::make_shared<PreflightReadState>(
            PreflightReadState{
                std::move(ClientEndpoint), Mode, ReadStarted, ReadResult,
                std::make_shared<std::array<std::byte, 8>>()});
        try
        {
            Net::co_spawn(
                Executor,
                RunPreflightRead(ReadState),
                [ReadDone](std::exception_ptr Exception)
                {
                    const auto Error = Exception
                                           ? boost::system::errc::make_error_code(
                                                 boost::system::errc::io_error)
                                           : boost::system::error_code{};
                    (void)ReadDone->try_send(Error);
                });
        }
        catch (...)
        {
            const auto Error = boost::system::errc::make_error_code(
                boost::system::errc::io_error);
            (void)ReadStarted->try_send(Error);
            (void)ReadDone->try_send(Error);
        }
        boost::system::error_code ReadStartedError;
        co_await ReadStarted->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadStartedError));
        if (ReadStartedError)
        {
            std::printf(
                "io-preflight %-18s case=%s stage=read-start-error\n",
                ModeName(Mode), CancelClient ? "cancel" : "error");
            (void)ReadState->Endpoint.Reliable->Close();
            (void)ServerEndpoint->Reliable->Close();
            boost::system::error_code CloseError;
            Acceptor->close(CloseError);
            boost::system::error_code ReadDoneError;
            co_await ReadDone->async_receive(
                Net::redirect_error(Net::use_awaitable, ReadDoneError));
            (void)co_await ServerExited->async_receive(Net::use_awaitable);
            co_return false;
        }
        std::printf(
            "io-preflight %-18s case=%s stage=read-started\n",
            ModeName(Mode), CancelClient ? "cancel" : "error");
        if (CancelClient)
        {
            (void)ReadState->Endpoint.Reliable->Cancel();
        }
        else
        {
            (void)ServerEndpoint->Reliable->Close();
        }
        boost::system::error_code ReadDoneError;
        co_await ReadDone->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadDoneError));
        std::printf(
            "io-preflight %-18s case=%s stage=read-done count=%zu "
            "raw-category=%s raw-value=%d raw-message=%s "
            "projected-category=%s projected-value=%d projected-message=%s\n",
            ModeName(Mode), CancelClient ? "cancel" : "error", ReadResult->Count,
            ReadResult->Projection.RawCategory.c_str(), ReadResult->Projection.RawValue,
            ReadResult->Projection.RawMessage.c_str(), ReadResult->Error.category().name(),
            ReadResult->Error.value(), ReadResult->Error.message().c_str());
        (void)ReadState->Endpoint.Reliable->Close();
        (void)ServerEndpoint->Reliable->Close();
        boost::system::error_code CloseError;
        Acceptor->close(CloseError);
        (void)co_await ServerExited->async_receive(Net::use_awaitable);
        const auto ExpectedError = CancelClient
                                        ? IsCancellationError(ReadResult->Error)
                                        : IsEofError(ReadResult->Error);
        co_return ReadResult->Count == 0 && ExpectedError;
    }

    auto RunIoPreflightSequence(
        const IoMode Mode, bool &CancelOk, bool &ErrorOk) -> Net::awaitable<void>
    {
        std::printf("io-preflight %-18s stage=cancel-start\n", ModeName(Mode));
        CancelOk = co_await RunPreflightCase(Mode, true);
        std::printf(
            "io-preflight %-18s stage=cancel-done result=%s\n",
            ModeName(Mode), CancelOk ? "pass" : "fail");
        std::printf("io-preflight %-18s stage=error-start\n", ModeName(Mode));
        ErrorOk = co_await RunPreflightCase(Mode, false);
        std::printf(
            "io-preflight %-18s stage=error-done result=%s\n",
            ModeName(Mode), ErrorOk ? "pass" : "fail");
    }

    [[nodiscard]] auto RunIoPreflight(const IoMode Mode) -> bool
    {
        Net::io_context IoContext;
        bool CancelOk = false;
        bool ErrorOk = false;
        RunCoroutine(IoContext, RunIoPreflightSequence(Mode, CancelOk, ErrorOk));
        std::printf(
            "io-preflight %-18s cancel=%s error=%s\n",
            ModeName(Mode), CancelOk ? "pass" : "fail", ErrorOk ? "pass" : "fail");
        return CancelOk && ErrorOk;
    }


}

