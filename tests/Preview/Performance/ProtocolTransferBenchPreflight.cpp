/**
 * @file ProtocolTransferBenchPreflight.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolTransferBench
{
    struct EchoFailureReceipt final
    {
        std::error_code Native;
        std::size_t Bytes{0};
    };

    using EchoDoneChannel = Net::experimental::channel<void(
        boost::system::error_code, EchoFailureReceipt)>;

    struct FailurePreflightState final
    {
        explicit FailurePreflightState(Net::any_io_executor Executor)
            : Acceptor(Executor, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)),
              ServerReady(std::make_shared<DoneChannel>(Executor, 1)),
              EchoDone(std::make_shared<EchoDoneChannel>(Executor, 1)),
              ReadStarted(std::make_shared<DoneChannel>(Executor, 1)),
              ReadDone(std::make_shared<DoneChannel>(Executor, 1))
        {
        }

        Net::ip::tcp::acceptor Acceptor;
        std::shared_ptr<Transport::Reliable> Client;
        std::shared_ptr<Transport::Reliable> Server;
        std::shared_ptr<DoneChannel> ServerReady;
        std::shared_ptr<EchoDoneChannel> EchoDone;
        std::shared_ptr<DoneChannel> ReadStarted;
        std::shared_ptr<DoneChannel> ReadDone;
        std::size_t PayloadBytes{0};
        std::uint64_t PayloadHash{1469598103934665603ULL};
        std::uint64_t ServerHash{1469598103934665603ULL};
        std::size_t CancelCount{0};
        std::size_t FinCount{0};
        std::size_t ResetCount{0};
        std::error_code CancelError;
        std::error_code FinError;
        std::error_code ResetError;
        Preview::Fault::Failure ConnectFailure;
        EchoFailureReceipt EchoFailure;
        std::exception_ptr Failure;
        bool Diagnose{false};
    };

    auto PrintFailurePreflightDiagnostic(
        const FailurePreflightState &State,
        const char *Stage) -> void
    {
        if (!State.Diagnose)
        {
            return;
        }
        const auto ErrorText = [](const std::error_code &Error) -> const char *
        {
            return Error ? Error.category().name() : "none";
        };
        const auto ConnectNative = Preview::Fault::ToNative(State.ConnectFailure);
        std::printf(
            "protocol-preflight-diagnose stage=%s connect-code=%d connect-ec=%s/%d "
            "echo-bytes=%zu echo-ec=%s/%d "
            "payload-bytes=%zu payload-hash=%016llx "
            "cancel-count=%zu cancel-ec=%s/%d fin-count=%zu fin-ec=%s/%d "
            "reset-count=%zu reset-ec=%s/%d server-hash=%016llx\n",
            Stage, static_cast<int>(State.ConnectFailure.Code), ErrorText(ConnectNative),
            ConnectNative.value(), State.EchoFailure.Bytes, ErrorText(State.EchoFailure.Native),
            State.EchoFailure.Native.value(), State.PayloadBytes,
            static_cast<unsigned long long>(State.PayloadHash),
            State.CancelCount, ErrorText(State.CancelError), State.CancelError.value(),
            State.FinCount, ErrorText(State.FinError), State.FinError.value(),
            State.ResetCount, ErrorText(State.ResetError), State.ResetError.value(),
            static_cast<unsigned long long>(State.ServerHash));
        std::fflush(stdout);
    }

    auto CloseFailureSockets(const std::shared_ptr<FailurePreflightState> &State) noexcept -> void
    {
        if (State->Client)
        {
            (void)State->Client->Close();
        }
        if (State->Server)
        {
            (void)State->Server->Close();
        }
        boost::system::error_code Error;
        State->Acceptor.close(Error);
    }

    auto WriteFailureExact(
        const std::shared_ptr<Transport::Reliable> &Connection,
        std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            const auto Write = co_await Connection->WriteSome(Buffer.subspan(Done));
            ErrorCode = Preview::Fault::ToNative(Write.Failure);
            const auto Count = Write.Bytes;
            if (ErrorCode || Count == 0 || Count > Buffer.size() - Done)
            {
                co_return Done;
            }
            Done += Count;
        }
        co_return Done;
    }

    auto ReadFailureExact(
        const std::shared_ptr<Transport::Reliable> &Connection,
        std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            const auto Read = co_await Connection->ReadSome(Buffer.subspan(Done));
            ErrorCode = Preview::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ErrorCode || Count == 0 || Count > Buffer.size() - Done)
            {
                co_return Done;
            }
            Done += Count;
        }
        co_return Done;
    }

    /** @brief 只唤醒预检协程；真实 Native 已保存在 FailurePreflightState::Failure。 */
    auto SignalEchoFailure(
        const std::shared_ptr<FailurePreflightState> &State,
        EchoFailureReceipt Receipt) -> void
    {
        (void)State->EchoDone->try_send(boost::system::error_code{}, std::move(Receipt));
    }

    auto RunFailureAccept(std::shared_ptr<FailurePreflightState> State) -> Net::awaitable<void>
    {
        Net::ip::tcp::socket Socket(State->Acceptor.get_executor());
        boost::system::error_code Error;
        co_await State->Acceptor.async_accept(
            Socket, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            State->Failure = std::make_exception_ptr(std::system_error(
                std::error_code(Error.value(), std::generic_category())));
            (void)State->ServerReady->try_send(Error);
            co_return;
        }
        State->Server = std::make_shared<Transport::Reliable>(std::move(Socket));
        (void)State->ServerReady->try_send(boost::system::error_code{});
    }

    auto RunFailureEcho(std::shared_ptr<FailurePreflightState> State) -> Net::awaitable<void>
    {
        std::array<std::byte, 8> Buffer{};
        std::error_code Error;
        const auto Count = co_await ReadFailureExact(State->Server, Buffer, Error);
        if (Error || Count != Buffer.size())
        {
            const auto Native = Error ? Error : std::make_error_code(std::errc::io_error);
            State->Failure = std::make_exception_ptr(std::system_error(Native));
            SignalEchoFailure(State, EchoFailureReceipt{Native, Count});
            co_return;
        }
        HashBytes(State->ServerHash, Buffer);
        const auto Written = co_await WriteFailureExact(State->Server, Buffer, Error);
        if (Error || Written != Buffer.size())
        {
            const auto Native = Error ? Error : std::make_error_code(std::errc::io_error);
            State->Failure = std::make_exception_ptr(std::system_error(Native));
            SignalEchoFailure(State, EchoFailureReceipt{Native, Written});
            co_return;
        }
        (void)State->EchoDone->try_send(boost::system::error_code{}, EchoFailureReceipt{});
    }

    auto RunFailureReadFrame(std::shared_ptr<FailurePreflightState> State) -> Net::awaitable<void>
    {
        PrintFailurePreflightDiagnostic(*State, "read-started");
        (void)State->ReadStarted->try_send(boost::system::error_code{});
        std::array<std::byte, 1> Buffer{};
        const auto CancelRead = co_await State->Client->ReadSome(Buffer);
        State->CancelError = Preview::Fault::ToNative(CancelRead.Failure);
        State->CancelCount = CancelRead.Bytes;
        (void)State->ReadDone->try_send(boost::system::error_code{});
        PrintFailurePreflightDiagnostic(*State, "done");
    }

    auto RunFailurePreflight(const std::shared_ptr<FailurePreflightState> &State)
        -> Net::awaitable<void>
    {
        PrintFailurePreflightDiagnostic(*State, "start");
        constexpr std::array<std::byte, 8> Payload{
            std::byte{0x10}, std::byte{0x22}, std::byte{0x34}, std::byte{0x46},
            std::byte{0x58}, std::byte{0x6A}, std::byte{0x7C}, std::byte{0x8E}};
        std::array<std::byte, Payload.size()> Received{};
        std::error_code ErrorCode;

        auto AcceptFrame = RunFailureAccept(State);
        Net::co_spawn(State->Acceptor.get_executor(), std::move(AcceptFrame), Net::detached);
        State->Client = std::make_shared<Transport::Reliable>(State->Acceptor.get_executor());
        const auto ConnectResult = co_await State->Client->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(),
                                   State->Acceptor.local_endpoint().port()));
        if (!ConnectResult)
        {
            State->ConnectFailure = ConnectResult.error();
            State->Failure = std::make_exception_ptr(std::system_error(
                Preview::Fault::ToNative(State->ConnectFailure)));
            CloseFailureSockets(State);
            co_return;
        }

        boost::system::error_code ReadyError;
        co_await State->ServerReady->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadyError));
        if (ReadyError || !State->Server)
        {
            State->Failure = std::make_exception_ptr(std::system_error(
                std::error_code(ReadyError ? ReadyError.value() : 1, std::generic_category())));
            CloseFailureSockets(State);
            co_return;
        }
        PrintFailurePreflightDiagnostic(*State, "ready");

        auto EchoFrame = RunFailureEcho(State);
        Net::co_spawn(State->Server->Executor(), std::move(EchoFrame), Net::detached);
        State->PayloadBytes = co_await WriteFailureExact(State->Client, Payload, ErrorCode);
        if (ErrorCode || State->PayloadBytes != Payload.size())
        {
            State->Failure = std::make_exception_ptr(std::system_error(
                ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error)));
            CloseFailureSockets(State);
            co_return;
        }
        const auto Echoed = co_await ReadFailureExact(State->Client, Received, ErrorCode);
        if (ErrorCode || Echoed != Received.size() ||
            !std::equal(Received.begin(), Received.end(), Payload.begin(), Payload.end()))
        {
            State->Failure = std::make_exception_ptr(std::system_error(
                ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error)));
            CloseFailureSockets(State);
            co_return;
        }
        HashBytes(State->PayloadHash, Received);
        State->EchoFailure = co_await State->EchoDone->async_receive(Net::use_awaitable);
        if (State->EchoFailure.Native || State->Failure)
        {
            CloseFailureSockets(State);
            co_return;
        }

        auto ReadFrame = RunFailureReadFrame(State);
        Net::co_spawn(State->Client->Executor(), std::move(ReadFrame), Net::detached);
        boost::system::error_code ReadStartedError;
        co_await State->ReadStarted->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadStartedError));
        if (ReadStartedError)
        {
            State->Failure = std::make_exception_ptr(std::system_error(
                std::error_code(ReadStartedError.value(), std::generic_category())));
            CloseFailureSockets(State);
            co_return;
        }
        (void)State->Client->Cancel();
        boost::system::error_code ReadDoneError;
        co_await State->ReadDone->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadDoneError));
        if (ReadDoneError)
        {
            State->Failure = std::make_exception_ptr(std::system_error(
                std::error_code(ReadDoneError.value(), std::generic_category())));
            CloseFailureSockets(State);
            co_return;
        }

        (void)co_await State->Server->WriteShutdown();
        std::array<std::byte, 1> FinBuffer{};
        const auto FinRead = co_await State->Client->ReadSome(FinBuffer);
        State->FinError = Preview::Fault::ToNative(FinRead.Failure);
        State->FinCount = FinRead.Bytes;

        (void)State->Client->Close();
        const std::array<std::byte, 1> ResetPayload{std::byte{0xF1}};
        const auto ResetWrite = co_await State->Client->WriteSome(ResetPayload);
        State->ResetError = Preview::Fault::ToNative(ResetWrite.Failure);
        State->ResetCount = ResetWrite.Bytes;
        CloseFailureSockets(State);
        PrintFailurePreflightDiagnostic(*State, "end");
    }

    [[nodiscard]] auto CheckFailurePreflight(const FailurePreflightState &State) -> bool
    {
        constexpr std::array<std::byte, 8> Payload{
            std::byte{0x10}, std::byte{0x22}, std::byte{0x34}, std::byte{0x46},
            std::byte{0x58}, std::byte{0x6A}, std::byte{0x7C}, std::byte{0x8E}};
        const std::uint64_t ExpectedHash = [&Payload]
        {
            std::uint64_t Hash = 1469598103934665603ULL;
            HashBytes(Hash, Payload);
            return Hash;
        }();
        const auto IsFault = [](const std::error_code &Error, const Preview::Fault::Code Code) noexcept
        {
            return Error && Error.category() == Preview::Fault::Category() &&
                   Error.value() == static_cast<int>(Code);
        };
        // 本地已关闭 socket 的 write 必须走正式 bad-descriptor -> IoError 映射。
        const auto ResetClassified = IsFault(State.ResetError, Preview::Fault::Code::IoError);
        const auto Valid = !State.Failure && State.PayloadBytes == Payload.size() &&
            State.PayloadHash == ExpectedHash && State.ServerHash == ExpectedHash &&
            !State.EchoFailure.Native &&
            IsFault(State.CancelError, Preview::Fault::Code::Canceled) && State.CancelCount == 0 &&
            IsFault(State.FinError, Preview::Fault::Code::Eof) && State.FinCount == 0 &&
            ResetClassified && State.ResetCount == 0;
        std::printf("preflight=%s wire_bytes=%zu wire_hash=%016llx echo_bytes=%zu echo_ec=%s/%d "
                    "cancel_count=%zu cancel_ec=%s fin_count=%zu fin_ec=%s reset_count=%zu reset_ec=%s\n",
                    Valid ? "pass" : "fail", State.PayloadBytes,
                    static_cast<unsigned long long>(State.PayloadHash), State.EchoFailure.Bytes,
                    State.EchoFailure.Native ? State.EchoFailure.Native.category().name() : "none",
                    State.EchoFailure.Native.value(), State.CancelCount,
                    State.CancelError ? State.CancelError.category().name() : "none",
                    State.FinCount, State.FinError ? State.FinError.category().name() : "none",
                    State.ResetCount, State.ResetError ? State.ResetError.category().name() : "none");
        std::fflush(stdout);
        return Valid;
    }

    [[nodiscard]] auto RunFailurePreflightCase(const bool Diagnose) -> bool
    {
        Net::io_context Io;
        auto State = std::make_shared<FailurePreflightState>(Io.get_executor());
        State->Diagnose = Diagnose;
        Net::co_spawn(Io, RunFailurePreflight(State),
            [State](std::exception_ptr Failure)
            {
                if (Failure)
                {
                    State->Failure = std::move(Failure);
                }
            });
        Io.run();
        PrintFailurePreflightDiagnostic(*State, "exited");
        return CheckFailurePreflight(*State);
    }

    [[nodiscard]] auto RunAllocationPreflight(const bool Diagnose) -> bool
    {
        constexpr auto Alignment = std::align_val_t{64};
        void *Ordinary = nullptr;
        void *OrdinaryArray = nullptr;
        void *OrdinaryNoThrow = nullptr;
        void *OrdinaryArrayNoThrow = nullptr;
        void *Aligned = nullptr;
        void *AlignedArray = nullptr;
        void *AlignedNoThrow = nullptr;
        void *AlignedArrayNoThrow = nullptr;
        bool Valid = true;
        if (Diagnose)
        {
            std::printf("protocol-preflight-diagnose stage=allocation-start\n");
            std::fflush(stdout);
        }
        ProtocolBenchAllocation::Start();
        try
        {
            Ordinary = ::operator new(17U);
            OrdinaryArray = ::operator new[](19U);
            OrdinaryNoThrow = ::operator new(23U, std::nothrow);
            OrdinaryArrayNoThrow = ::operator new[](29U, std::nothrow);
            Aligned = ::operator new(31U, Alignment);
            AlignedArray = ::operator new[](37U, Alignment);
            AlignedNoThrow = ::operator new(41U, Alignment, std::nothrow);
            AlignedArrayNoThrow = ::operator new[](43U, Alignment, std::nothrow);
        }
        catch (...)
        {
            Valid = false;
        }
        ::operator delete(Ordinary);
        ::operator delete[](OrdinaryArray);
        ::operator delete(OrdinaryNoThrow);
        ::operator delete[](OrdinaryArrayNoThrow);
        ::operator delete(Aligned, Alignment);
        ::operator delete[](AlignedArray, Alignment);
        ::operator delete(AlignedNoThrow, Alignment);
        ::operator delete[](AlignedArrayNoThrow, Alignment);
        ProtocolBenchAllocation::Stop();
        const auto Snapshot = ProtocolBenchAllocation::Read();
        const auto OrdinaryBytes = 17U + 19U + 23U + 29U;
        const auto AlignedBytes = 31U + 37U + 41U + 43U;
        Valid = Valid && Snapshot.OrdinaryAllocations == 4U &&
                Snapshot.AlignedAllocations == 4U && Snapshot.OrdinaryBytes == OrdinaryBytes &&
                Snapshot.AlignedBytes == AlignedBytes;
        std::printf(
            "allocation-preflight=%s ordinary=[%zu,%zu] aligned=[%zu,%zu]\n",
            Valid ? "pass" : "fail", Snapshot.OrdinaryAllocations, Snapshot.OrdinaryBytes,
            Snapshot.AlignedAllocations, Snapshot.AlignedBytes);
        if (Diagnose)
        {
            std::printf("protocol-preflight-diagnose stage=allocation-end valid=%s\n",
                        Valid ? "yes" : "no");
            std::fflush(stdout);
        }
        return Valid;
    }

    [[nodiscard]] auto WriteAll(
        const Preview::SharedTransmission &Conn,
        std::span<const std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        std::size_t Done = 0;
        while (Done < Data.size())
        {
            const auto Write = co_await Conn->WriteSome(Data.subspan(Done));
            ErrorCode = Preview::Fault::ToNative(Write.Failure);
            const auto Count = Write.Bytes;
            if (Count > Data.size() - Done)
            {
                ErrorCode = std::make_error_code(std::errc::io_error);
                co_return Done;
            }
            Done += Count;
            if (ErrorCode || Count == 0)
            {
                co_return Done;
            }
        }
        co_return Done;
    }

    [[nodiscard]] auto ReadExact(
        const Preview::SharedTransmission &Conn,
        std::span<std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        std::size_t Done = 0;
        while (Done < Data.size())
        {
            const auto Read = co_await Conn->ReadSome(Data.subspan(Done));
            ErrorCode = Preview::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (Count > Data.size() - Done)
            {
                ErrorCode = std::make_error_code(std::errc::io_error);
                co_return Done;
            }
            Done += Count;
            if (ErrorCode || Count == 0)
            {
                co_return Done;
            }
        }
        co_return Done;
    }

    auto RunBenchIo(Net::io_context &IoContext, Net::awaitable<void> Coroutine)
        -> std::exception_ptr
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&Failure](std::exception_ptr Error)
            {
                Failure = std::move(Error);
            });
        IoContext.run();
        return Failure;
    }


}
