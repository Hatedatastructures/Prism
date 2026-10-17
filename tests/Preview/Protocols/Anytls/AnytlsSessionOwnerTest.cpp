/** @file AnytlsSessionOwnerTest.cpp @brief 实际认证和会话首包行为的独立 wire 回归。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Anytls/Detail/Session/Writer.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <array>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Payload{"A4-FIRST-PAYLOAD"};
    static_assert(Payload.size() == 16);
    /**
     * @brief 用真实有界字节池构造 AnyTLS 接入输入。
     * @param Inbound fixture 移交的入站传输 owner。
     * @param Metadata fixture 持有的请求元数据快照。
     * @return 完整且唯一的接入输入。
     */
    [[nodiscard]] auto MakeStreamAcceptInput(Preview::SharedTransmission Inbound,
                               Preview::Contract::RequestMetadata Metadata)
        -> Preview::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), std::move(Metadata),
            std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 8})};
    }

    struct Result final
    {
        bool Authenticated{false}, Settings{false};
        bool SynAck{false}, Echo{false};
        bool RootCompleted{false};
        std::size_t TargetReceived{0};
        std::size_t Completed{0};
        std::uint8_t AlertCommand{0xff};
        std::expected<void, Preview::Fault::Failure> RootStatus;
        std::vector<std::byte> AlertPayload;
        std::exception_ptr Failure;
    };

    struct Fixture final : std::enable_shared_from_this<Fixture>
    {
        explicit Fixture(Net::any_io_executor Executor)
            : Acceptor(Executor, Tcp::endpoint(Tcp::v4(), 0)), EchoSocket(Executor),
              Deadline(Executor)
        {
            auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(Executor);
            Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
            Server = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        }
        auto Close() -> void
        {
            boost::system::error_code Ignored;
            Acceptor.close(Ignored);
            EchoSocket.close(Ignored);
            Deadline.cancel();
            if (Client) (void)Client->Close();
            if (Server) (void)Server->Close();
            if (Outbound) (void)Outbound->Close();
            if (Owner) { Owner->Cancel(); Owner->Close(); }
        }
        Tcp::acceptor Acceptor;
        Tcp::socket EchoSocket;
        Net::steady_timer Deadline;
        Preview::SharedTransmission Client, Server, Outbound;
        std::shared_ptr<Preview::Contract::MuxSession> Owner;
        bool Fragmented{false};
        Result Actual;
    };

    auto WriteAll(Preview::SharedTransmission Stream, std::span<const std::byte> Bytes)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset != Bytes.size())
        {
            std::error_code Error;
            const auto Write = co_await Stream->WriteSome(Bytes.subspan(Offset));
            Error = Preview::Fault::ToNative(Write.Failure);
            const auto Count = Write.Bytes;
            if (Error || Count == 0 || Count > Bytes.size() - Offset) co_return false;
            Offset += Count;
        }
        co_return true;
    }

    auto ReadExact(Preview::SharedTransmission Stream, std::span<std::byte> Bytes)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset != Bytes.size())
        {
            std::error_code Error;
            const auto Read = co_await Stream->ReadSome(Bytes.subspan(Offset));
            Error = Preview::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (Error || Count == 0 || Count > Bytes.size() - Offset) co_return false;
            Offset += Count;
        }
        co_return true;
    }

    auto FrameWithId(std::uint8_t Command, std::uint32_t Id,
                     std::span<const std::byte> Bytes = {})
        -> std::vector<std::byte>
    {
        std::vector<std::byte> Wire{
            std::byte{Command}, std::byte{static_cast<std::uint8_t>(Id >> 24)},
            std::byte{static_cast<std::uint8_t>(Id >> 16)},
            std::byte{static_cast<std::uint8_t>(Id >> 8)},
            std::byte{static_cast<std::uint8_t>(Id)},
            std::byte{static_cast<std::uint8_t>(Bytes.size() >> 8)},
            std::byte{static_cast<std::uint8_t>(Bytes.size())}};
        Wire.insert(Wire.end(), Bytes.begin(), Bytes.end());
        return Wire;
    }

    auto Frame(std::uint8_t Command, std::span<const std::byte> Bytes = {})
        -> std::vector<std::byte>
    {
        return FrameWithId(Command, Command == 4 ? 0U : 1U, Bytes);
    }

    auto ReadWire(Preview::SharedTransmission Stream)
        -> Net::awaitable<std::pair<std::uint8_t, std::vector<std::byte>>>
    {
        std::array<std::byte, 7> Header{};
        if (!co_await ReadExact(Stream, Header)) co_return std::pair{0xffU, std::vector<std::byte>{}};
        const auto Length = (std::to_integer<std::size_t>(Header[5]) << 8) |
                            std::to_integer<std::size_t>(Header[6]);
        std::vector<std::byte> Body(Length);
        if (!co_await ReadExact(Stream, Body)) co_return std::pair{0xffU, std::vector<std::byte>{}};
        co_return std::pair{std::to_integer<std::uint8_t>(Header[0]), std::move(Body)};
    }

    auto Dial(std::shared_ptr<Fixture> State, const Preview::Network::Target& Target)
        -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        Tcp::socket Socket(co_await Net::this_coro::executor);
        boost::system::error_code Error;
        co_await Socket.async_connect(Tcp::endpoint(*Preview::Network::IpAddress(Target.Host),
            Target.Port),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::BadGateway, static_cast<std::error_code>(Error)});
        }
        State->Outbound = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        co_return State->Outbound;
    }

    class Egress final : public Preview::Contract::StreamEgress
    {
    public:
        explicit Egress(std::weak_ptr<Fixture> State) : State_(std::move(State)) {}
        auto Connect(Preview::Network::Target Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>> override
        { co_return co_await Dial(State_.lock(), Target); }
    private:
        std::weak_ptr<Fixture> State_;
    };
    auto RunRoot(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        auto Bytes = std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{.BlockCount = 4U});
        Preview::Anytls::IngressFactory Factory({.Configuration = {"task-four-secret"},
            .Streams = {.Egress = std::make_shared<Egress>(State), .Bytes = Bytes}});
        auto Input = MakeStreamAcceptInput(std::move(State->Server), {});
        const auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        Input.GenerationUseState = UseState;
        auto Accepted = co_await Factory.Accept(std::move(Input));
        State->Actual.Authenticated = Accepted && Accepted->ProtocolAuthenticated;
        if (!Accepted) co_return;
        State->Server = Accepted->Transport();
        State->Owner = Accepted->Mux()->Session;
        Preview::Contract::MuxRootRequest Request;
        Request.Lease = std::move(Accepted->AccountLease);
        Request.GenerationUseState = UseState;
        State->Actual.RootStatus = co_await State->Owner->Run(std::move(Request));
        EXPECT_EQ(UseState->Outstanding(), 0U);
        EXPECT_TRUE(State->Owner->IsRetired());
        State->Actual.RootCompleted = true;
    }

    auto RunEcho(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await State->Acceptor.async_accept(State->EchoSocket,
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error) co_return;
        std::array<char, Payload.size()> Received{};
        State->Actual.TargetReceived = co_await Net::async_read(State->EchoSocket,
            Net::buffer(Received), Net::redirect_error(Net::use_awaitable, Error));
        if (Error) co_return;
        EXPECT_EQ(std::string_view(Received.data(), Received.size()), Payload);
        (void)co_await Net::async_write(State->EchoSocket, Net::buffer(Received),
            Net::redirect_error(Net::use_awaitable, Error));
        State->EchoSocket.shutdown(Tcp::socket::shutdown_send, Error);
    }

    auto RunClient(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        std::string Auth;
        EXPECT_EQ(Preview::Anytls::BuildAuthFrame("task-four-secret", 0, Auth), Preview::Error::None);
        const auto AuthBytes = std::as_bytes(std::span(Auth));
        if (!co_await WriteAll(State->Client, AuthBytes)) co_return;
        constexpr std::string_view SettingsText{"v=2\nclient=task4\n"};
        const auto Settings = Frame(4, std::as_bytes(std::span(SettingsText)));
        if (!co_await WriteAll(State->Client, Settings)) co_return;
        auto [Command, SettingsPayload] = co_await ReadWire(State->Client);
        State->Actual.Settings = Command == 10;
        const auto Syn = Frame(1);
        if (!co_await WriteAll(State->Client, Syn)) co_return;
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Target{std::byte{1}, std::byte{127}, std::byte{0},
            std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8)},
            std::byte{static_cast<std::uint8_t>(Port)}};
        const auto PayloadBytes = std::as_bytes(std::span(Payload));
        Target.insert(Target.end(), PayloadBytes.begin(), PayloadBytes.end());
        if (State->Fragmented)
        {
            const auto First = Frame(2, std::span(Target).first(3));
            const auto Second = Frame(2, std::span(Target).subspan(3));
            if (!co_await WriteAll(State->Client, First)) co_return;
            if (!co_await WriteAll(State->Client, Second)) co_return;
        }
        else
        {
            const auto First = Frame(2, Target);
            if (!co_await WriteAll(State->Client, First)) co_return;
        }
        for (int Index = 0; Index < 3; ++Index)
        {
            auto [Next, Body] = co_await ReadWire(State->Client);
            if (Next == 7) State->Actual.SynAck = true;
            if (Next == 2)
            {
                State->Actual.Echo = Body.size() == PayloadBytes.size() &&
                    std::equal(Body.begin(), Body.end(), PayloadBytes.begin(), PayloadBytes.end());
                break;
            }
            if (Next == 0xff) break;
        }
        State->Close();
    }

    enum class InvalidInput : std::uint8_t
    {
        DuplicateSettings,
        SettingsWithNonzeroStream,
        SynWithZeroStream,
        SynWithoutSettings,
        SynWithDuplicateOrBackwardStream,
        SynWithPayload,
    };

    auto RunInvalidClient(std::shared_ptr<Fixture> State, InvalidInput Input)
        -> Net::awaitable<void>
    {
        std::string Auth;
        if (Preview::Anytls::BuildAuthFrame("task-four-secret", 0, Auth) != Preview::Error::None ||
            !co_await WriteAll(State->Client, std::as_bytes(std::span(Auth))))
        {
            co_return;
        }
        constexpr std::string_view SettingsText{"v=2\nclient=invalid-input\n"};
        const auto SettingsBytes = std::as_bytes(std::span(SettingsText));
        if (Input != InvalidInput::SynWithoutSettings)
        {
            if (!co_await WriteAll(State->Client, Frame(4, SettingsBytes))) co_return;
            const auto [Command, Body] = co_await ReadWire(State->Client);
            if (Command != 10 || Body.empty()) co_return;
        }
        if (Input == InvalidInput::DuplicateSettings)
        {
            if (!co_await WriteAll(State->Client, FrameWithId(4, 0, SettingsBytes))) co_return;
        }
        else if (Input == InvalidInput::SettingsWithNonzeroStream)
        {
            if (!co_await WriteAll(State->Client, FrameWithId(4, 7, SettingsBytes))) co_return;
        }
        else if (Input == InvalidInput::SynWithoutSettings)
        {
            if (!co_await WriteAll(State->Client, FrameWithId(1, 1))) co_return;
        }
        else if (Input == InvalidInput::SynWithDuplicateOrBackwardStream)
        {
            if (!co_await WriteAll(State->Client, FrameWithId(1, 3)) ||
                !co_await WriteAll(State->Client, FrameWithId(1, 2))) co_return;
        }
        else if (Input == InvalidInput::SynWithPayload)
        {
            const std::array<std::byte, 1> PayloadBytes{std::byte{0x42}};
            if (!co_await WriteAll(State->Client, FrameWithId(1, 1, PayloadBytes))) co_return;
        }
        else
        {
            if (!co_await WriteAll(State->Client, FrameWithId(1, 0))) co_return;
        }
        const auto [Command, Body] = co_await ReadWire(State->Client);
        State->Actual.AlertCommand = Command;
        State->Actual.AlertPayload = Body;
        (void)State->Client->Close();
    }

    auto Watchdog(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        State->Deadline.expires_after(std::chrono::milliseconds(400));
        boost::system::error_code Error;
        co_await State->Deadline.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error) State->Close();
    }

    auto Scenario(bool Fragmented) -> Result
    {
        Net::io_context Io;
        auto State = std::make_shared<Fixture>(Io.get_executor());
        State->Fragmented = Fragmented;
        const auto Complete = [State](std::exception_ptr Failure)
        {
            ++State->Actual.Completed;
            if (Failure) { State->Actual.Failure = Failure; State->Close(); }
        };
        Net::co_spawn(Io, RunRoot(State), Complete);
        Net::co_spawn(Io, RunEcho(State), Complete);
        Net::co_spawn(Io, RunClient(State), Complete);
        Net::co_spawn(Io, Watchdog(State), Complete);
        Io.run();
        State->Close();
        return State->Actual;
    }

    auto InvalidScenario(InvalidInput Input) -> Result
    {
        Net::io_context Io;
        auto State = std::make_shared<Fixture>(Io.get_executor());
        const auto Complete = [State](std::exception_ptr Failure)
        {
            ++State->Actual.Completed;
            if (Failure)
            {
                State->Actual.Failure = Failure;
                State->Close();
            }
        };
        Net::co_spawn(Io, RunRoot(State), Complete);
        Net::co_spawn(Io, RunInvalidClient(State, Input), Complete);
        Io.run();
        const auto Actual = State->Actual;
        State->Close();
        return Actual;
    }

    class PartialWriter final : public Preview::Transmission
    {
    public:
        explicit PartialWriter(Preview::SharedTransmission Next)
            : Preview::Transmission(Next->Executor()), Next_(std::move(Next)) {}
        auto Executor() const -> Net::any_io_executor override { return Next_->Executor(); }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(ReadWork{}, Executor()), Handler,
                ReadInput{std::static_pointer_cast<PartialWriter>(Preview::Transmission::shared_from_this()), Buffer});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(WriteWork{}, Executor()), Handler,
                WriteInput{std::static_pointer_cast<PartialWriter>(Preview::Transmission::shared_from_this()), Buffer});
        }
        /** @brief 测试替身显式兑现半关闭；原 Shutdown 沿实际 inner 转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Next_->WriteShutdown(std::move(Handler));
        }
        auto IsOpen() const -> bool override { return Next_->IsOpen(); }
        [[nodiscard]] auto OnClose() -> ControlResult override { (void)Next_->Close(); return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override { (void)Next_->Cancel(); return {}; }
    private:
        struct ReadInput final
        {
            std::shared_ptr<PartialWriter> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<PartialWriter> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->ReadPartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Bytes, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            const auto Read = co_await Next_->ReadSome(Bytes);
            Error = Preview::Fault::ToNative(Read.Failure);
            co_return Read.Bytes;
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Bytes, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            co_await Net::post(Net::use_awaitable);
            const auto Write = co_await Next_->WriteSome(Bytes.first((std::min)(Bytes.size(), std::size_t{1})));
            Error = Preview::Fault::ToNative(Write.Failure);
            co_return Write.Bytes;
        }
        Preview::SharedTransmission Next_;
    };

    class PendingWriter final : public Preview::Transmission
    {
    public:
        explicit PendingWriter(Preview::SharedTransmission Next)
            : Preview::Transmission(Next->Executor()), Next_(std::move(Next)),
              Started_(Next_->Executor(), 1), Gate_(Next_->Executor(), 1)
        {
        }

        auto Executor() const -> Net::any_io_executor override { return Next_->Executor(); }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(ReadWork{}, Executor()), Handler,
                ReadInput{std::static_pointer_cast<PendingWriter>(Preview::Transmission::shared_from_this()), Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(WriteWork{}, Executor()), Handler,
                WriteInput{std::static_pointer_cast<PendingWriter>(Preview::Transmission::shared_from_this()), Buffer});
        }

        auto WaitStarted() -> Net::awaitable<void>
        {
            co_await Started_.async_receive(Net::use_awaitable);
        }

        auto IsOpen() const -> bool override { return Next_->IsOpen(); }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Gate_.close();
            (void)Next_->Close();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;
            Gate_.close();
            (void)Next_->Cancel();
            return {};
        }

        /** @brief 测试替身显式兑现半关闭；原 Shutdown 沿实际 inner 转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override { Next_->WriteShutdown(std::move(Handler)); }

        [[nodiscard]] auto Canceled() const noexcept -> bool { return Canceled_; }

    private:
        struct ReadInput final
        {
            std::shared_ptr<PendingWriter> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<PendingWriter> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->ReadPartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Bytes, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            const auto Read = co_await Next_->ReadSome(Bytes);
            Error = Preview::Fault::ToNative(Read.Failure);
            co_return Read.Bytes;
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Bytes, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            (void)Started_.try_send(boost::system::error_code{});
            boost::system::error_code GateError;
            co_await Gate_.async_receive(Net::redirect_error(Net::use_awaitable, GateError));
            if (GateError)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            const auto Write = co_await Next_->WriteSome(Bytes);
            Error = Preview::Fault::ToNative(Write.Failure);
            co_return Write.Bytes;
        }
        Preview::SharedTransmission Next_;
        Net::experimental::channel<void(boost::system::error_code)> Started_;
        Net::experimental::channel<void(boost::system::error_code)> Gate_;
        bool Canceled_{false};
    };

    struct WriterFixture final
    {
        Preview::SharedTransmission Client, Server;
        std::shared_ptr<Preview::Contract::MuxSession> Owner;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        std::array<std::byte, 46> Wire{};
        bool Accepted{false}, Read{false};
        std::size_t Writes{0};
        std::exception_ptr Failure;
    };
    class NativeWriteFailureTransmission final : public Preview::Transmission
    {
    public:
        NativeWriteFailureTransmission(Net::any_io_executor Executor, std::error_code Native)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)), Native_(Native) {}
        auto Executor() const -> ExecutorType override { return Executor_; }
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        { Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), Preview::IoResult{}); }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler),
                Preview::IoResult{0U, Preview::Fault::FromNative(Native_)});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), Preview::IoResult{}); }
        auto OnClose() -> ControlResult override { return {}; }
        auto OnCancel() -> ControlResult override { return {}; }
    private:
        Net::any_io_executor Executor_;
        std::error_code Native_;
    };
    struct NativeWriterScenario final
    {
        explicit NativeWriterScenario(Net::any_io_executor Executor)
            : Native(std::make_error_code(std::errc::connection_reset)),
              Stream(std::make_shared<NativeWriteFailureTransmission>(std::move(Executor), Native)),
              Tasks(std::make_shared<Preview::Lifecycle::TaskRegistry>(Stream->Executor())),
              Writer(std::make_shared<Preview::Anytls::Detail::FrameWriter>(Stream, Tasks)) {}
        std::error_code Native;
        std::shared_ptr<NativeWriteFailureTransmission> Stream;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        std::shared_ptr<Preview::Anytls::Detail::FrameWriter> Writer;
        Preview::Anytls::Detail::WriteResult Write;
        bool TasksDrained{false}, CarrierDrained{false}, CloseDelivered{false};
        std::exception_ptr Exception;
    };
    auto RunNativeWriterFailure(std::shared_ptr<NativeWriterScenario> State) -> Net::awaitable<void>
    {
        const auto Data = std::as_bytes(std::span(Payload));
        State->Write = co_await State->Writer->Send({Preview::Anytls::Command::Push, 1,
            std::vector<std::byte>(Data.begin(), Data.end())});
        State->TasksDrained = bool(co_await State->Tasks->Drain());
        State->CloseDelivered = bool(State->Stream->Close());
        const auto Activity = State->Stream->Activity();
        Activity->Seal();
        State->CarrierDrained = bool(co_await Activity->Drain());
    }
    auto WriteOne(std::shared_ptr<Preview::Anytls::Detail::FrameWriter> State, std::uint32_t Id)
        -> Net::awaitable<bool>
    {
        const auto Data = std::as_bytes(std::span(Payload));
        co_return (co_await State->Send({Preview::Anytls::Command::Push, Id,
            std::vector<std::byte>(Data.begin(), Data.end())})).Failure.Succeeded();
    }
    auto WriterServer(std::shared_ptr<WriterFixture> WriterState) -> Net::awaitable<void>
    {
        Preview::Anytls::IngressFactory Factory({.Configuration = {"task-four-secret"},
            .Streams = {.Egress = std::make_shared<Egress>(std::weak_ptr<Fixture>{})}});
        auto Input = MakeStreamAcceptInput(std::move(WriterState->Server), {});
        Input.GenerationUseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Plane = co_await Factory.Accept(std::move(Input));
        WriterState->Accepted = bool(Plane);
        if (!Plane) co_return;
        WriterState->Server = Plane->Transport();
        WriterState->Owner = Plane->Mux()->Session;
        auto Connection = Plane->Transport();
        WriterState->Tasks = std::make_shared<Preview::Lifecycle::TaskRegistry>(Connection->Executor());
        auto State = std::make_shared<Preview::Anytls::Detail::FrameWriter>(Connection, WriterState->Tasks);
        const auto Complete = [WriterState](std::exception_ptr Failure, bool Written)
        {
            if (Written) ++WriterState->Writes;
            if (Failure) WriterState->Failure = Failure;
        };
        Net::co_spawn(Connection->Executor(), WriteOne(State, 1), Complete);
        Net::co_spawn(Connection->Executor(), WriteOne(State, 3), Complete);
    }
    auto WriterClient(std::shared_ptr<WriterFixture> Fixture) -> Net::awaitable<void>
    {
        std::string Auth;
        (void)Preview::Anytls::BuildAuthFrame("task-four-secret", 0, Auth);
        EXPECT_TRUE(co_await WriteAll(Fixture->Client, std::as_bytes(std::span(Auth))));
        Fixture->Read = co_await ReadExact(Fixture->Client, Fixture->Wire);
        (void)Fixture->Client->Close(); (void)Fixture->Server->Close();
    }
}

TEST(AnytlsSessionOwner, FirstTargetFramePreservesLiteralTrailingPayload)
{
    const auto Actual = Scenario(false);
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.Settings);
    EXPECT_TRUE(Actual.SynAck);
    EXPECT_EQ(Actual.TargetReceived, Payload.size());
    EXPECT_TRUE(Actual.Echo);
    ASSERT_TRUE(Actual.RootStatus) << "code=" << static_cast<unsigned>(Actual.RootStatus.error().Code);
    EXPECT_EQ(Actual.Completed, 4);
    EXPECT_FALSE(Actual.Failure);
}
TEST(AnytlsSessionOwner, FragmentedTargetPreservesLiteralTrailingPayload)
{
    const auto Actual = Scenario(true);
    ASSERT_TRUE(Actual.Authenticated);
    ASSERT_TRUE(Actual.Settings);
    EXPECT_TRUE(Actual.SynAck);
    EXPECT_EQ(Actual.TargetReceived, Payload.size());
    EXPECT_TRUE(Actual.Echo);
    ASSERT_TRUE(Actual.RootStatus) << "code=" << static_cast<unsigned>(Actual.RootStatus.error().Code);
    EXPECT_EQ(Actual.Completed, 4);
    EXPECT_FALSE(Actual.Failure);
}

TEST(AnytlsSessionOwner, ConcurrentPartialWritesPreserveWholeLiteralFrames)
{
    Net::io_context Io;
    auto Fixture = std::make_shared<WriterFixture>();
    auto [Client, Server] = Preview::MakeMemoryPair(Io.get_executor());
    Fixture->Client = std::make_shared<Preview::MemoryStream>(std::move(Client));
    Fixture->Server = std::make_shared<PartialWriter>(
        std::make_shared<Preview::MemoryStream>(std::move(Server)));
    const auto Complete = [Fixture](std::exception_ptr Failure) { if (Failure) Fixture->Failure = Failure; };
    Net::co_spawn(Io, WriterServer(Fixture), Complete);
    Net::co_spawn(Io, WriterClient(Fixture), Complete);
    Io.run();
    ASSERT_TRUE(Fixture->Accepted);
    ASSERT_TRUE(Fixture->Read);
    EXPECT_EQ(Fixture->Writes, 2);
    EXPECT_FALSE(Fixture->Failure);
    const auto A = Frame(2, std::as_bytes(std::span(Payload)));
    auto B = A; B[4] = std::byte{3};
    auto AB = A; AB.insert(AB.end(), B.begin(), B.end());
    auto BA = B; BA.insert(BA.end(), A.begin(), A.end());
    EXPECT_TRUE(std::equal(Fixture->Wire.begin(), Fixture->Wire.end(), AB.begin()) ||
                std::equal(Fixture->Wire.begin(), Fixture->Wire.end(), BA.begin()));
    Fixture.reset();
}

TEST(AnytlsSessionOwner, PendingFrameWriterSendCompletesAfterCloseCancellation)
{
    Net::io_context Io;
    auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
    auto Underlying = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
    auto Pending = std::make_shared<PendingWriter>(Underlying);
    auto Tasks = std::make_shared<Preview::Lifecycle::TaskRegistry>(Io.get_executor());
    auto Writer = std::make_shared<Preview::Anytls::Detail::FrameWriter>(Pending, Tasks);
    bool Started = false;
    bool Completed = false;
    Preview::Fault::Failure SendFailure;
    std::exception_ptr Failure;

    auto Send = [&]() -> Net::awaitable<void>
    {
        const auto Data = std::as_bytes(std::span(Payload));
        const auto Result = co_await Writer->Send({Preview::Anytls::Command::Push, 1,
            std::vector<std::byte>(Data.begin(), Data.end())});
        Completed = true;
        SendFailure = Result.Failure;
    };
    auto Close = [&]() -> Net::awaitable<void>
    {
        co_await Pending->WaitStarted();
        Started = true;
        Writer->Close();
        (void)Tasks->Cancel();
    };
    const auto Complete = [&](std::exception_ptr Error)
    {
        if (Error) Failure = std::move(Error);
    };
    Net::co_spawn(Io, Send(), Complete);
    Net::co_spawn(Io, Close(), Complete);
    Io.run();

    EXPECT_TRUE(Started);
    EXPECT_TRUE(Pending->Canceled());
    EXPECT_TRUE(Completed);
    EXPECT_EQ(SendFailure.Code, Preview::Fault::Code::Canceled);
    EXPECT_FALSE(Failure);
    Writer->Close();
    (void)Client->Close();
}

TEST(AnytlsSessionOwner, FrameWriterPreservesNativeWriteFailureThroughDrain)
{
    Net::io_context Io;
    auto State = std::make_shared<NativeWriterScenario>(Io.get_executor());
    Net::co_spawn(Io, RunNativeWriterFailure(State),
        [State](std::exception_ptr Failure) { State->Exception = std::move(Failure); });
    Io.run();

    ASSERT_FALSE(State->Exception);
    EXPECT_EQ(State->Write.Failure.Native, State->Native);
    EXPECT_EQ(State->Write.Failure.Code, Preview::Fault::Code::ConnectionReset);
    EXPECT_EQ(State->Write.PayloadBytes, 0U);
    EXPECT_TRUE(State->TasksDrained);
    EXPECT_TRUE(State->CloseDelivered);
    EXPECT_TRUE(State->CarrierDrained);
}

TEST(AnytlsSessionOwner, RejectsInvalidSettingsAndSynWithTypedAlert)
{
    struct Case final
    {
        InvalidInput Input;
        std::string_view Reason;
    };
    constexpr std::array Cases{
        Case{InvalidInput::DuplicateSettings, "InvalidSettings"},
        Case{InvalidInput::SettingsWithNonzeroStream, "InvalidSettings"},
        Case{InvalidInput::SynWithZeroStream, "InvalidStreamIdOrSettings"},
        Case{InvalidInput::SynWithoutSettings, "InvalidStreamIdOrSettings"},
        Case{InvalidInput::SynWithDuplicateOrBackwardStream, "InvalidStreamIdOrSettings"},
        Case{InvalidInput::SynWithPayload, "InvalidStreamIdOrSettings"}};
    for (const auto &Value : Cases)
    {
        const auto Actual = InvalidScenario(Value.Input);
        ASSERT_FALSE(Actual.Failure);
        ASSERT_TRUE(Actual.Authenticated);
        ASSERT_TRUE(Actual.RootCompleted);
        ASSERT_FALSE(Actual.RootStatus);
        EXPECT_EQ(Actual.RootStatus.error().Code, Preview::Fault::Code::ProtocolError);
        EXPECT_EQ(Actual.AlertCommand, 5U);
        const auto Expected = std::as_bytes(std::span(Value.Reason));
        ASSERT_EQ(Actual.AlertPayload.size(), Expected.size());
        EXPECT_TRUE(std::equal(Actual.AlertPayload.begin(), Actual.AlertPayload.end(), Expected.begin()));
    }
}
