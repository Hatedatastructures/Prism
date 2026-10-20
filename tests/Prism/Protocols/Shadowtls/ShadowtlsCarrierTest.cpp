/**
 * @file ShadowtlsCarrierTest.cpp
 * @brief ShadowTLS server-side Composition carrier 的真实 wire/transport 测试。
 */

#include <Prism/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Prism/Composition/Recognition/TlsCarrierHelpers.hpp>
#include <Prism/Protocols/Shadowtls/Detail/CarrierWire.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Conn.hpp>
#include <Prism/Protocols/Shadowtls/Detail/RecordProtector.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Retirement.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <exception>
#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Recognition = Prism::Composition::Recognition;
    namespace Core = Prism::Recognition;
    namespace Net = boost::asio;
    namespace Shadowtls = Prism::Shadowtls;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;
    auto ErrorOf(const Shadowtls::Failure &Failure) -> Error
    {
        const auto Native = boost::system::error_code(Failure.Native);
        if (&Native.category() == &Prism::ErrorCategory())
            return static_cast<Error>(Native.value());
        return Shadowtls::ToProtocolError(Failure.Code);
    }

    template <class Value>
    auto ErrorOf(const Shadowtls::Result<Value> &Outcome) -> Error
    {
        if (Outcome)
        {
            return Error::None;
        }
        return ErrorOf(Outcome.error());
    }

    auto RetireTransport(SharedTransmission Transport) -> Net::awaitable<void>
    {
        auto Retired = co_await Shadowtls::Detail::TransportRetirement::RetireAndDrain(
            std::move(Transport));
        EXPECT_EQ(ErrorOf(Retired), Error::None);
    }

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &Context, Awaitable Task) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            std::move(Task),
            [&](std::exception_ptr ErrorValue)
            {
                Failure = std::move(ErrorValue);
                Context.stop();
            });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    [[nodiscard]] auto MakeClientHelloTemplate() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(75, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0;
        Hello[68] = 2;
        Hello[69] = 0x13;
        Hello[70] = 0x01;
        Hello[71] = 1;
        Hello[72] = 0;
        Hello[73] = 0;
        Hello[74] = 0;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = Shadowtls::HsTypeClienthello;
        Record[7] = 0;
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        return Record;
    }

    [[nodiscard]] auto MakeServerHello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(78, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x80 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0x13;
        Hello[68] = 0x01;
        Hello[69] = 0;
        Hello[70] = 0;
        Hello[71] = 6;
        Hello[72] = 0;
        Hello[73] = 43;
        Hello[74] = 0;
        Hello[75] = 2;
        Hello[76] = 3;
        Hello[77] = 4;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = 2;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        return Record;
    }

    [[nodiscard]] auto ReadExactBytes(const SharedTransmission &Transport,
                                      std::span<std::uint8_t> Buffer)
        -> Net::awaitable<Shadowtls::Result<std::size_t>>
    {
        std::optional<Shadowtls::Failure> PendingTerminal;
        co_return co_await Shadowtls::Detail::Io::ReadExact(
            Transport, Buffer, PendingTerminal);
    }

    [[nodiscard]] auto WriteAllBytes(const SharedTransmission &Transport,
                                     std::span<const std::uint8_t> Buffer)
        -> Net::awaitable<Shadowtls::Result<std::size_t>>
    {
        co_return co_await Shadowtls::Detail::Io::SendBytes(Transport, Buffer);
    }

    [[nodiscard]] auto ReadRecord(const SharedTransmission &Transport,
                                  std::vector<std::uint8_t> &Record)
        -> Net::awaitable<Shadowtls::Result<void>>
    {
        std::array<std::uint8_t, Shadowtls::TlsHdrsize> Header{};
        const auto HeaderResult = co_await ReadExactBytes(Transport, Header);
        if (!HeaderResult) co_return std::unexpected(HeaderResult.error());
        const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
        Record.resize(Shadowtls::TlsHdrsize + Length);
        std::copy(Header.begin(), Header.end(), Record.begin());
        const auto PayloadResult = co_await ReadExactBytes(
            Transport, std::span<std::uint8_t>(Record).subspan(Shadowtls::TlsHdrsize));
        if (!PayloadResult)
        {
            auto Failure = PayloadResult.error();
            Failure.Bytes += Header.size();
            co_return std::unexpected(Failure);
        }
        co_return Shadowtls::Result<void>{};
    }

    struct CarrierTargetRequest final
    {
        SharedTransmission TargetClient;
        std::vector<std::uint8_t> ServerHello;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        std::shared_ptr<std::vector<std::uint8_t>> Observed;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    /** @brief 处理 ShadowTLS carrier 的真实 target server hello 和关闭。 */
    auto RunCarrierTarget(CarrierTargetRequest Request) -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Forwarded;
        const auto ClientHello = co_await ReadRecord(Request.TargetClient, Forwarded);
        if (!ClientHello)
        {
            *Request.Failure = std::make_exception_ptr(
                std::runtime_error("ShadowTLS target ClientHello read failed"));
            co_return;
        }
        *Request.Observed = Forwarded;
        const auto ServerHello = co_await WriteAllBytes(Request.TargetClient, Request.ServerHello);
        if (!ServerHello)
        {
            *Request.Failure = std::make_exception_ptr(
                std::runtime_error("ShadowTLS target ServerHello write failed"));
            co_return;
        }
        std::array<std::byte, 1> Buffer{};
        const auto CloseRead = co_await Request.TargetClient->ReadSome(Buffer);
        (void)CloseRead;
    }

    struct CarrierTargetLaunchRequest final
    {
        SharedTransmission Target;
        SharedTransmission TargetClient;
        std::vector<std::uint8_t> ServerHello;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        std::shared_ptr<std::vector<std::uint8_t>> Observed;
        std::shared_ptr<std::exception_ptr> Failure;
        std::shared_ptr<bool> Started;
    };

    /** @brief 启动 target coroutine，成功提交后才发布 Started。 */
    auto LaunchCarrierTarget(CarrierTargetLaunchRequest Request)
        -> Net::awaitable<Shadowtls::Result<SharedTransmission>>
    {
        try
        {
            Net::co_spawn(Request.TargetClient->Executor(), RunCarrierTarget(CarrierTargetRequest{
                Request.TargetClient,
                Request.ServerHello,
                Request.Done,
                Request.Observed,
                Request.Failure}),
                [Done = Request.Done, Failure = Request.Failure](std::exception_ptr ErrorValue)
                {
                    if (ErrorValue)
                    {
                        *Failure = ErrorValue;
                    }
                    (void)Done->try_send(boost::system::error_code{});
                });
            *Request.Started = true;
        }
        catch (...)
        {
            *Request.Failure = std::current_exception();
        }
        co_return Request.Target;
    }

    struct CarrierAuthenticatedRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        SharedTransmission Target;
        SharedTransmission TargetClient;
        std::string Password;
        std::vector<std::uint8_t> ServerHello;
        std::vector<std::uint8_t> ClientPayload;
        std::vector<std::uint8_t> ServerPayload;
    };

    struct AuthenticatedCarrierResultRequest final
    {
        CarrierAuthenticatedRequest Request;
        std::shared_ptr<Shadowtls::Detail::Conn<>> ClientConnection;
        std::vector<std::uint8_t> ClientHelloWire;
        Core::CarrierAcceptResult Result;
        std::shared_ptr<std::vector<std::uint8_t>> TargetObserved;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> TargetDone;
        std::shared_ptr<bool> TargetStarted;
        std::shared_ptr<std::exception_ptr> TargetFailure;
    };

    /** @brief 关闭 carrier 场景的全部 endpoint，供失败分支回收已拥有资源。 */
    auto CloseCarrierEndpoints(const CarrierAuthenticatedRequest &Request, SharedTransmission ClientOwner)
        -> Net::awaitable<void>
    {
        if (ClientOwner) co_await RetireTransport(std::move(ClientOwner));
        else co_await RetireTransport(Request.Client);
        co_await RetireTransport(Request.Server);
        co_await RetireTransport(Request.Target);
        co_await RetireTransport(Request.TargetClient);
    }

    /** @brief 只等待已经由 DialTarget 启动的 target 协程。 */
    auto WaitForStartedTarget(
        const std::shared_ptr<bool> &Started,
        const std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> &Done,
        const std::shared_ptr<std::exception_ptr> &Failure)
        -> Net::awaitable<void>
    {
        if (*Started)
        {
            (void)co_await Done->async_receive(Net::use_awaitable);
        }
        if (*Failure)
        {
            ADD_FAILURE() << "ShadowTLS target completion failed";
            std::rethrow_exception(*Failure);
        }
    }

    /** @brief 将 Accept completion 中保存的首个异常转回当前测试协程。 */
    auto RethrowCompletionFailure(
        const std::shared_ptr<std::exception_ptr> &Failure,
        std::string_view Label) -> void
    {
        if (*Failure)
        {
            ADD_FAILURE() << Label;
            std::rethrow_exception(*Failure);
        }
    }

    struct CarrierAcceptLaunchRequest final
    {
        Recognition::CarrierAcceptFn Accept;
        SharedTransmission Server;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        std::shared_ptr<std::optional<Core::CarrierAcceptResult>> Result;
    };

    /** @brief 执行 carrier Accept，并让外层 completion handler 唯一通知退出。 */
    auto LaunchCarrierAccept(CarrierAcceptLaunchRequest Request)
        -> Net::awaitable<void>
    {
        *Request.Result = co_await Request.Accept(Core::CarrierAcceptInput{Request.Server, {}});
    }

    /** @brief 验证唯一接入结果、双向 inner payload 与各 endpoint 的真实回收。 */
    auto VerifyAuthenticatedCarrierResult(AuthenticatedCarrierResultRequest Request)
        -> Net::awaitable<void>
    {
        auto &Result = Request.Result;
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Result.Metadata.Carrier, "shadowtls");
        const auto HasTransport = static_cast<bool>(Result.Transport);
        EXPECT_TRUE(HasTransport);
        if (!HasTransport)
        {
            co_await CloseCarrierEndpoints(Request.Request, Request.ClientConnection);
            co_await WaitForStartedTarget(Request.TargetStarted, Request.TargetDone, Request.TargetFailure);
            co_return;
        }
        EXPECT_EQ(*Request.TargetObserved, Request.ClientHelloWire);
        std::array<std::byte, 32> ServerReadBuffer{};
        const auto ServerRead = co_await Result.Transport->ReadSome(ServerReadBuffer);
        EXPECT_FALSE(ServerRead.Failure.Failed());
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(ServerReadBuffer.data()),
                      reinterpret_cast<const std::uint8_t *>(ServerReadBuffer.data()) + ServerRead.Bytes),
                  Request.Request.ClientPayload);
        const auto ServerWritten = co_await Result.Transport->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Request.ServerPayload.data()),
                                       Request.Request.ServerPayload.size()));
        EXPECT_FALSE(ServerWritten.Failure.Failed());
        EXPECT_EQ(ServerWritten.Bytes, Request.Request.ServerPayload.size());
        std::array<std::byte, 32> ClientReadBuffer{};
        const auto ClientRead = co_await Request.ClientConnection->ReadSome(ClientReadBuffer);
        EXPECT_FALSE(ClientRead.Failure.Failed());
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(ClientReadBuffer.data()),
                      reinterpret_cast<const std::uint8_t *>(ClientReadBuffer.data()) + ClientRead.Bytes),
                  Request.Request.ServerPayload);
        co_await RetireTransport(Result.Transport);
        co_await RetireTransport(Request.ClientConnection);
        co_await WaitForStartedTarget(Request.TargetStarted, Request.TargetDone, Request.TargetFailure);
        co_await RetireTransport(Request.Request.Target);
    }

    /** @brief 驱动真实 ShadowTLS carrier 认证、HMAC、inner transport 和 peer close。 */
    auto RunAuthenticatedCarrier(CarrierAuthenticatedRequest Request) -> Net::awaitable<void>
    {
        const auto TargetDone = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Request.Client->Executor(), 1);
        const auto TargetObserved = std::make_shared<std::vector<std::uint8_t>>();
        const auto TargetStarted = std::make_shared<bool>(false);
        const auto TargetFailure = std::make_shared<std::exception_ptr>();
        Shadowtls::ServerOptions Options;
        Options.DialTarget = [Target = Request.Target, TargetClient = Request.TargetClient,
                              ServerHello = Request.ServerHello, TargetDone, TargetObserved,
                              TargetStarted, TargetFailure](std::span<const std::uint8_t>)
            -> Net::awaitable<Shadowtls::Result<SharedTransmission>>
        {
            co_return co_await LaunchCarrierTarget(CarrierTargetLaunchRequest{
                Target, TargetClient, ServerHello, TargetDone, TargetObserved, TargetFailure, TargetStarted});
        };
        auto Accept = Recognition::MakeShadowtlsServerAccept(
            std::move(Options), Shadowtls::ServerConfig{Request.Password});
        const auto AcceptDone = std::make_shared<Net::experimental::channel<void(
            boost::system::error_code)>>(Request.Client->Executor(), 1);
        const auto AcceptResult = std::make_shared<std::optional<Core::CarrierAcceptResult>>();
        const auto AcceptFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(Request.Client->Executor(), LaunchCarrierAccept(
            CarrierAcceptLaunchRequest{Accept, Request.Server, AcceptDone, AcceptResult}),
            [AcceptDone, AcceptFailure](std::exception_ptr ErrorValue)
            {
                if (ErrorValue)
                {
                    *AcceptFailure = ErrorValue;
                }
                (void)AcceptDone->try_send(boost::system::error_code{});
            });
        auto ClientConnection = std::make_shared<Shadowtls::Detail::Conn<>>(
            Request.Client, Request.Password);
        const auto ClientHandshake = co_await ClientConnection->WriteStandardHandshake(
            MakeClientHelloTemplate());
        const auto ClientError = ErrorOf(ClientHandshake);
        auto ClientHelloWire = ClientConnection->TakeClientHelloWire();
        if (ClientError != Error::None)
        {
            ClientConnection.reset();
        }
        EXPECT_EQ(ClientError, Error::None);
        EXPECT_TRUE(ClientConnection);
        if (!ClientConnection)
        {
            co_await CloseCarrierEndpoints(Request, {});
            (void)co_await AcceptDone->async_receive(Net::use_awaitable);
            co_await WaitForStartedTarget(TargetStarted, TargetDone, TargetFailure);
            co_return;
        }
        auto ClientTransport = std::static_pointer_cast<Prism::Transmission>(ClientConnection);
        Request.Client->SetTimeout(std::chrono::milliseconds(1000));
        std::vector<std::uint8_t> ReceivedServerHello;
        const auto ServerHelloRead = co_await ReadRecord(ClientTransport, ReceivedServerHello);
        EXPECT_TRUE(ServerHelloRead);
        if (!ServerHelloRead)
        {
            co_await CloseCarrierEndpoints(Request, ClientConnection);
            co_await WaitForStartedTarget(TargetStarted, TargetDone, TargetFailure);
            co_return;
        }
        EXPECT_EQ(ReceivedServerHello, Request.ServerHello);
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom{};
        std::copy(Request.ServerHello.begin() + 11,
                  Request.ServerHello.begin() + 11 + ServerRandom.size(), ServerRandom.begin());
        EXPECT_EQ(ErrorOf(ClientConnection->EnableRecordProtection(ServerRandom)), Error::None);
        const auto Written = co_await ClientConnection->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.ClientPayload.data()),
                                       Request.ClientPayload.size()));
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, Request.ClientPayload.size());
        co_await AcceptDone->async_receive(Net::use_awaitable);
        RethrowCompletionFailure(AcceptFailure, "ShadowTLS carrier Accept completion failed");
        const auto HasAcceptResult = AcceptResult->has_value();
        EXPECT_TRUE(HasAcceptResult);
        if (!HasAcceptResult)
        {
            co_await CloseCarrierEndpoints(Request, ClientConnection);
            co_await WaitForStartedTarget(TargetStarted, TargetDone, TargetFailure);
            co_return;
        }
        co_await VerifyAuthenticatedCarrierResult(AuthenticatedCarrierResultRequest{
            Request, std::move(ClientConnection), std::move(ClientHelloWire),
            std::move(**AcceptResult), TargetObserved, TargetDone, TargetStarted, TargetFailure});
    }

    /** @brief 四个工厂失败路径共用的原生错误和最终关闭观察。 */
    struct FactoryFailureProbe final
    {
        FactoryFailureProbe(Net::any_io_executor Domain, std::error_code Error)
            : Executor(std::move(Domain)), Native(std::move(Error))
        {
        }

        Net::any_io_executor Executor;
        std::error_code Native;
        std::atomic<std::size_t> CancelCalls{0};
        std::atomic<std::size_t> CloseCalls{0};
        std::atomic<std::size_t> DrainCalls{0};
    };

    /** @brief 记录 factory retirement 是否等待了真实 carrier activity。 */
    class FactoryFailureActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        FactoryFailureActivity(
            std::shared_ptr<FactoryFailureProbe> Probe,
            std::shared_ptr<Prism::Contract::CarrierActivity> Inner)
            : Probe_(std::move(Probe)), Inner_(std::move(Inner))
        {
        }

        auto Seal() noexcept -> void override { Inner_->Seal(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Inner_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Inner_->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            ++Probe_->DrainCalls;
            co_return co_await Inner_->Drain();
        }

    private:
        std::shared_ptr<FactoryFailureProbe> Probe_;
        std::shared_ptr<Prism::Contract::CarrierActivity> Inner_;
    };

    /** @brief 每个方向用同一个原生错误失败，并记录取消、关闭与 activity drain。 */
    class FactoryFailureTransport final : public Prism::Transmission
    {
    public:
        explicit FactoryFailureTransport(std::shared_ptr<FactoryFailureProbe> Probe)
            : Transmission(Probe->Executor), Probe_(std::move(Probe)),
              Activity_(std::make_shared<FactoryFailureActivity>(Probe_, Prism::Transmission::Activity()))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        auto IsOpen() const -> bool override { return true; }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                {0, Prism::Fault::FromNative(Probe_->Native)});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                {0, Prism::Fault::FromNative(Probe_->Native)});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{});
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++Probe_->CancelCalls;
            return {};
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++Probe_->CloseCalls;
            return {};
        }

    private:
        std::shared_ptr<FactoryFailureProbe> Probe_;
        std::shared_ptr<FactoryFailureActivity> Activity_;
    };

    /** @brief 四个 typed factory 均须保留主 Native/progress 并完成唯一 owner retirement。 */
    template <class Value>
    auto VerifyFactoryFailure(
        const Shadowtls::Result<Value> &Outcome,
        const std::shared_ptr<FactoryFailureProbe> &Probe,
        const std::weak_ptr<FactoryFailureTransport> &Weak) -> void
    {
        ASSERT_FALSE(Outcome);
        EXPECT_EQ(Outcome.error().Code, Prism::Fault::ToCode(Probe->Native));
        EXPECT_EQ(Outcome.error().Native, Probe->Native);
        EXPECT_EQ(Outcome.error().Bytes, 0U);
        EXPECT_GT(Probe->CancelCalls.load(), 0U);
        EXPECT_GT(Probe->CloseCalls.load(), 0U);
        EXPECT_GT(Probe->DrainCalls.load(), 0U);
        EXPECT_TRUE(Weak.expired());
    }

    auto CheckConnectFailure(std::shared_ptr<FactoryFailureProbe> Probe)
        -> Net::awaitable<void>
    {
        const Shadowtls::ClientConfig Config{"factory-password"};
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom{}, ClientRandom{};
        auto Upstream = std::make_shared<FactoryFailureTransport>(Probe);
        const std::weak_ptr<FactoryFailureTransport> Weak = Upstream;
        const auto Outcome = co_await Shadowtls::Connect(
            Shadowtls::ConnectParameters{std::move(Upstream), Config, ServerRandom, ClientRandom});
        Upstream.reset();
        VerifyFactoryFailure(Outcome, Probe, Weak);
    }

    auto CheckConnectStandardFailure(std::shared_ptr<FactoryFailureProbe> Probe)
        -> Net::awaitable<void>
    {
        const Shadowtls::ClientConfig Config{"factory-password"};
        const auto ClientHello = MakeClientHelloTemplate();
        auto Upstream = std::make_shared<FactoryFailureTransport>(Probe);
        const std::weak_ptr<FactoryFailureTransport> Weak = Upstream;
        const auto Outcome = co_await Shadowtls::ConnectStandard(
            Shadowtls::StandardConnectParameters{std::move(Upstream), Config, ClientHello});
        Upstream.reset();
        VerifyFactoryFailure(Outcome, Probe, Weak);
    }

    auto CheckAcceptFailure(std::shared_ptr<FactoryFailureProbe> Probe)
        -> Net::awaitable<void>
    {
        const Shadowtls::ServerConfig Config{"factory-password"};
        auto Upstream = std::make_shared<FactoryFailureTransport>(Probe);
        const std::weak_ptr<FactoryFailureTransport> Weak = Upstream;
        const auto Outcome = co_await Shadowtls::Accept(std::move(Upstream), Config);
        Upstream.reset();
        VerifyFactoryFailure(Outcome, Probe, Weak);
    }

    auto CheckAcceptStandardFailure(std::shared_ptr<FactoryFailureProbe> Probe)
        -> Net::awaitable<void>
    {
        const Shadowtls::ServerConfig Config{"factory-password"};
        auto Upstream = std::make_shared<FactoryFailureTransport>(Probe);
        const std::weak_ptr<FactoryFailureTransport> Weak = Upstream;
        const auto Outcome = co_await Shadowtls::AcceptStandard(std::move(Upstream), Config);
        Upstream.reset();
        VerifyFactoryFailure(Outcome, Probe, Weak);
    }

    auto CheckAllFactoryFailures() -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        co_await CheckConnectFailure(std::make_shared<FactoryFailureProbe>(Executor, Native));
        co_await CheckConnectStandardFailure(std::make_shared<FactoryFailureProbe>(Executor, Native));
        co_await CheckAcceptFailure(std::make_shared<FactoryFailureProbe>(Executor, Native));
        co_await CheckAcceptStandardFailure(std::make_shared<FactoryFailureProbe>(Executor, Native));
    }

    TEST(ShadowtlsCarrier, TypedFactoriesRetireFailedHandshakesAndPreserveNativeProgress)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        const auto Owner = Prism::Executor::ContextOwner::Create(Storage);
        RunCoroutine(Owner->Io, CheckAllFactoryFailures());
        EXPECT_EQ(Storage->Pending(), 0U);
    }
    TEST(ShadowtlsCarrier, RequiresTargetDialBeforeReportingWireReady)
    {
        Recognition::ShadowtlsCarrierOptions Options;
        Options.HandshakeDest = "example.com:443";
        Options.Password = "carrier-password";
        const auto Accept = Recognition::MakeConfiguredShadowtlsServerAccept(std::move(Options));
        ASSERT_FALSE(Accept);
        EXPECT_EQ(Accept.error(), Recognition::ShadowtlsCarrierBuildError::MissingDial);
    }

    TEST(ShadowtlsCarrier, AcceptsAuthenticatedWireAndReturnsProtectedTransport)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        auto [TargetEndpoint, TargetClientEndpoint] = MakeMemoryPair(Context.get_executor());
        const auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        const auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        const auto Target = std::make_shared<MemoryStream>(std::move(TargetEndpoint));
        const auto TargetClient = std::make_shared<MemoryStream>(std::move(TargetClientEndpoint));
        const auto ServerHello = MakeServerHello();
        const auto Password = std::string{"carrier-password"};
        const auto ClientPayload = std::vector<std::uint8_t>{0x31, 0x32, 0x33, 0x34};
        const auto ServerPayload = std::vector<std::uint8_t>{0xa1, 0xa2, 0xa3};

        RunCoroutine(Context, RunAuthenticatedCarrier(CarrierAuthenticatedRequest{
            Client, Server, Target, TargetClient, Password, ServerHello,
            ClientPayload, ServerPayload}));
    }

} // namespace
