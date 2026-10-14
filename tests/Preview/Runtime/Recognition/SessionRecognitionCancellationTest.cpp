#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
/**
 * @file SessionRecognitionCancellationTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionRecognitionModeTestSupport.hpp"

namespace
{
    /**
     * @brief 启动 Session owner，并把最终 Fault 交给外部 completion channel。
     */
    auto RunSessionOwner(
        std::shared_ptr<Preview::MemoryStream> Inbound,
        Preview::Runtime::SessionOptions Options,
        Preview::Fault::Code &SessionCode) -> Net::awaitable<void>
    {
        Preview::Runtime::Session Session(std::move(Options));
        SessionCode = (co_await Session.Run(std::move(Inbound))).Code;
    }

    /** @brief 记录 Session owner 首异常并发布唯一完成通知。 */
    struct SessionRunCompletion final
    {
        std::shared_ptr<CodeChannel> SessionDone;
        Preview::Fault::Code &SessionCode;

        auto operator()(std::exception_ptr Failure) const -> void
        {
            if (Failure)
            {
                SessionCode = Preview::Fault::Code::IoError;
            }
            (void)SessionDone->try_send(boost::system::error_code{}, SessionCode);
        }
    };

    /** @brief 阻塞 recognition prepare，等待取消测试释放并发布完成通知。 */
    struct CancellationPrepareOperation final
    {
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Entered;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Release;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Completed;

        auto operator()(Core::PrepareContext Context) const
            -> Net::awaitable<Core::PrepareResult>
        {
            (void)Context;
            (void)Entered->try_send(boost::system::error_code{});
            boost::system::error_code Error;
            co_await Release->async_receive(Net::redirect_error(Net::use_awaitable, Error));
            (void)Completed->try_send(boost::system::error_code{});
            Core::PrepareResult Result;
            Result.Status = Core::RecognitionStatus::Accepted;
            co_return Result;
        }
    };

    /**
     * @brief 持有 cancellation admission 场景的全部 channel、transport 和观察结果。
     */
    struct SessionCancellationRequest final
    {
        Net::io_context &Io;
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Inbound;
        std::shared_ptr<Preview::Runtime::SessionControl> Control;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> PrepareEntered;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> ReleasePrepare;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> PrepareCompleted;
        std::shared_ptr<CodeChannel> SessionDone;
        Preview::Runtime::SessionOptions Options;
        Preview::Fault::Code &SessionCode;
        bool &TimedOut;
    };

    auto RunSessionCancellationScenario(SessionCancellationRequest Request)
        -> Net::awaitable<void>
    {
        Net::co_spawn(
            Request.Io,
            RunSessionOwner(Request.Inbound, std::move(Request.Options), Request.SessionCode),
            SessionRunCompletion{Request.SessionDone, Request.SessionCode});

        std::array<std::byte, 1> Prefix{std::byte{0x42}};
        std::error_code WriteError;
        co_await Request.Client->async_write_some(Prefix, WriteError);

        boost::system::error_code EnteredError;
        co_await Request.PrepareEntered->async_receive(
            Net::redirect_error(Net::use_awaitable, EnteredError));
        Request.Control->Cancel();
        (void)Request.ReleasePrepare->try_send(boost::system::error_code{});

        Net::steady_timer Watchdog(Request.Io);
        Watchdog.expires_after(std::chrono::seconds(2));
        boost::system::error_code DoneError;
        using Net::experimental::awaitable_operators::operator||;
        auto Race = co_await (
            Request.SessionDone->async_receive(Net::redirect_error(Net::use_awaitable, DoneError)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Race.index() == 1U)
        {
            Request.TimedOut = true;
            Request.Inbound->Close();
        }
        boost::system::error_code PrepareError;
        co_await Request.PrepareCompleted->async_receive(
            Net::redirect_error(Net::use_awaitable, PrepareError));
    }
}

TEST(SessionRecognitionMode, MixedTrialProfileResolvesAuthenticatedWinner)
    {
        const auto GoodUuid = Preview::Testing::RecognitionWire::MakeUuid(31);
        auto UseState = Preview::Testing::MakeProtocolIngressUseState();
        std::vector<Composition::CandidateBinding> Bindings;
        Bindings.push_back(Preview::Testing::MakeVlessCandidate(
            Preview::Composition::Recognition::CandidateOptions{18},
            Preview::Vless::ServerConfig{GoodUuid}, UseState));
        Bindings.push_back(Preview::Testing::MakeVmessCandidate(
            Preview::Composition::Recognition::CandidateOptions{19},
            Preview::Vmess::ServerConfig{Preview::Testing::RecognitionWire::MakeUuid(32)}, UseState));
        auto Options = MakeMixedOptions(std::move(Bindings));
        const auto Flow = [GoodUuid](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunVlessClient(std::move(Client), Preview::Vless::ClientConfig{GoodUuid});
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, DeterministicProfileResolvesByStructuralSelector)
    {
        std::vector<Composition::CandidateBinding> Bindings;
        Bindings.push_back(Composition::CandidateFactory::MakeHttp(Preview::Composition::Recognition::CandidateOptions{20}));
        Bindings.push_back(Composition::CandidateFactory::MakeSocks5(Composition::CandidateOptions{21}, Preview::Testing::MakeSocks5Binding({})));
        auto Options = MakeDeterministicOptions(std::move(Bindings));
        const auto Flow = [](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunSocks5Client(std::move(Client), Preview::Socks5::ClientConfig{});
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, WrongTypedSs2022PskDoesNotReachResolver)
    {
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x61);
        Preview::Shadowsocks2022::ServerConfig Config;
        Config.Psk = Preview::Testing::RecognitionWire::MakePsk(0x62);
        auto Options = MakeConfiguredOptions(Composition::CandidateFactory::MakeSs2022(Composition::CandidateOptions{17}, Preview::Testing::MakeSs2022Binding(Config)));
        const auto Flow = [Psk](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunSs2022Client(std::move(Client), Psk);
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_NE(Result.SessionCode, Preview::Fault::Code::Success);
        EXPECT_EQ(Result.ResolverCalls, 0U);
    }

TEST(SessionRecognitionMode, SessionCancellationStopsRecognitionBeforeAccept)
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto PrepareEntered = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        auto ReleasePrepare = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        auto PrepareCompleted = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        auto SessionDone = std::make_shared<CodeChannel>(Io.get_executor(), 1);
        auto AcceptCalls = std::make_shared<std::size_t>(0);

        Composition::CandidateBinding Binding;
        Binding.Spec.Id = 60;
        Binding.Spec.Name = "blocked-opaque";
        Binding.Spec.Protocol = Preview::Contract::ProtocolType::Http;
        Binding.Spec.Kind = Core::CandidateKind::Opaque;
        Binding.Spec.FirstBytes = {0x42U};
        Binding.Spec.MinimumBytes = 1;
        Binding.Spec.RequiresAuthentication = true;
        Binding.Spec.Inspect = [](const Core::ProbeSnapshot &) { return Core::MatchState::Structural; };
        Binding.Spec.Prepare = CancellationPrepareOperation{
            PrepareEntered, ReleasePrepare, PrepareCompleted};
        Binding.Spec.Commit = [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Binding.Accept = std::make_shared<Preview::Testing::StreamFactory>([AcceptCalls](Preview::SharedTransmission Inbound, Preview::Contract::RequestMetadata)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            ++*AcceptCalls;
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{std::move(Inbound)};
            co_return Plane;
        });
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding));
        ASSERT_TRUE(Built.has_value());

        Preview::Runtime::SessionOptions Options;
        Options.Control = Control;
        Options.Services->Profile = Built->Profile;
        Options.Services->ResolveCandidate = Built->Resolver;

        Preview::Fault::Code SessionCode = Preview::Fault::Code::IoError;
        bool TimedOut = false;
        Preview::Testing::RunCoro(
            Io,
            RunSessionCancellationScenario(SessionCancellationRequest{
                Io, Client, Inbound, Control, PrepareEntered, ReleasePrepare,
                PrepareCompleted, SessionDone, std::move(Options), SessionCode, TimedOut}));

        EXPECT_FALSE(TimedOut);
        EXPECT_EQ(SessionCode, Preview::Fault::Code::Canceled);
        EXPECT_EQ(*AcceptCalls, 0U);
    }

TEST(SessionNativeTls, FallbackDeadlineCoversHandshakeAfterCompleteClientHello)
    {
        Net::io_context Io;
        auto ClientHello = MakeTls13ClientHello();
        ASSERT_FALSE(ClientHello.empty());

        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
        Raw->ToRead = std::move(ClientHello);
        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->NativeTls = MakeSessionNativeTlsContext();
        Services->HandshakeTimeout = std::chrono::milliseconds(20);

        auto AcceptCalls = std::make_shared<std::size_t>(0);
        const auto Accept = std::make_shared<Preview::Testing::StreamFactory>(
            std::bind_front(CountSessionNativeTlsAccept, AcceptCalls));
        Services->AcceptProtocol = Accept;
        Preview::Runtime::SessionOptions Options;
        Options.Services = Services;
        Options.Services->AcceptProtocol = Accept;
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
        auto Done = std::make_shared<CodeChannel>(Io.get_executor(), 1);
        auto Result = std::make_shared<SessionNativeTlsProbeResult>();

        Preview::Testing::RunCoro(
            Io,
            RunSessionNativeTlsProbe(SessionNativeTlsProbeRequest{
                Io.get_executor(), Session, Raw, Done, Result}));

        EXPECT_TRUE(Result->CompletedBeforeWatchdog);
        EXPECT_TRUE(Result->SessionCompleted);
        EXPECT_EQ(Result->Code, Preview::Fault::Code::Timeout);
        EXPECT_FALSE(Raw->IsOpen());
        EXPECT_FALSE(Raw->Written.empty());
        EXPECT_EQ(*AcceptCalls, 0U);
    }
