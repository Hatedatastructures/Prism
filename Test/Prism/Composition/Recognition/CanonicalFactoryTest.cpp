/** @file CanonicalFactoryTest.cpp @brief 直接工厂拒绝的最终关闭与委托移交。 */
#include <gtest/gtest.h>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/ActivityGroupFactory.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

#include <expected>

namespace
{
    namespace Net = boost::asio;
    namespace Composition = Prism::Composition::Recognition;
    class ObservedTransport final : public Prism::Transmission
    {
    public:
        explicit ObservedTransport(Prism::SharedTransmission Inner)
            : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner)),
              Activity_(Prism::Transmission::Activity(), Inner_->Activity()) {}
        auto Executor() const -> ExecutorType override { return Inner_->Executor(); }
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override { return Activity_.Activity(); }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->ReadSome(Buffer, std::move(Handler));
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->WriteSome(Buffer, std::move(Handler));
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Inner_->WriteShutdown(std::move(Handler));
        }
        auto IsOpen() const -> bool override { return Inner_->IsOpen(); }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++Cancels;
            return Inner_->Cancel();
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++Closes;
            const auto Result = Inner_->Close();
            if (Result) Activity_.RequireChildDrain();
            return Result;
        }
        int Cancels{0}, Closes{0};
    private:
        Prism::SharedTransmission Inner_;
        Prism::Transport::ForwardActivityOwner Activity_;
    };

    enum class Reject { Empty, NoMatch, Ambiguous, Eof, Vmess, Success, DelegateFailure };

    class FactoryScenario final
    {
    public:
        explicit FactoryScenario(Reject Mode) : Mode_(Mode)
        {
            auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
            Client_ = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
            Observer_ = std::make_shared<ObservedTransport>(
                std::make_shared<Prism::MemoryStream>(std::move(ServerValue)));
            Prepare();
        }

        auto Run() -> Net::awaitable<void>
        {
            std::error_code Error;
            if (Mode_ == Reject::Ambiguous || Mode_ == Reject::Success || Mode_ == Reject::DelegateFailure)
            {
                const std::string Wire = "CONNECT guard.test:443 HTTP/1.1\r\n\r\n";
                const auto Write = co_await Client_->WriteExact(std::as_bytes(std::span(Wire)));
                Error = Prism::Fault::ToNative(Write.Failure);
            }
            else if (Mode_ == Reject::Eof)
            {
                const std::array<std::byte, 1> Wire{std::byte{'C'}};
                const auto Write = co_await Client_->WriteExact(Wire);
                Error = Prism::Fault::ToNative(Write.Failure);
            }
            else if (Mode_ != Reject::Empty)
            {
                const std::array<std::byte, 64> Wire{};
                const auto Write = co_await Client_->WriteExact(Wire);
                Error = Prism::Fault::ToNative(Write.Failure);
            }
            if (Mode_ != Reject::Success && Mode_ != Reject::DelegateFailure)
                (void)co_await Client_->WriteShutdown();
            auto Bytes = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
            auto Result = co_await Factory_->Accept(
                Prism::Contract::StreamAcceptInput{Observer_, {}, std::move(Bytes)});
            if (Mode_ == Reject::Success)
            {
                if (!Result) { ADD_FAILURE() << "HTTP delegate rejected the literal request"; co_return; }
                EXPECT_EQ(Result->Target.Host, *Prism::Network::ParseHost("guard.test"));
                EXPECT_TRUE(Observer_->IsOpen());
                EXPECT_EQ(Observer_->Closes, 0);
                const auto Transport = Result->Transport();
                const auto Activity = Transport->Activity();
                const auto Closed = Transport->Close();
                EXPECT_TRUE(Closed);
                if (!Closed) co_return;
                const auto Drained = co_await Activity->Drain();
                EXPECT_TRUE(Drained);
                EXPECT_TRUE(Activity->IsRetired());
            }
            else EXPECT_FALSE(Result);
            EXPECT_FALSE(Observer_->IsOpen());
            EXPECT_EQ(Observer_->Closes, 1);
            (void)Observer_->Close();
            (void)Client_->Close();
            if (VmessFactory_)
            {
                VmessFactory_->Close();
                const auto Drained = co_await VmessFactory_->Drain();
                EXPECT_TRUE(Drained);
                EXPECT_TRUE(VmessFactory_->IsRetired());
            }
        }

        Net::io_context Io;

    private:
        auto Prepare() -> void
        {
            if (Mode_ == Reject::Vmess)
            {
                VmessFactory_ = Prism::Testing::MakeVmessIngress(
                    Prism::Vmess::ServerConfig{},
                    Prism::Testing::VmessIngressResources{{}, {}, {},
                        Prism::Testing::MakeProtocolIngressUseState(), Io.get_executor()},
                    Prism::Vmess::IngressRoute{});
                Factory_ = VmessFactory_;
                return;
            }
            std::vector<std::shared_ptr<const Composition::CandidateInnerBinding>> Candidates;
            const auto Count = Mode_ == Reject::Empty ? 0U : Mode_ == Reject::Ambiguous ? 2U : 1U;
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                auto Http = Composition::CandidateFactory::MakeHttp(
                    Composition::CandidateOptions{static_cast<std::uint16_t>(Index + 1U), "http"},
                    std::make_shared<Prism::Http11::Binding>(
                        Prism::Http11::PreparedBinding{
                            "canonical-http", {}, Io.get_executor(),
                            Mode_ == Reject::DelegateFailure}));
                if (Mode_ == Reject::DelegateFailure) Http.Spec.Prepare = {};
                auto Binding = std::make_shared<Composition::CandidateInnerBinding>();
                Binding->Spec = std::move(Http.Spec);
                Binding->Accept = std::move(Http.Accept);
                Candidates.push_back(std::move(Binding));
            }
            Factory_ = Composition::MakeInnerProtocolDispatch(std::move(Candidates));
        }

        Reject Mode_;
        std::shared_ptr<Prism::MemoryStream> Client_;
        std::shared_ptr<ObservedTransport> Observer_;
        std::shared_ptr<Prism::Vmess::IngressFactory> VmessFactory_;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory_;
    };

    auto CheckRejection(Reject Mode) -> void
    {
        FactoryScenario Scenario(Mode);
        Prism::Testing::RunCoro(Scenario.Io, [&Scenario]() -> Net::awaitable<void>
        { co_await Scenario.Run(); });
    }

    /** @brief 使用给定 UUID 执行一次真实 VLESS 接入并返回完整 typed 结果。 */
    auto AcceptVlessOnce(const std::shared_ptr<Prism::Vless::IngressFactory>& Factory,
        Net::any_io_executor Executor, const std::array<std::uint8_t, 16>& Uuid)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(std::move(Executor));
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        const auto Wire = Prism::Testing::RecognitionWire::MakeVless(Uuid);
        const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Wire)));
        if (Written.Failure.Failed())
        {
            (void)Client->Close();
            co_return std::unexpected(Written.Failure);
        }
        (void)co_await Client->WriteShutdown();
        auto Accepted = co_await Factory->Accept(Prism::Contract::StreamAcceptInput{
            Inbound, {}, std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{64U * 1024U, 64U}), Factory->GenerationUseState()});
        (void)Client->Close();
        co_return std::move(Accepted);
    }

    /** @brief 错误 UUID 不污染后续成功接入或 binding 的真实物理退休。 */
    class VlessAuthenticationLifecycleScenario final
    {
    public:
        VlessAuthenticationLifecycleScenario()
            : UseState_(Prism::Testing::MakeProtocolIngressUseState())
        {
            Configuration_.uuid = GoodUuid_;
            Factory_ = Prism::Testing::MakeVlessIngress(Configuration_,
                Prism::Testing::ProtocolIngressResources{
                    {}, UseState_, Io.get_executor()}, Prism::Vless::IngressRoute{});
        }

        auto Run() -> Net::awaitable<void>
        {
            auto BadUuid = GoodUuid_;
            BadUuid[0] = 99U;
            const auto Rejected = co_await AcceptVlessOnce(Factory_, Io.get_executor(), BadUuid);
            EXPECT_FALSE(Rejected);
            if (!Rejected)
            {
                EXPECT_EQ(Rejected.error().Code, Prism::Fault::Code::AuthFailed);
            }
            EXPECT_EQ(UseState_->Outstanding(), 0U);
            const auto Accepted = co_await AcceptVlessOnce(Factory_, Io.get_executor(), GoodUuid_);
            EXPECT_TRUE(Accepted);
            EXPECT_EQ(UseState_->Outstanding(), 1U);
            Factory_->Close();
            const auto Drained = co_await Factory_->Drain();
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(Factory_->IsRetired());
            EXPECT_EQ(UseState_->Outstanding(), 0U);
        }

        Net::io_context Io;

    private:
        const std::array<std::uint8_t, 16> GoodUuid_{
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        Prism::Vless::ServerConfig Configuration_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        std::shared_ptr<Prism::Vless::IngressFactory> Factory_;
    };

    TEST(CanonicalFactory, EmptyInnerCandidatesCloseRetainedInbound) { CheckRejection(Reject::Empty); }
    TEST(CanonicalFactory, NoMatchingInnerCandidateClosesRetainedInbound) { CheckRejection(Reject::NoMatch); }
    TEST(CanonicalFactory, AmbiguousInnerCandidatesCloseRetainedInbound) { CheckRejection(Reject::Ambiguous); }
    TEST(CanonicalFactory, InnerEofClosesRetainedInbound) { CheckRejection(Reject::Eof); }
    TEST(CanonicalFactory, VmessStaticFailureClosesRetainedInbound) { CheckRejection(Reject::Vmess); }
    TEST(CanonicalFactory, SuccessfulDelegateKeepsInboundUntilPlaneFinalClose) { CheckRejection(Reject::Success); }
    TEST(CanonicalFactory, RejectingDelegateClosesInboundOnce) { CheckRejection(Reject::DelegateFailure); }
    TEST(CanonicalFactory, AuthenticationFailureDoesNotPoisonLaterAcceptOrRetirement)
    {
        VlessAuthenticationLifecycleScenario Scenario;
        Prism::Testing::RunCoro(Scenario.Io, [&Scenario]() { return Scenario.Run(); });
    }
}
