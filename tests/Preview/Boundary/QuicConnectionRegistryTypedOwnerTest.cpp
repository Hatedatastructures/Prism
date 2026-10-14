/**
 * @file QuicConnectionRegistryTypedOwnerTest.cpp
 * @brief QUIC typed ingress selection 与 connection-generation owner 合同。
 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <Preview/Contract/Ingress/DatagramIngressSelection.hpp>
#include <Preview/Contract/Ingress/QuicConnection.hpp>
#include <Preview/Contract/Ingress/RawDatagramIngress.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <TestSupport/Preview/QuicFactory.hpp>

namespace
{
    namespace Net = boost::asio;
    using BoundaryPacket = Preview::Boundary::BoundaryPacket;
    using Registry = Preview::Boundary::QuicConnectionRegistry;
    using Udp = Net::ip::udp;
    using GenerationUse = Preview::Contract::QuicConnectionGenerationLease;

    /** @brief 保留一次 admission 的 generation-use 与 owner-close 通知。 */
    class TypedConnectionOwner final : public Preview::Contract::QuicConnectionOwner
    {
    public:
        TypedConnectionOwner(
            GenerationUse Use,
            std::function<void()> OnClosed,
            Preview::GenerationId MetadataGeneration)
            : Use_(std::move(Use)), OnClosed_(std::move(OnClosed)),
              MetadataGeneration_(MetadataGeneration)
        {
        }

        auto Start() -> void override { Started_ = true; }

        [[nodiscard]] auto ReceivePacket(
            std::span<const std::byte>,
            const Udp::endpoint&) -> bool override
        {
            return Started_ && !Closed_;
        }

        [[nodiscard]] auto State() const noexcept
            -> Preview::Contract::QuicConnectionState override
        {
            return {false, Closed_};
        }

        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (!Closed_)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            Use_ = {};
            auto OnClosed = std::move(OnClosed_);
            if (OnClosed)
            {
                OnClosed();
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Use_.Generation();
        }

        [[nodiscard]] auto BindingId() const noexcept -> std::string_view
        {
            return Use_.BindingId();
        }

        [[nodiscard]] auto MetadataGeneration() const noexcept -> Preview::GenerationId
        {
            return MetadataGeneration_;
        }

        [[nodiscard]] auto HasGenerationUse() const noexcept -> bool
        {
            return static_cast<bool>(Use_);
        }

    private:
        GenerationUse Use_;
        std::function<void()> OnClosed_;
        Preview::GenerationId MetadataGeneration_;
        bool Started_{false};
        bool Closed_{false};
    };

    /** @brief 将 typed factory request 的 move-only generation owner 移入连接。 */
    class TypedConnectionFactory final : public Preview::Contract::QuicConnectionFactory
    {
    public:
        [[nodiscard]] auto Create(Preview::Contract::QuicAcceptRequest Request)
            -> std::expected<Preview::Contract::QuicConnectionLease,
                Preview::Contract::ProviderFailure> override
        {
            auto Owner = std::make_shared<TypedConnectionOwner>(
                std::move(Request.GenerationUse), std::move(Request.OnClosed),
                Request.Metadata.TaskIdentity.Generation);
            Owners_.push_back(Owner);
            std::shared_ptr<Preview::Contract::QuicConnectionOwner> Base = Owner;
            return std::expected<Preview::Contract::QuicConnectionLease,
                Preview::Contract::ProviderFailure>{std::in_place, std::move(Base)};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return std::all_of(Owners_.begin(), Owners_.end(),
                [](const auto& Owner) { return !Owner->HasGenerationUse(); });
        }

        [[nodiscard]] auto Owners() const noexcept
            -> const std::vector<std::shared_ptr<TypedConnectionOwner>>&
        {
            return Owners_;
        }

    private:
        std::vector<std::shared_ptr<TypedConnectionOwner>> Owners_;
    };

    [[nodiscard]] auto MakePacket(
        const std::array<std::byte, 4>& ConnectionId,
        const Udp::endpoint& Peer) -> BoundaryPacket
    {
        BoundaryPacket Packet;
        Packet.Payload = {std::byte{0x01}};
        Packet.Peer = Peer;
        Packet.Classification.Kind = Preview::Boundary::DatagramKind::Quic;
        Packet.Classification.Route = Preview::Boundary::DatagramRoute::UnknownCid;
        Packet.Classification.ConnectionIdBytes.assign(
            ConnectionId.begin(), ConnectionId.end());
        return Packet;
    }

    [[nodiscard]] auto MakeRegistryOptions() -> Registry::Options
    {
        Registry::Options Options;
        Options.AdmissionBudget = std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
            Preview::Boundary::QuicAdmissionBudgetLimits{4096U, 65536U});
        return Options;
    }
}

TEST(QuicConnectionRegistryTypedOwner, RejectsCrossGenerationRawOwnerBeforeFactory)
{
    const auto Factory = std::make_shared<TypedConnectionFactory>();
    const auto Ingress = Preview::Testing::Quic::MakeIngress(Factory);
    const auto ForeignUse = std::make_shared<Preview::Foundation::GenerationUseState>();
    const auto Raw = std::make_shared<const Preview::Contract::RawDatagramIngressSnapshot>(
        Preview::Contract::RawDatagramIngressSnapshot::Options{
            Ingress->Generation(), ForeignUse, {}, {}});
    const auto Selection = std::make_shared<const Preview::Contract::DatagramIngressSelection>(
        Preview::Contract::DatagramIngressSelection::Options{
            Ingress->GenerationOwner(), Ingress->UseState(), Raw, Ingress});
    auto RegistryOwner = std::make_shared<Registry>(MakeRegistryOptions());
    std::size_t AdmissionCalls = 0;
    std::size_t FallbackCalls = 0;
    Preview::Boundary::BoundaryDispatcher Dispatcher({
        nullptr,
        [&FallbackCalls](BoundaryPacket) { ++FallbackCalls; },
        [&AdmissionCalls, RegistryOwner](BoundaryPacket Packet,
            std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot> Snapshot)
        {
            ++AdmissionCalls;
            return RegistryOwner->Handle(Packet, Snapshot);
        }});
    const std::array<std::byte, 4> Cid{
        std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12}};
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);

    EXPECT_FALSE(Selection->IsValid());
    Dispatcher.Dispatch(MakePacket(Cid, Peer), Selection);

    EXPECT_EQ(AdmissionCalls, 0U);
    EXPECT_EQ(FallbackCalls, 0U);
    EXPECT_EQ(Factory->Owners().size(), 0U);
    EXPECT_EQ(RegistryOwner->Size(), 0U);
    EXPECT_EQ(Dispatcher.Snapshot().RejectedPackets, 1U);
    EXPECT_EQ(Ingress->UseState()->Outstanding(), 0U);
    EXPECT_EQ(ForeignUse->Outstanding(), 0U);
}

TEST(QuicConnectionRegistryTypedOwner, KeepsGenerationBoundOwnersIndependentUntilDrain)
{
    Net::io_context Io;
    auto RegistryOwner = std::make_shared<Registry>(MakeRegistryOptions());
    const auto FactoryA = std::make_shared<TypedConnectionFactory>();
    const auto FactoryB = std::make_shared<TypedConnectionFactory>();
    const auto IngressA = Preview::Testing::Quic::MakeIngress(
        FactoryA, Preview::GenerationId{31}, "listener-a");
    const auto IngressB = Preview::Testing::Quic::MakeIngress(
        FactoryB, Preview::GenerationId{32}, "listener-b");
    const auto SelectionA = Preview::Testing::Quic::MakeSelection(IngressA);
    const auto SelectionB = Preview::Testing::Quic::MakeSelection(IngressB);
    Preview::Boundary::BoundaryDispatcher Dispatcher({
        nullptr,
        [](BoundaryPacket) {},
        [RegistryOwner](BoundaryPacket Packet,
            std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot> Snapshot)
        { return RegistryOwner->Handle(Packet, Snapshot); }});
    const auto PeerA = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto PeerB = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> CidA{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> CidB{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};

    Dispatcher.Dispatch(MakePacket(CidA, PeerA), SelectionA);
    Dispatcher.Dispatch(MakePacket(CidB, PeerB), SelectionB);

    ASSERT_EQ(FactoryA->Owners().size(), 1U);
    ASSERT_EQ(FactoryB->Owners().size(), 1U);
    const auto OwnerA = FactoryA->Owners().front();
    const auto OwnerB = FactoryB->Owners().front();
    EXPECT_EQ(OwnerA->Generation(), Preview::GenerationId{31});
    EXPECT_EQ(OwnerA->BindingId(), "listener-a");
    EXPECT_EQ(OwnerA->MetadataGeneration(), Preview::GenerationId{31});
    EXPECT_EQ(OwnerB->Generation(), Preview::GenerationId{32});
    EXPECT_EQ(OwnerB->BindingId(), "listener-b");
    EXPECT_EQ(OwnerB->MetadataGeneration(), Preview::GenerationId{32});
    EXPECT_EQ(IngressA->UseState()->Outstanding(), 1U);
    EXPECT_EQ(IngressB->UseState()->Outstanding(), 1U);
    ASSERT_TRUE(RegistryOwner->Close());
    EXPECT_FALSE(RegistryOwner->IsRetired());

    std::optional<std::expected<void, Preview::Fault::Failure>> DrainA;
    std::optional<std::expected<void, Preview::Fault::Failure>> DrainB;
    std::exception_ptr ExceptionA;
    std::exception_ptr ExceptionB;
    Net::co_spawn(Io, OwnerA->Drain(),
        [&DrainA, &ExceptionA](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            ExceptionA = std::move(Error);
            DrainA.emplace(std::move(Result));
        });
    Net::co_spawn(Io, OwnerB->Drain(),
        [&DrainB, &ExceptionB](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            ExceptionB = std::move(Error);
            DrainB.emplace(std::move(Result));
        });
    Io.run();

    ASSERT_FALSE(ExceptionA);
    ASSERT_FALSE(ExceptionB);
    ASSERT_TRUE(DrainA);
    ASSERT_TRUE(DrainB);
    ASSERT_TRUE(*DrainA);
    ASSERT_TRUE(*DrainB);
    EXPECT_TRUE(RegistryOwner->IsRetired());
    EXPECT_TRUE(FactoryA->IsRetired());
    EXPECT_TRUE(FactoryB->IsRetired());
    EXPECT_EQ(IngressA->UseState()->Outstanding(), 0U);
    EXPECT_EQ(IngressB->UseState()->Outstanding(), 0U);
}
