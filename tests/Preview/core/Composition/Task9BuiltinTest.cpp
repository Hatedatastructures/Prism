/**
 * @file Task9BuiltinTest.cpp
 * @brief Task 9 builtin registration and capability closure RED/GREEN tests.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>

namespace
{

    using namespace Preview::Composition::Builtin;

    template <typename Set>
    constexpr auto DirectDeclarationMask(const Set &Value) noexcept -> std::uint64_t
    {
        if constexpr (requires { Value.DeclaredMask(); })
        {
            return Value.DeclaredMask();
        }
        return 0U;
    }

    template <typename Set>
    constexpr auto DirectlyDeclares(const Set &Value, const Capability Item) noexcept -> bool
    {
        if constexpr (requires { Value.Declares(Item); })
        {
            return Value.Declares(Item);
        }
        return false;
    }

    auto MakeSnapshotWithProvides(
        const CapabilitySet Provides,
        const CapabilitySet InitialCapabilities = {})
        -> std::shared_ptr<const BuiltinSnapshot>
    {
        Registry RegistryValue({.InitialCapabilities = InitialCapabilities});
        BuiltinDescriptor Descriptor;
        Descriptor.Kind = Preview::KindId::From("protocol");
        Descriptor.Name = Preview::NameId::From("identity-test");
        Descriptor.Provides = Provides;
        Descriptor.Callback = [](const BuiltinRequest &) -> Preview::Foundation::Expected<void>
        {
            return {};
        };
        if (!RegistryValue.Register(std::move(Descriptor)))
        {
            return nullptr;
        }
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    TEST(Task9Builtin, RegistersAllProtocolAndCarrierDescriptorsInStableOrder)
    {
        Registry RegistryValue(RegistryOptions{ProtocolBuiltinCapabilities()});
        const auto Result = RegisterStaticBuiltins(RegistryValue, StaticBuiltinOptions{});

        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Registered, 17U);
        EXPECT_EQ(Result->Disabled, 0U);
        EXPECT_EQ(RegistryValue.Size(), 17U);
        ASSERT_TRUE(RegistryValue.Freeze(FreezeRequest{}));
        ASSERT_NE(RegistryValue.Snapshot(), nullptr);
        EXPECT_EQ(RegistryValue.Snapshot()->Entries().front().Descriptor.Name.Value(), "http");
        EXPECT_EQ(RegistryValue.Snapshot()->Entries().back().Descriptor.Name.Value(), "gun");
        const auto Invocation = RegistryValue.Snapshot()->Invoke(
            InvocationRequest{RegistryValue.Snapshot()->Entries().front().Id});
        ASSERT_FALSE(Invocation);
        EXPECT_EQ(Invocation.error(), Preview::Foundation::Error::NotFound);
    }

    TEST(Task9Builtin, DisabledDescriptorsAreSkippedWithoutChangingOrder)
    {
        Registry RegistryValue(RegistryOptions{ProtocolBuiltinCapabilities()});
        StaticBuiltinOptions Options;
        Options.Disabled = {
            BuiltinKey{"protocol", "vmess"},
            BuiltinKey{"carrier", "reality"},
        };

        const auto Result = RegisterStaticBuiltins(RegistryValue, Options);

        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Registered, 15U);
        EXPECT_EQ(Result->Disabled, 2U);
        EXPECT_EQ(RegistryValue.Size(), 15U);
        ASSERT_TRUE(RegistryValue.Freeze(FreezeRequest{}));
        ASSERT_NE(RegistryValue.Snapshot(), nullptr);
        EXPECT_EQ(RegistryValue.Snapshot()->Entries()[4].Descriptor.Name.Value(), "ss2022");
        EXPECT_EQ(RegistryValue.Snapshot()->Entries().back().Descriptor.Name.Value(), "gun");
    }

    TEST(Task9Builtin, CapabilityClosureCoversEachFrontAndOperationPrerequisite)
    {
        const auto Capabilities = ProtocolBuiltinCapabilities();

        EXPECT_TRUE(Capabilities.Contains(Capability::Transport));
        EXPECT_TRUE(Capabilities.Contains(Capability::Stream));
        EXPECT_TRUE(Capabilities.Contains(Capability::Datagram));
        EXPECT_TRUE(Capabilities.Contains(Capability::Quic));
        EXPECT_TRUE(Capabilities.Contains(Capability::Tls));
        EXPECT_TRUE(Capabilities.Contains(Capability::Alpn));
        EXPECT_TRUE(Capabilities.Contains(Capability::Dns));
        EXPECT_TRUE(Capabilities.Contains(Capability::Route));
        EXPECT_TRUE(Capabilities.Contains(Capability::Dial));
    }

    TEST(Task9Builtin, DirectDeclarationsSurviveClosureAndUnion)
    {
        const CapabilitySet QuicOnly{Capability::Quic};
        const auto WithDeclaredStream = QuicOnly | CapabilitySet{Capability::Stream};
        auto WithDeclaredStreamAssignment = QuicOnly;
        WithDeclaredStreamAssignment |= CapabilitySet{Capability::Stream};

        EXPECT_TRUE(QuicOnly.Contains(Capability::Stream));
        EXPECT_TRUE(QuicOnly.Includes(CapabilitySet{Capability::Stream}));
        EXPECT_EQ(QuicOnly.Mask(), WithDeclaredStream.Mask());
        EXPECT_EQ(QuicOnly, WithDeclaredStream);
        EXPECT_EQ(DirectDeclarationMask(QuicOnly),
                  static_cast<std::uint64_t>(Capability::Quic));
        EXPECT_FALSE(DirectlyDeclares(QuicOnly, Capability::Stream));
        EXPECT_TRUE(DirectlyDeclares(QuicOnly, Capability::Quic));
        EXPECT_EQ(DirectDeclarationMask(WithDeclaredStream),
                  static_cast<std::uint64_t>(Capability::Quic) |
                      static_cast<std::uint64_t>(Capability::Stream));
        EXPECT_TRUE(DirectlyDeclares(WithDeclaredStream, Capability::Stream));
        EXPECT_TRUE(DirectlyDeclares(WithDeclaredStreamAssignment, Capability::Stream));
    }

    TEST(Task9Builtin, SnapshotIdentityIncludesDirectDescriptorProvides)
    {
        const CapabilitySet SharedInitialCapabilities{Capability::Quic, Capability::Stream};
        const auto QuicOnly = MakeSnapshotWithProvides(
            CapabilitySet{Capability::Quic}, SharedInitialCapabilities);
        const auto QuicAndStream = MakeSnapshotWithProvides(
            CapabilitySet{Capability::Quic, Capability::Stream}, SharedInitialCapabilities);

        ASSERT_NE(QuicOnly, nullptr);
        ASSERT_NE(QuicAndStream, nullptr);
        const auto QuicOnlyProvides = QuicOnly->Entries().front().Descriptor.Provides;
        const auto QuicAndStreamProvides = QuicAndStream->Entries().front().Descriptor.Provides;
        EXPECT_EQ(QuicOnlyProvides.Mask(), QuicAndStreamProvides.Mask());
        EXPECT_EQ(QuicOnly->Capabilities().DeclaredMask(),
                  QuicAndStream->Capabilities().DeclaredMask());
        EXPECT_NE(QuicOnly->Identity(), QuicAndStream->Identity());
    }

    TEST(Task9Builtin, AnyTlsAndTrustTunnelAreStackProtocols)
    {
        bool AnyTlsProtocol = false;
        bool AnyTlsCarrier = false;
        bool TrustTunnelProtocol = false;
        bool TrustTunnelCarrier = false;
        for (const auto &Spec : StaticBuiltinSpecs())
        {
            if (Spec.Name == StaticBuiltinName::AnyTls)
            {
                AnyTlsProtocol = Spec.Kind == "protocol";
                AnyTlsCarrier = Spec.Kind == "carrier";
            }
            if (Spec.Name == StaticBuiltinName::TrustTunnel)
            {
                TrustTunnelProtocol = Spec.Kind == "protocol";
                TrustTunnelCarrier = Spec.Kind == "carrier";
            }
        }

        EXPECT_TRUE(AnyTlsProtocol);
        EXPECT_FALSE(AnyTlsCarrier);
        EXPECT_TRUE(TrustTunnelProtocol);
        EXPECT_FALSE(TrustTunnelCarrier);
    }

} // namespace
