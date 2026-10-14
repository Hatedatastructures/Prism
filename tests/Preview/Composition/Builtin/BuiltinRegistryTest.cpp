#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include <Preview/Composition/Builtin/Registry.hpp>

namespace
{

    using Preview::Composition::Builtin::BuiltinDescriptor;
    using Preview::Composition::Builtin::BuiltinRequest;
    using Preview::Composition::Builtin::Capability;
    using Preview::Composition::Builtin::CapabilitySet;
    using Preview::Composition::Builtin::FreezeRequest;
    using Preview::Composition::Builtin::InvocationRequest;
    using Preview::Composition::Builtin::Registry;
    using Preview::Cancellation::Mode;
    using Preview::Executor::Affinity;
    using Preview::Foundation::Error;
    using Preview::Memory::Domain;

    auto MakeDescriptor(std::string_view Kind, std::string_view Name) -> BuiltinDescriptor
    {
        BuiltinDescriptor Descriptor;
        Descriptor.Kind = Preview::KindId::From(Kind);
        Descriptor.Name = Preview::NameId::From(Name);
        Descriptor.Callback = [](const BuiltinRequest &) -> Preview::Foundation::Expected<void>
        {
            return {};
        };
        return Descriptor;
    }

    TEST(PreviewTask2Capabilities, ClosureIncludesTransitiveRequirements)
    {
        const CapabilitySet Tls{Capability::Tls};

        EXPECT_TRUE(Tls.Contains(Capability::Tls));
        EXPECT_TRUE(Tls.Contains(Capability::Stream));
        EXPECT_TRUE(Tls.Contains(Capability::Transport));
        EXPECT_FALSE(Tls.Contains(Capability::Datagram));

        const auto Union = CapabilitySet{Capability::Multiplex} | CapabilitySet{Capability::Datagram};
        EXPECT_TRUE(Union.Contains(Capability::Multiplex));
        EXPECT_TRUE(Union.Contains(Capability::Stream));
        EXPECT_TRUE(Union.Contains(Capability::Transport));

        CapabilitySet Assigned{Capability::Core};
        Assigned |= CapabilitySet{Capability::Session};
        EXPECT_TRUE(Assigned.Contains(Capability::Memory));
        EXPECT_TRUE(Assigned.Contains(Capability::Executor));
        EXPECT_TRUE(Assigned.Contains(Capability::Cancellation));
    }

    TEST(PreviewTask2Capabilities, MissingExcludesProvidedPrerequisites)
    {
        const CapabilitySet Provided{Capability::Transport};
        const CapabilitySet Required{Capability::Tls};
        const CapabilitySet Missing = Provided.Missing(Required);
        const auto ExpectedMask = static_cast<std::uint64_t>(Capability::Tls) |
                                  static_cast<std::uint64_t>(Capability::Stream);

        EXPECT_EQ(Missing.Mask(), ExpectedMask);
        EXPECT_TRUE(Missing.Contains(Capability::Tls));
        EXPECT_TRUE(Missing.Contains(Capability::Stream));
        EXPECT_FALSE(Missing.Contains(Capability::Transport));
    }

    TEST(PreviewTask2Registry, PreservesExplicitOrderAndStableSnapshotIdentity)
    {
        Registry First;
        const auto FirstId = First.Register(MakeDescriptor("transport", "tls"));
        const auto SecondId = First.Register(MakeDescriptor("protocol", "http"));
        ASSERT_TRUE(FirstId);
        ASSERT_TRUE(SecondId);

        const auto FirstSnapshot = First.Freeze(FreezeRequest{});
        ASSERT_TRUE(FirstSnapshot);
        ASSERT_EQ((*FirstSnapshot)->Entries().size(), 2U);
        EXPECT_EQ((*FirstSnapshot)->Entries()[0].Id, *FirstId);
        EXPECT_EQ((*FirstSnapshot)->Entries()[1].Id, *SecondId);
        EXPECT_EQ((*FirstSnapshot)->Entries()[0].Descriptor.Name.Value(), "tls");
        static_assert(std::is_const_v<std::remove_reference_t<
                      decltype((*FirstSnapshot)->Entries()[0])>>);

        Registry Second;
        ASSERT_TRUE(Second.Register(MakeDescriptor("transport", "tls")));
        ASSERT_TRUE(Second.Register(MakeDescriptor("protocol", "http")));
        const auto SecondSnapshot = Second.Freeze(FreezeRequest{});
        ASSERT_TRUE(SecondSnapshot);

        EXPECT_EQ((*FirstSnapshot)->Identity(), (*SecondSnapshot)->Identity());
    }

    TEST(PreviewTask2Registry, RejectsDuplicateKindAndName)
    {
        Registry RegistryValue;

        ASSERT_TRUE(RegistryValue.Register(MakeDescriptor("transport", "tls")));
        const auto Duplicate = RegistryValue.Register(MakeDescriptor("transport", "tls"));

        ASSERT_FALSE(Duplicate);
        EXPECT_EQ(Duplicate.error(), Error::Duplicate);
    }

    TEST(PreviewTask2Registry, RejectsMissingCapabilitiesAndAcceptsClosedCapabilities)
    {
        Registry RegistryValue;
        auto Provider = MakeDescriptor("transport", "tls");
        Provider.Provides = CapabilitySet{Capability::Tls};
        ASSERT_TRUE(RegistryValue.Register(std::move(Provider)));

        auto Dependent = MakeDescriptor("protocol", "http");
        Dependent.Requires = CapabilitySet{Capability::Transport};
        ASSERT_TRUE(RegistryValue.Register(std::move(Dependent)));

        auto Missing = MakeDescriptor("protocol", "udp");
        Missing.Requires = CapabilitySet{Capability::Datagram};
        const auto Result = RegistryValue.Register(std::move(Missing));

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error(), Error::MissingCapability);
    }

    TEST(PreviewTask2Registry, RejectsRegistrationAfterFreeze)
    {
        Registry RegistryValue;
        ASSERT_TRUE(RegistryValue.Register(MakeDescriptor("transport", "tls")));
        ASSERT_TRUE(RegistryValue.Freeze(FreezeRequest{}));

        const auto Result = RegistryValue.Register(MakeDescriptor("protocol", "http"));
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error(), Error::Frozen);
    }

    TEST(PreviewTask2Registry, ValidatesFreezeRequestAndDerivesIdentity)
    {
        Registry Empty;
        FreezeRequest MissingRequest;
        MissingRequest.RequiredCapabilities = CapabilitySet{Capability::Tls};
        const auto Missing = Empty.Freeze(MissingRequest);

        ASSERT_FALSE(Missing);
        EXPECT_EQ(Missing.error(), Error::MissingCapability);
        EXPECT_FALSE(Empty.IsFrozen());

        Registry First;
        auto Provider = MakeDescriptor("transport", "tls");
        Provider.Provides = CapabilitySet{Capability::Tls};
        ASSERT_TRUE(First.Register(std::move(Provider)));
        FreezeRequest FirstRequest;
        FirstRequest.RequiredCapabilities = CapabilitySet{Capability::Transport};
        FirstRequest.Identity = "generation-a";
        FirstRequest.Generation = Preview::GenerationId{1};
        const auto FirstSnapshot = First.Freeze(std::move(FirstRequest));
        ASSERT_TRUE(FirstSnapshot);

        const auto SecondFreeze = First.Freeze(FreezeRequest{});
        ASSERT_FALSE(SecondFreeze);
        EXPECT_EQ(SecondFreeze.error(), Error::AlreadyFrozen);

        Registry Second;
        auto SameProvider = MakeDescriptor("transport", "tls");
        SameProvider.Provides = CapabilitySet{Capability::Tls};
        ASSERT_TRUE(Second.Register(std::move(SameProvider)));
        FreezeRequest SecondRequest;
        SecondRequest.RequiredCapabilities = CapabilitySet{Capability::Transport};
        SecondRequest.Identity = "generation-b";
        SecondRequest.Generation = Preview::GenerationId{1};
        const auto SecondSnapshot = Second.Freeze(std::move(SecondRequest));
        ASSERT_TRUE(SecondSnapshot);

        EXPECT_NE((*FirstSnapshot)->Identity(), (*SecondSnapshot)->Identity());
    }

    TEST(PreviewTask2Snapshot, InvokesCallbackWithDerivedIdentityAndContext)
    {
        Registry RegistryValue;
        const auto Observed = std::make_shared<BuiltinRequest>();
        auto Descriptor = MakeDescriptor("transport", "tls");
        Descriptor.Provides = CapabilitySet{Capability::Tls};
        Descriptor.MemoryDomain = Domain::Session;
        Descriptor.ExecutorAffinity = Affinity::Worker;
        Descriptor.CancellationMode = Mode::Required;
        Descriptor.Callback = [Observed](const BuiltinRequest &Request) -> Preview::Foundation::Expected<void>
        {
            *Observed = Request;
            return {};
        };
        const auto Id = RegistryValue.Register(std::move(Descriptor));
        ASSERT_TRUE(Id);

        FreezeRequest Freeze;
        Freeze.Generation = Preview::GenerationId{7};
        Freeze.RequiredCapabilities = CapabilitySet{Capability::Transport};
        const auto Frozen = RegistryValue.Freeze(std::move(Freeze));
        ASSERT_TRUE(Frozen);
        const InvocationRequest Request{.Id = *Id};

        EXPECT_TRUE((*Frozen)->Invoke(Request));
        EXPECT_EQ(Observed->Id, *Id);
        EXPECT_EQ(Observed->Generation, Preview::GenerationId{7});
        EXPECT_TRUE(Observed->Capabilities.Includes(CapabilitySet{Capability::Tls}));
        EXPECT_EQ(Observed->MemoryDomain, Domain::Session);
        EXPECT_EQ(Observed->ExecutorAffinity, Affinity::Worker);
        EXPECT_EQ(Observed->CancellationMode, Mode::Required);
    }

    TEST(PreviewTask2Snapshot, PropagatesCallbackErrors)
    {
        Registry RegistryValue;
        auto Descriptor = MakeDescriptor("protocol", "error");
        Descriptor.Callback = [](const BuiltinRequest &) -> Preview::Foundation::Expected<void>
        {
            return std::unexpected(Error::InvalidArgument);
        };
        const auto Id = RegistryValue.Register(std::move(Descriptor));
        ASSERT_TRUE(Id);
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);

        const auto Result = (*Frozen)->Invoke(InvocationRequest{.Id = *Id});
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error(), Error::InvalidArgument);
    }

    TEST(PreviewTask2Snapshot, RejectsUnknownInvocation)
    {
        Registry RegistryValue;
        ASSERT_TRUE(RegistryValue.Register(MakeDescriptor("protocol", "known")));
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);

        const auto Result = (*Frozen)->Invoke(InvocationRequest{.Id = Preview::BuiltinId{999}});
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error(), Error::NotFound);
    }

    TEST(PreviewTask2Snapshot, ConvertsCallbackExceptionsToTypedErrors)
    {
        Registry RegistryValue;
        auto Descriptor = MakeDescriptor("protocol", "exception");
        Descriptor.Callback = [](const BuiltinRequest &) -> Preview::Foundation::Expected<void>
        {
            throw std::runtime_error("callback failure");
        };
        const auto Id = RegistryValue.Register(std::move(Descriptor));
        ASSERT_TRUE(Id);
        const auto Frozen = RegistryValue.Freeze(FreezeRequest{});
        ASSERT_TRUE(Frozen);

        const auto Result = (*Frozen)->Invoke(InvocationRequest{.Id = *Id});
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error(), Error::CallbackException);
    }

} // namespace
