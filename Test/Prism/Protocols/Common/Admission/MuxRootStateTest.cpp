/**
 * @file MuxRootStateTest.cpp
 * @brief 覆盖 provider 票据向 Runtime 交接 mux root session 的契约。
 */
#include <Prism/Protocols/Common/ProviderMuxRootState.hpp>

#include <gtest/gtest.h>

namespace Prism::Testing
{
    namespace Net = boost::asio;

    class MuxSessionStub final : public Prism::Contract::MuxSession
    {
    public:
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return {};
        }

        [[nodiscard]] auto Run(Prism::Contract::MuxRootRequest)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return false;
        }

        auto Cancel() noexcept -> void override {}
        auto Close() noexcept -> void override {}
    };

    class ProviderMuxRootStateStub final : public Prism::Protocols::ProviderMuxRootState
    {
    public:
        [[nodiscard]] auto SessionAttached() const noexcept -> bool
        {
            return SessionAttached_;
        }

    protected:
        auto OnMuxRootSessionAttached() noexcept -> void override
        {
            SessionAttached_ = true;
        }

        auto RetainMuxRootTicket() noexcept -> void override {}

    private:
        bool SessionAttached_{false};
    };

    TEST(ProviderMuxRootState, AttachedSessionIsReturnedWithThePendingPlane)
    {
        auto Owner = std::make_shared<ProviderMuxRootStateStub>();
        ASSERT_TRUE(Owner->ClaimMuxRootCreate());

        Prism::Contract::ProtocolDataPlane Pending;
        Pending.Root = Prism::Contract::MuxRootDataPlane{};
        Owner->AttachMuxRootPlane(std::move(Pending));

        const auto Session = std::make_shared<MuxSessionStub>();
        Owner->AttachMuxRootSession(Session);
        const auto Published = Owner->TakeMuxRootPlane();
        const auto *Mux = Published.Mux();

        ASSERT_NE(Mux, nullptr);
        EXPECT_EQ(Mux->Session, Session);
        EXPECT_TRUE(Owner->SessionAttached());
    }
}
