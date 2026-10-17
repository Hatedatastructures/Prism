/**
 * @file ProviderMuxRootStateTest.cpp
 * @brief 覆盖 provider 票据向 Runtime 交接 mux root session 的契约。
 */
#include <Preview/Protocols/Common/ProviderMuxRootState.hpp>

#include <gtest/gtest.h>

namespace Preview::Testing
{
    namespace Net = boost::asio;

    class MuxSessionStub final : public Preview::Contract::MuxSession
    {
    public:
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return {};
        }

        [[nodiscard]] auto Run(Preview::Contract::MuxRootRequest)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return false;
        }

        auto Cancel() noexcept -> void override {}
        auto Close() noexcept -> void override {}
    };

    class ProviderMuxRootStateStub final : public Preview::Protocols::ProviderMuxRootState
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

        Preview::Contract::ProtocolDataPlane Pending;
        Pending.Root = Preview::Contract::MuxRootDataPlane{};
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
