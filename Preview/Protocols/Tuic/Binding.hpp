/** @file Binding.hpp @brief TUIC 真实 Prepared/exporter/admission Native 工厂与关闭 owner。 */
#pragma once
#include <Preview/Protocols/Tuic/NativeSession.hpp>
#include <stop_token>
namespace Preview::Tuic
{
    class Binding final : public Preview::Contract::QuicConnectionFactory
    {
    public:
        explicit Binding(Prepared Value):Prepared_(std::make_shared<const Prepared>(std::move(Value))),
            Lifetime_(std::make_shared<Preview::Protocols::QuicBindingState>(Prepared_.load()->Services.Network.Listener.Executor)){}
        ~Binding() override {Close();Lifetime_->HoldPending();}
        /** @brief listener executor 单次接管 CID/peer/weak 观察者，输出 owning 唯一 Native/admission lease。 */
        [[nodiscard]] auto Create(Preview::Contract::QuicAcceptRequest Request)
            ->std::expected<Preview::Contract::QuicConnectionLease,Preview::Contract::ProviderFailure> override
        {
            auto Value=Prepared_.load();
            if(!Value || Lifetime_->Closed() || !Lifetime_->CanAdmit())return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::DispatchUnavailable,Value?Value->Input.Instance:std::string{},"Quic.Accept"});
            if(!Request.GenerationUse || !Value->Input.Generation ||
                Request.GenerationUse.Generation()!=Value->Input.Generation->Id() ||
                Request.GenerationUse.BindingId()!=Value->Input.Instance ||
                Request.Metadata.TaskIdentity.Generation!=Value->Input.Generation->Id())
                return std::unexpected(Preview::Contract::ProviderFailure{
                    Preview::Contract::ProviderError::GenerationMismatch,Value->Input.Instance,"Quic.Generation"});
            auto Owner=std::make_shared<NativeSession>(Value,Preview::Protocols::QuicConnectionPreparation{
                Value->Services.Network.Listener,std::move(Request),Lifetime_,Value->Input.Generation,Value->Services.Network.Traffic});
            Owner->Build();
            if(!Lifetime_->Track(Owner))return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::Cancelled,Value->Input.Instance,"Quic.Accept"});
            return Preview::Contract::QuicConnectionLease(std::move(Owner));
        }
        auto Close() noexcept -> void {Lifetime_->Close();}
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {return Lifetime_->IsRetired() && !Prepared_.load(std::memory_order_acquire);}
        /** @brief 等实际 auth/relay/UDP/native 退栈及最终完成；不把 bool Closed 当成 drain。 */
        [[nodiscard]] auto Drain()
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>>
        {
            Close();
            const auto Drained=co_await Lifetime_->Drain();
            if(Lifetime_->IsRetired())Prepared_.store({});
            if(!Drained)co_return std::unexpected(Drained.error());
            co_return std::expected<void,Preview::Fault::Failure>{};
        }
    private:
        std::atomic<std::shared_ptr<const Prepared>> Prepared_;
        std::shared_ptr<Preview::Protocols::QuicBindingState> Lifetime_;
    };
    [[nodiscard]] inline auto Bind(Prepared Value,std::stop_token Stop)
        ->std::expected<std::shared_ptr<Binding>,Preview::Contract::ProviderFailure>
    {
        if(Stop.stop_requested())return std::unexpected(Preview::Contract::ProviderFailure{
            Preview::Contract::ProviderError::Cancelled,Value.Input.Instance,"Bind"});
        auto Verified=Prepare(std::move(Value.Input),std::move(Value.Services));
        if(!Verified)return std::unexpected(Verified.error());
        auto Result=std::make_shared<Binding>(std::move(*Verified));
        if(Stop.stop_requested()){Result->Close();return std::unexpected(Preview::Contract::ProviderFailure{
            Preview::Contract::ProviderError::Cancelled,{},"Bind"});}
        return Result;
    }
}
