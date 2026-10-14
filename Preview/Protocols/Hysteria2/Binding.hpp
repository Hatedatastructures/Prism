/** @file Binding.hpp @brief Hysteria2 真实 Prepared 到 Native connection lease 的唯一 provider。 */
#pragma once
#include <Preview/Protocols/Hysteria2/NativeSession.hpp>
#include <stop_token>
namespace Preview::Hysteria2
{
    class Binding final : public Preview::Contract::QuicConnectionFactory
    {
    public:
        explicit Binding(Prepared Value):Prepared_(std::make_shared<const Prepared>(std::move(Value))),
            Lifetime_(std::make_shared<Preview::Protocols::QuicBindingState>(Prepared_.load()->Services.Network.Listener.Executor)){}
        ~Binding() override {Close();Lifetime_->HoldPending();}
        /** @brief listener executor 单次消耗 Initial 接入；失败不返回可启动 native，不借用 CID。 */
        [[nodiscard]] auto Create(Preview::Contract::QuicAcceptRequest Request)
            -> std::expected<Preview::Contract::QuicConnectionLease,Preview::Contract::ProviderFailure> override
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
        /** @brief 所有连接实际 child/native/finalizer 完成后释放长期材料；外部 lease 单独 pin 原 generation。 */
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
