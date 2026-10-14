/** @file NativeSession.hpp @brief Hysteria2 的实际 Native/HTTP3/auth/admission owner，无 server 强环。 */
#pragma once
#include <Preview/Protocols/Hysteria2/Prepared.hpp>
#include <Preview/Protocols/Hysteria2/ServiceBinding.hpp>
#include <Preview/Protocols/Http3/NativeServer.hpp>
#include <Preview/Protocols/Quic/ConnectionLifecycle.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
namespace Preview::Hysteria2
{
    class NativeSession final : public Preview::Protocols::QuicConnectionLifecycle
    {
    public:
        NativeSession(std::shared_ptr<const Prepared> PreparedValue,Preview::Protocols::QuicConnectionPreparation Input)
            :QuicConnectionLifecycle(std::move(Input)),Prepared_(std::move(PreparedValue)){}
        /** @brief 在 listener executor 构造真实 Native factory 回调，所有 owner 反向联系为 weak。 */
        auto Build()->void
        {
            auto Value=Options();const auto& Config=Prepared_->Input.Config;
            Value.ExpectedAlpn=Config.Alpn;Value.ExpectedServerName=Config.ServerName;
            Value.MaxStreams=Config.MaxStreams;Value.MaxDatagrams=Config.MaxDatagrams;
            const auto Weak=std::weak_ptr<NativeSession>(std::static_pointer_cast<NativeSession>(shared_from_this()));
            Value.OnEstablished=[Weak](std::string)
                ->std::expected<void,Preview::Fault::Failure>
            {
                if(auto Owner=Weak.lock())return Owner->StartHttp3();
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            };
            Value.OnDatagram=[Weak](Preview::Quic::SharedDatagramProvider Provider)
                ->std::expected<void,Preview::Fault::Failure>
            {
                if(auto Owner=Weak.lock();Owner && Owner->Admission_)
                    return Owner->Admission_->OnDatagram(std::move(Provider));
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            };
            Value.OnLifecycle=[Trace=Prepared_->Services.Network.Trace](Preview::Quic::ServerLifecycleEvent Event)
            {(void)Preview::Diagnose::Trace(Trace,"QuicNativeStage Stage={} Code={}",Preview::Quic::ServerLifecycleStageName(Event.Stage),Event.Code);};
            Install(std::move(Value));
        }
    private:
        auto StartHttp3()->std::expected<void,Preview::Fault::Failure>
        {
            if(Http3_)return {};
            if(!Prepared_)return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            Auth_=std::make_shared<Http3AuthSession>(Http3AuthSessionOptions{Executor(),Prepared_->Services.Authentication.Authenticator});
            auto AdmissionOptionsValue = AdmissionOptions{
                Executor(), Auth_, Prepared_->Input.Config.MaxStreams, 1, {},
                Metadata()};
            const auto WeakOwner=std::weak_ptr<NativeSession>(
                std::static_pointer_cast<NativeSession>(shared_from_this()));
            AdmissionOptionsValue.CloseOwner=[WeakOwner]()
                ->std::expected<void,Preview::Fault::Failure>
            {
                if(auto Owner=WeakOwner.lock())return Owner->RequestClose();
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            };
            if (Prepared_->Input.Generation)
                AdmissionOptionsValue.Metadata.TaskIdentity.Generation = Prepared_->Input.Generation->Id();
            auto AdmissionResult=ConnectionAdmission::Create(std::move(AdmissionOptionsValue),
                BindServices(Prepared_->Services.Network));
            if(!AdmissionResult)
            {
                AdmissionFailure_=AdmissionResult.error();
                RequestClose();
                return std::unexpected(*AdmissionFailure_);
            }
            Admission_=std::move(*AdmissionResult);
            Preview::Http3::NativeServerSessionOptions Options;
            Options.Executor=Executor();Options.Factory=Prepared_->Services.Http3;
            Options.MaxConcurrentStreams=Prepared_->Input.Config.MaxStreams;
            const auto Weak=std::weak_ptr<Preview::Quic::Server>(NativeServer());
            Options.OpenUnidirectional=[Weak]()->Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,Preview::Fault::Failure>>
            {
                auto Server = Weak.lock();
                if (!Server)
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Canceled});
                }
                co_return co_await Server->OpenUnidirectionalStream();
            };
            Options.AcceptUnidirectional=[Weak]()->Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,Preview::Fault::Failure>>
            {
                auto Server = Weak.lock();
                if (!Server)
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Canceled});
                }
                co_return co_await Server->AcceptUnidirectionalStream();
            };
            Options.AcceptBidirectional=[Weak]()->Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,Preview::Fault::Failure>>
            {
                auto Server = Weak.lock();
                if (!Server)
                {
                    co_return std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::Canceled});
                }
                co_return co_await Server->AcceptBidirectionalStream();
            };
            Options.OnEvent=[WeakAdmission=std::weak_ptr<ConnectionAdmission>(Admission_)](Preview::Http3::ServerEvent Event)
                ->Net::awaitable<Preview::Http3::SessionAction>
            {
                auto Admission = WeakAdmission.lock();
                if (!Admission)
                {
                    co_return Preview::Http3::SessionAction{};
                }
                co_return co_await Admission->HandleEvent(std::move(Event));
            };
            Http3_=std::make_shared<Preview::Http3::NativeServerSession>(std::move(Options));
            auto Session=Http3_;
            Net::co_spawn(Executor(),Session->Run(),[Session,WeakOwner](std::exception_ptr Error,
                std::expected<void,Preview::Fault::Failure> Result)
            {if(auto Owner=WeakOwner.lock())Owner->OnHttp3Complete(std::move(Error),std::move(Result));});
            return {};
        }
        auto OnHttp3Complete(std::exception_ptr Error,
            std::expected<void,Preview::Fault::Failure> Result) noexcept -> void
        {
            if(Error)
            {
                Http3Failure_=Preview::Contract::InboundAdmission::ExceptionFailure(Error);
                const auto Context=Preview::Executor::ContextOwner::Find(Executor());
                if(Context && Context->Fatal)Context->Fatal->Publish(std::move(Error));
            }
            else if(!Result && (Result.error().Code!=Preview::Fault::Code::Canceled ||
                Result.error().Native))
                Http3Failure_=Result.error();
            if(Admission_)Admission_->Close();
            RequestClose();
        }
        auto CloseProtocol()->void override {if(Http3_)Http3_->Close();if(Admission_)Admission_->Close();}
        auto DrainProtocol()
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>> override
        {
            auto FirstFailure=std::expected<void,Preview::Fault::Failure>{};
            if(AdmissionFailure_)FirstFailure=std::unexpected(*AdmissionFailure_);
            if(Http3Failure_ && FirstFailure)FirstFailure=std::unexpected(*Http3Failure_);
            if(Http3_)
            {
                const auto Http3Drain=co_await Http3_->Drain();
                if(!Http3Drain && FirstFailure)
                    FirstFailure=std::unexpected(Http3Drain.error());
                if(!Http3_->IsRetired() && FirstFailure)
                    FirstFailure=std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            if(Admission_)
            {
                const auto AdmissionDrain=co_await Admission_->Drain();
                if(!AdmissionDrain && FirstFailure)
                    FirstFailure=std::unexpected(AdmissionDrain.error());
            }
            if(!FirstFailure)co_return std::unexpected(FirstFailure.error());
            Http3_.reset();
            Admission_.reset();
            Auth_.reset();
            Prepared_.reset();
            co_return std::expected<void,Preview::Fault::Failure>{};
        }
        std::shared_ptr<const Prepared> Prepared_;
        std::shared_ptr<Http3AuthSession> Auth_;
        std::shared_ptr<ConnectionAdmission> Admission_;
        std::shared_ptr<Preview::Http3::NativeServerSession> Http3_;
        std::optional<Preview::Fault::Failure> AdmissionFailure_{};
        std::optional<Preview::Fault::Failure> Http3Failure_{};
    };
}
