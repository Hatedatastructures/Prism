/** @file NativeSession.hpp @brief TUIC 的 Native/exporter/auth/stream/datagram owner 与统一关闭门。 */
#pragma once
#include <Preview/Protocols/Tuic/Prepared.hpp>
#include <Preview/Protocols/Tuic/ServiceBinding.hpp>
#include <Preview/Protocols/Quic/ConnectionLifecycle.hpp>
namespace Preview::Tuic
{
    class NativeSession final : public Preview::Protocols::QuicConnectionLifecycle
    {
    public:
        NativeSession(std::shared_ptr<const Prepared> PreparedValue,Preview::Protocols::QuicConnectionPreparation Input)
            :QuicConnectionLifecycle(std::move(Input)),Prepared_(std::move(PreparedValue)),
             Retirement_(std::make_shared<Preview::Lifecycle::DrainBarrier>(
                std::make_shared<Preview::Executor::ExecutorReclaimer>(Executor()))) {(void)Retirement_->Enter();}
        /** @brief 单次实际工厂装配；exporter 由 Native TLS 提供，admission 只拥有本连接。 */
        auto Build()->void
        {
            auto Value=Options();const auto& Config=Prepared_->Input.Config;
            Value.ExpectedAlpn=Config.Alpn;Value.ExpectedServerName=Config.ServerName;
            Value.MaxStreams=Config.MaxStreams;Value.MaxDatagrams=Config.MaxDatagrams;
            const auto WeakOwner=weak_from_this();
            const auto& Credential=Prepared_->Credential.Material().Credential.View();
            AdmissionOptions Admission;
            Admission.Executor=Executor();Admission.Uuid=Prepared_->Uuid;
            Admission.ExporterContext=std::string(reinterpret_cast<const char*>(Credential.Bytes().data()),Credential.Size());
            Admission.Credential=std::make_shared<const Preview::Account::Credential>(Preview::Account::Credential::Token(Admission.ExporterContext));
            Admission.AuthenticatorOwner=Prepared_->Services.Authentication.Authenticator;
            Admission.MaxPendingBidiStreams=Config.MaxStreams;
            Admission.Metadata=Metadata();
            if (Prepared_->Input.Generation)
                Admission.Metadata.TaskIdentity.Generation=Prepared_->Input.Generation->Id();
            Admission.CloseOwner=[WeakOwner]()
                ->std::expected<void,Preview::Fault::Failure>
            {
                if(auto Owner=WeakOwner.lock())return Owner->RequestClose();
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            };
            Admission.OnFinalized=[Weak=std::weak_ptr<Preview::Lifecycle::DrainBarrier>(Retirement_)]
            {if(auto Barrier=Weak.lock())Barrier->Leave();};
            auto AdmissionResult=ConnectionAdmission::Create(std::move(Admission),
                BindServices(Prepared_->Services.Network,SourceIp()));
            if(!AdmissionResult)
            {
                AdmissionFailure_=AdmissionResult.error();
                RequestClose();
            }
            else Admission_=std::move(*AdmissionResult);
            const auto Weak=std::weak_ptr<ConnectionAdmission>(Admission_);
            const auto AdmissionFailure=AdmissionFailure_;
            Value.OnClosed=[WeakOwner,Weak]
            {
                if(auto Owner=Weak.lock())Owner->OnClosed();
                if(auto Owner=WeakOwner.lock())Owner->RequestClose();
            };
            Value.OnExporter=[Weak,AdmissionFailure](Preview::Quic::ServerOptions::KeyingMaterialExporter Exporter)
                ->std::expected<void,Preview::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnExporter(std::move(Exporter));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});};
            Value.OnUnidirectional=[Weak,AdmissionFailure](Preview::Quic::SharedStreamProvider Provider)
                ->std::expected<void,Preview::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnUnidirectional(std::move(Provider));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});};
            Value.OnStream=[Weak,AdmissionFailure](Preview::Quic::SharedStreamProvider Provider)
                ->std::expected<void,Preview::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnBidirectional(std::move(Provider));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});};
            Value.OnDatagram=[Weak,AdmissionFailure](Preview::Quic::SharedDatagramProvider Provider)
                ->std::expected<void,Preview::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnDatagram(std::move(Provider));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});};
            Install(std::move(Value));
        }
    private:
        auto CloseProtocol()->void override {if(Admission_)Admission_->Close();}
        auto DrainProtocol()
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>> override
        {
            if(AdmissionFailure_)co_return std::unexpected(*AdmissionFailure_);
            if(Admission_)
            {
                const auto AdmissionDrain=co_await Admission_->Drain();
                if(!AdmissionDrain)co_return std::unexpected(AdmissionDrain.error());
                Admission_.reset();
            }
            const auto Retired=co_await Retirement_->Drain();
            if(!Retired)co_return std::unexpected(Retired.error());
            Prepared_.reset();
            co_return std::expected<void,Preview::Fault::Failure>{};
        }
        std::shared_ptr<const Prepared> Prepared_;
        std::shared_ptr<ConnectionAdmission> Admission_;
        std::optional<Preview::Fault::Failure> AdmissionFailure_{};
        std::shared_ptr<Preview::Lifecycle::DrainBarrier> Retirement_;
    };
}
