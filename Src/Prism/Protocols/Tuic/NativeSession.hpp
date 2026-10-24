/** @file NativeSession.hpp @brief TUIC 的 Native/exporter/auth/stream/datagram owner 与统一关闭门。 */
#pragma once
#include <Prism/Protocols/Tuic/Binding.hpp>
#include <Prism/Protocols/Tuic/ServiceBinding.hpp>
#include <Prism/Protocols/Quic/QuicConnectionLifecycle.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Protocols/Tuic/Admission.hpp>
#include <expected>
#include <memory>
#include <string>
#include <utility>
namespace Prism::Tuic
{
    class NativeSession final : public Prism::Protocols::QuicConnectionLifecycle
    {
    public:
        NativeSession(std::shared_ptr<const Prepared> PreparedValue,Prism::Protocols::QuicConnectionPreparation Input)
            :QuicConnectionLifecycle(std::move(Input)),Prepared_(std::move(PreparedValue)),
             Retirement_(std::make_shared<Prism::Lifecycle::DrainBarrier>(
                std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor()))) {(void)Retirement_->Enter();}
        /** @brief 单次实际工厂装配；exporter 由 Native TLS 提供，admission 只拥有本连接。 */
        auto Build()->void
        {
            auto Value=Options();const auto& Config=Prepared_->Input.Config;
            Value.ExpectedAlpn=Config.Alpn;Value.ExpectedServerName=Config.ServerName;
            Value.MaxStreams=Config.MaxStreams;Value.MaxDatagrams=Config.MaxDatagrams;
            const auto WeakOwner=std::weak_ptr<NativeSession>(
                std::static_pointer_cast<NativeSession>(shared_from_this()));
            const auto& Credential=Prepared_->Credential.Material().Credential.View();
            AdmissionOptions Admission;
            Admission.Executor=Executor();Admission.Uuid=Prepared_->Uuid;
            Admission.ExporterContext=std::string(reinterpret_cast<const char*>(Credential.Bytes().data()),Credential.Size());
            Admission.Credential=std::make_shared<const Prism::Account::Credential>(Prism::Account::Credential::Token(Admission.ExporterContext));
            Admission.AuthenticatorOwner=Prepared_->Services.Authentication.Authenticator;
            Admission.MaxPendingBidiStreams=Config.MaxStreams;
            Admission.Metadata=Metadata();
            if (Prepared_->Input.Generation)
                Admission.Metadata.TaskIdentity.Generation=Prepared_->Input.Generation->Id();
            Admission.CloseOwner=[WeakOwner]()
                ->std::expected<void,Prism::Fault::Failure>
            {
                if(auto Owner=WeakOwner.lock())return Owner->RequestClose();
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            };
            Admission.OnFinalized=[Weak=std::weak_ptr<Prism::Lifecycle::DrainBarrier>(Retirement_)]
            {if(auto Barrier=Weak.lock())Barrier->Leave();};
            auto AdmissionResult=ConnectionAdmission::Create(std::move(Admission),
                BindServices(Prepared_->Services.Network,SourceIp()));
            if(!AdmissionResult)
            {
                AdmissionFailure_=AdmissionResult.error();
                RecordProtocolFailure(*AdmissionFailure_);
                (void)RequestClose();
            }
            else Admission_=std::move(*AdmissionResult);
            const auto Weak=std::weak_ptr<ConnectionAdmission>(Admission_);
            const auto AdmissionFailure=AdmissionFailure_;
            Value.OnClosed=[WeakOwner,Weak]
            {
                if(auto Owner=Weak.lock())Owner->OnClosed();
                if(auto Owner=WeakOwner.lock())
                {
                    const auto Closed=Owner->RequestClose();
                    if(!Closed)Owner->RecordProtocolFailure(Closed.error());
                }
            };
            Value.OnExporter=[Weak,AdmissionFailure](Prism::Quic::ServerOptions::KeyingMaterialExporter Exporter)
                ->std::expected<void,Prism::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnExporter(std::move(Exporter));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});};
            Value.OnUnidirectional=[Weak,AdmissionFailure](Prism::Quic::SharedStreamProvider Provider)
                ->std::expected<void,Prism::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnUnidirectional(std::move(Provider));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});};
            Value.OnStream=[Weak,AdmissionFailure](Prism::Quic::SharedStreamProvider Provider)
                ->std::expected<void,Prism::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnBidirectional(std::move(Provider));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});};
            Value.OnDatagram=[Weak,AdmissionFailure](Prism::Quic::SharedDatagramProvider Provider)
                ->std::expected<void,Prism::Fault::Failure>
            {if(auto Owner=Weak.lock())return Owner->OnDatagram(std::move(Provider));
             if(AdmissionFailure)return std::unexpected(*AdmissionFailure);
             return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});};
            Install(std::move(Value));
        }
    private:
        auto CloseProtocol()->void override {if(Admission_)Admission_->Close();}
        auto DrainProtocol()
            ->Net::awaitable<std::expected<void,Prism::Fault::Failure>> override
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
            co_return std::expected<void,Prism::Fault::Failure>{};
        }
        std::shared_ptr<const Prepared> Prepared_;
        std::shared_ptr<ConnectionAdmission> Admission_;
        std::optional<Prism::Fault::Failure> AdmissionFailure_{};
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Retirement_;
    };
}
