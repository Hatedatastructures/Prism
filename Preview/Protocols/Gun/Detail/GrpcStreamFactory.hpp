/**
 * @file GrpcStreamFactory.hpp
 * @brief gRPC stream accept 工厂与握手失败退休 owner。
 * @details I/O 前预约输入和 stream owner；只有 request headers 握手成功后才释放票据。
 */
#pragma once

#include <Preview/Protocols/Gun/Detail/GrpcStreamOwner.hpp>
#include <Preview/Protocols/Gun/Detail/GrpcStreamDriver.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/redirect_error.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Gun::Grpc::Detail
{
    /**
     * @class StreamFactory
     * @brief 唯一创建 gRPC stream transport 的正式工厂。
     */
    class StreamFactory final
    {
    public:
        /**
         * @brief 接收 gRPC HTTP/2 stream 并完成首个 request headers 握手。
         * @param Lower 按值接管的下层加密传输；执行域固定为其 executor。
         * @param ConfigValue 按值持有的 path 与 message 限额。
         * @return 拥有型 stream 或保留 Native 的首个 typed Failure。
         * @details I/O 前预建失败退休 ticket；失败执行 Cancel、Close、driver 与 activity
         *          drain，成功后 ticket 转交给 stream。写半关闭只结束本地 trailers；最终
         *          Close 由 stream owner 转交下层，driver completion 等待真实协程退栈。
         */
        [[nodiscard]] static auto Accept(
            Preview::SharedTransmission Lower,
            Config ConfigValue)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            if (!Lower)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }

            auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Lower);
            if (!Prepared)
            {
                co_return std::unexpected(Prepared.error());
            }
            auto Admission = std::move(*Prepared);
            std::shared_ptr<StreamTransport> Self;
            std::exception_ptr ConstructionFailure;
            try
            {
                Self = std::shared_ptr<StreamTransport>(
                    new StreamTransport(Lower, std::move(ConfigValue)));
            }
            catch (...)
            {
                ConstructionFailure = std::current_exception();
            }
            if (ConstructionFailure)
            {
                const auto Failure = Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::move(ConstructionFailure));
                co_return std::unexpected(co_await Admission.Retire(Failure));
            }

            Preview::SharedTransmission Owner = Self;
            const auto Tracked = Admission.Track(Owner);
            if (!Tracked)
            {
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            }

            GrpcStreamDriver::StartRead(Self);
            GrpcStreamDriver::StartWrite(Self);
            const auto StartFailure = Self->Activity_->Failure();
            if (StartFailure.Failed())
            {
                co_return std::unexpected(co_await Self->RetireFailure(
                    std::move(Admission), StartFailure));
            }

            boost::system::error_code Error;
            co_await Self->Ready_.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error || !Self->ReadyOk_)
            {
                auto Failure = Self->Activity_->Failure();
                if (!Failure.Failed())
                {
                    if (Error)
                    {
                        Failure = Preview::Fault::FromNative(
                            static_cast<std::error_code>(Error));
                    }
                    else
                    {
                        Failure = {Preview::Fault::Code::ProtocolError};
                    }
                }
                co_return std::unexpected(co_await Self->RetireFailure(
                    std::move(Admission), Failure));
            }

            Admission.Release();
            co_return std::expected<Preview::SharedTransmission, Preview::Fault::Failure>(
                std::move(Self));
        }
    };
} // namespace Preview::Gun::Grpc::Detail
