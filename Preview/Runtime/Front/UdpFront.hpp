/**
 * @file UdpFront.hpp
 * @brief Preview UDP 关联 front。
 * @details UDP front 只负责关联选择、数据报边界和资源上限；具体协议
 *          编解码通过注册的 typed factory 注入，TCP recognition 不参与其中。
 *          真实生产 packet pump 位于 Preview/Ingress/UdpListener；该类保留
 *          typed association/transport contract，Bind 只负责建立其 own UDP carrier。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <Preview/Composition/Adapters/DataPlane.hpp>
#include <Preview/Composition/Recognition/ProtocolMatrix.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Unreliable.hpp>

namespace Preview::Runtime::Front
{

    namespace Net = boost::asio;
    namespace Adapters = Preview::Composition::Adapters;
    namespace Recognition = Preview::Composition::Recognition;

    struct UdpFrontHealth final
    {
        bool Bound{false};
        bool Ready{false};
        bool UnsupportedService{false};
        bool Draining{false};
        Preview::Error LastError{Preview::Error::None};

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return Ready && !UnsupportedService && !Draining &&
                   LastError == Preview::Error::None;
        }
    };

    struct UdpFrontOptions
    {
        Net::any_io_executor Executor{};
        std::size_t MaxAssociations{1024};
        std::size_t MaxPacketsPerAssociation{64};
    };

    struct UdpAssociationRequest
    {
        Preview::Recognition::ProtocolType Protocol{Preview::Recognition::ProtocolType::Unknown};
        Preview::SharedTransmission Carrier;
        std::uint64_t AssociationId{0};
        Recognition::OperationScope Scope{Recognition::OperationScope::UdpAssociation};
    };

    using UdpAssociationFactory = std::function<Net::awaitable<Adapters::DataPlaneResult>(
        UdpAssociationRequest)>;

    struct UdpAssociationRegistration
    {
        Preview::Recognition::ProtocolType Protocol{Preview::Recognition::ProtocolType::Unknown};
        UdpAssociationFactory Factory;
    };

    /**
     * @class UdpFront
     * @brief 负责 UDP typed 关联边界的前端。
     * @details Factory 只能返回 DatagramDataPlane。返回 stream 或空结果时
     *          front 将其转换为协议错误并收口 carrier。
     */
    class UdpFront final
    {
    public:
        explicit UdpFront(UdpFrontOptions Options) : Options_(std::move(Options)) {}

        ~UdpFront() noexcept
        {
            Close();
        }

        [[nodiscard]] auto RegisterAssociation(UdpAssociationRegistration Registration)
            -> Preview::Error
        {
            if (Closed_)
            {
                return Reject(Preview::Error::NotOpen);
            }
            if (Registration.Protocol == Preview::Recognition::ProtocolType::Unknown ||
                !Registration.Factory || !SupportsUdp(Registration.Protocol))
            {
                return Reject(Preview::Error::BadAddress);
            }
            if (!Factories_.emplace(Registration.Protocol, std::move(Registration.Factory)).second)
            {
                return Reject(Preview::Error::ProtocolError);
            }
            LastError_ = Preview::Error::None;
            return Preview::Error::None;
        }

        [[nodiscard]] auto Bind(const unsigned short Port) -> Preview::Error
        {
            if (Closed_)
            {
                return Reject(Preview::Error::NotOpen);
            }
            if (Draining_)
            {
                return Reject(Preview::Error::Canceled);
            }
            if (Carrier_)
            {
                return Reject(Preview::Error::ProtocolError);
            }
            auto Carrier = std::make_shared<Preview::Transport::Unreliable>(Options_.Executor);
            if (!Carrier->Bind(Port))
            {
                return Reject(Preview::Error::IoError);
            }
            Carrier->AllowAnyPeer();
            Carrier_ = std::move(Carrier);
            LastError_ = Preview::Error::None;
            return Preview::Error::None;
        }

        [[nodiscard]] auto Carrier() const noexcept -> Preview::SharedTransmission
        {
            return Carrier_;
        }

        [[nodiscard]] auto Associate(UdpAssociationRequest Request)
            -> Net::awaitable<Adapters::DataPlaneResult>
        {
            if (Closed_)
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (Draining_)
            {
                co_return RejectPlane(Preview::Error::Canceled);
            }
            if (Request.AssociationId == 0)
            {
                co_return RejectPlane(Preview::Error::BadMessage);
            }
            if (!Request.Carrier)
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (Request.Carrier->TransportType() != Preview::Transmission::Type::Udp)
            {
                co_return RejectPlane(Preview::Error::BadMessage);
            }
            if (!Request.Carrier->IsOpen())
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (Request.Scope != Recognition::OperationScope::UdpAssociation)
            {
                co_return RejectPlane(Preview::Error::BadMessage);
            }
            ReapClosedAssociations();
            if (Associations_.contains(Request.AssociationId))
            {
                co_return RejectPlane(Preview::Error::ProtocolError);
            }
            if (Associations_.size() >= Options_.MaxAssociations)
            {
                co_return RejectPlane(Preview::Error::NotSupported);
            }
            const auto It = Factories_.find(Request.Protocol);
            if (It == Factories_.end())
            {
                co_return RejectPlane(Preview::Error::NotSupported);
            }
            const auto InputCarrier = Request.Carrier;
            Adapters::DataPlaneResult Result;
            try
            {
                Result = co_await It->second(std::move(Request));
            }
            catch (...)
            {
                CloseTransport(InputCarrier);
                co_return RejectPlane(Preview::Error::ProtocolError);
            }
            if (!Result.IsDatagram() || !Result.IsOpen())
            {
                if (Result.Status == Preview::Error::None)
                {
                    Result.Status = Result.IsDatagram() ? Preview::Error::NotOpen
                                                        : Preview::Error::BadMessage;
                }
                LastError_ = Result.Status;
                Result.Close();
                co_return Result;
            }
            Associations_.emplace(Request.AssociationId,
                                   AssociationState{Request.Protocol, Result.Transport(), 0});
            LastError_ = Preview::Error::None;
            co_return Result;
        }

        /**
         * @brief 为已建立的关联申请一个数据报预算单位
         * @param AssociationId 关联标识
         * @return 成功或明确的生命周期/预算错误
         */
        [[nodiscard]] auto AdmitPacket(const std::uint64_t AssociationId) -> Preview::Error
        {
            if (Closed_)
            {
                return Reject(Preview::Error::NotOpen);
            }
            if (Draining_)
            {
                return Reject(Preview::Error::Canceled);
            }
            const auto It = Associations_.find(AssociationId);
            if (It == Associations_.end() || !It->second.Transport ||
                !It->second.Transport->IsOpen())
            {
                return Reject(Preview::Error::NotOpen);
            }
            if (It->second.PacketCount >= Options_.MaxPacketsPerAssociation)
            {
                return Reject(Preview::Error::NotSupported);
            }
            ++It->second.PacketCount;
            LastError_ = Preview::Error::None;
            return Preview::Error::None;
        }

        [[nodiscard]] auto PacketCount(const std::uint64_t AssociationId) const noexcept
            -> std::size_t
        {
            const auto It = Associations_.find(AssociationId);
            return It == Associations_.end() ? 0 : It->second.PacketCount;
        }

        [[nodiscard]] auto Release(const std::uint64_t AssociationId) -> bool
        {
            const auto It = Associations_.find(AssociationId);
            if (It == Associations_.end())
            {
                return false;
            }
            CloseTransport(It->second.Transport);
            Associations_.erase(It);
            LastError_ = Preview::Error::None;
            return true;
        }

        /**
         * @brief 停止接受新关联，但保留现有 carrier 直到 Close/Release
         */
        auto Drain() noexcept -> void
        {
            if (!Closed_)
            {
                Draining_ = true;
            }
        }

        /**
         * @brief 取消并关闭所有关联及 UDP carrier
         */
        auto Close() noexcept -> void
        {
            Drain();
            for (const auto &[Id, Association] : Associations_)
            {
                (void)Id;
                CloseTransport(Association.Transport);
            }
            Associations_.clear();
            if (Carrier_)
            {
                Carrier_->Cancel();
                Carrier_->Close();
                Carrier_.reset();
            }
            LastError_ = Preview::Error::None;
            Closed_ = true;
        }

        [[nodiscard]] auto AssociationCount() const noexcept -> std::size_t
        {
            return Associations_.size();
        }

        [[nodiscard]] auto Health() const noexcept -> UdpFrontHealth
        {
            const auto Bound = Carrier_ && Carrier_->IsOpen();
            if (LastError_ != Preview::Error::None)
            {
                return UdpFrontHealth{Bound, false, false, Draining_, LastError_};
            }
            if (Draining_)
            {
                return UdpFrontHealth{Bound, false, false, true, Preview::Error::Canceled};
            }
            return UdpFrontHealth{Bound, Bound, false, false, Preview::Error::None};
        }

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return Health().Healthy();
        }

        [[nodiscard]] auto LastError() const noexcept -> Preview::Error
        {
            return LastError_;
        }

    private:
        [[nodiscard]] auto Reject(const Preview::Error ErrorCode) noexcept -> Preview::Error
        {
            LastError_ = ErrorCode;
            return ErrorCode;
        }

        [[nodiscard]] auto RejectPlane(const Preview::Error ErrorCode)
            -> Adapters::DataPlaneResult
        {
            LastError_ = ErrorCode;
            return Adapters::DataPlaneResult::Failure(ErrorCode);
        }

        [[nodiscard]] static auto SupportsUdp(
            const Preview::Recognition::ProtocolType Protocol) noexcept -> bool
        {
            for (const auto &Binding : Recognition::ProtocolMatrix::UdpAssociations())
            {
                if (Binding.Protocol == Protocol)
                {
                    return true;
                }
            }
            return false;
        }

        struct AssociationState
        {
            Preview::Recognition::ProtocolType Protocol{
                Preview::Recognition::ProtocolType::Unknown};
            Preview::SharedTransmission Transport;
            std::size_t PacketCount{0};
        };

        static auto CloseTransport(const Preview::SharedTransmission &Transport) noexcept -> void
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        auto ReapClosedAssociations() noexcept -> void
        {
            for (auto It = Associations_.begin(); It != Associations_.end();)
            {
                if (!It->second.Transport || !It->second.Transport->IsOpen())
                {
                    It = Associations_.erase(It);
                }
                else
                {
                    ++It;
                }
            }
        }

        UdpFrontOptions Options_;
        std::unordered_map<Preview::Recognition::ProtocolType, UdpAssociationFactory> Factories_;
        std::unordered_map<std::uint64_t, AssociationState> Associations_;
        Preview::SharedTransmission Carrier_;
        Preview::Error LastError_{Preview::Error::None};
        bool Draining_{false};
        bool Closed_{false};
    };

} // namespace Preview::Runtime::Front
