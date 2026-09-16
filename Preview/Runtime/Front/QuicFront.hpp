/**
 * @file QuicFront.hpp
 * @brief Preview QUIC 连接绑定与 typed stream/datagram front。
 * @details ALPN 和配置协议在连接登记时确定；后续 stream 首字节只作为
 *          数据回调输入，绝不重新识别 Hysteria2/TUIC。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <utility>

#include <Preview/Composition/Adapters/DataPlane.hpp>
#include <Preview/Composition/Recognition/ProtocolMatrix.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <Preview/Protocols/Quic/GatewayCommon.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>

namespace Preview::Runtime::Front
{

    namespace Net = boost::asio;
    namespace Adapters = Preview::Composition::Adapters;
    namespace Recognition = Preview::Composition::Recognition;

    struct QuicFrontHealth final
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

    struct QuicFrontOptions
    {
        Net::any_io_executor Executor{};
        std::size_t MaxStreamsPerConnection{64};
        std::size_t MaxDatagramsPerConnection{64};
    };

    /**
     * @struct QuicProtocolRegistration
     * @brief QUIC 协议及其 typed carrier 能力登记
     * @details protocol/ALPN 在连接建立前固定；stream/datagram 能力必须
     *          显式登记，front 不根据流首字节猜测协议或载体。
     */
    struct QuicProtocolRegistration
    {
        Preview::Recognition::ProtocolType Protocol{
            Preview::Recognition::ProtocolType::Unknown};
        std::string Alpn;
        bool AllowStreams{false};
        bool AllowDatagrams{false};
    };

    struct QuicBindRequest
    {
        Preview::Quic::GatewayCommon::ConnKey Connection{0};
        Preview::Recognition::ProtocolType Protocol{Preview::Recognition::ProtocolType::Unknown};
        std::string Alpn;
        std::uint64_t PeerSource{0};
        Recognition::OperationScope Scope{Recognition::OperationScope::QuicBinding};
    };

    struct QuicStreamRequest
    {
        Preview::Quic::GatewayCommon::ConnKey Connection{0};
        Preview::Quic::SharedStreamProvider Provider{};
    };

    struct QuicDatagramRequest
    {
        Preview::Quic::GatewayCommon::ConnKey Connection{0};
        Preview::Quic::SharedDatagramProvider Provider{};
    };

    class QuicFront final : public Preview::Quic::GatewayCommon
    {
    public:
        using ConnKey = Preview::Quic::GatewayCommon::ConnKey;

        explicit QuicFront(QuicFrontOptions Options) : Options_(std::move(Options)) {}

        ~QuicFront() noexcept
        {
            Close();
        }

        /**
         * @brief 登记一个协议及其 stream/datagram carrier 能力
         */
        [[nodiscard]] auto RegisterProtocol(QuicProtocolRegistration Registration)
            -> Preview::Error
        {
            if (Closed_)
            {
                return Reject(Preview::Error::NotOpen);
            }
            if (Draining_)
            {
                return Reject(Preview::Error::Canceled);
            }
            if (Registration.Protocol == Preview::Recognition::ProtocolType::Unknown ||
                Registration.Alpn.empty() ||
                (!Registration.AllowStreams && !Registration.AllowDatagrams) ||
                !Recognition::ProtocolMatrix::FindQuic(Registration.Alpn,
                                                       Registration.Protocol))
            {
                return Reject(Preview::Error::BadMessage);
            }
            if (!Protocols_.emplace(Registration.Protocol, std::move(Registration)).second)
            {
                return Reject(Preview::Error::ProtocolError);
            }
            LastError_ = Preview::Error::None;
            return Preview::Error::None;
        }

        [[nodiscard]] auto BindConnection(const QuicBindRequest &Request) -> Preview::Error
        {
            if (Closed_)
            {
                return Reject(Preview::Error::NotOpen);
            }
            if (Draining_)
            {
                return Reject(Preview::Error::Canceled);
            }
            if (Request.Connection == 0 || Request.PeerSource == 0 || Request.Alpn.empty() ||
                Request.Scope != Recognition::OperationScope::QuicBinding ||
                !Recognition::ProtocolMatrix::FindQuic(Request.Alpn, Request.Protocol))
            {
                return Reject(Preview::Error::BadMessage);
            }
            if (Bindings_.contains(Request.Connection))
            {
                return Reject(Preview::Error::ProtocolError);
            }
            const auto RegistrationIterator = Protocols_.find(Request.Protocol);
            if (RegistrationIterator == Protocols_.end())
            {
                return Reject(Preview::Error::NotSupported);
            }
            if (!EqualAscii(RegistrationIterator->second.Alpn, Request.Alpn))
            {
                return Reject(Preview::Error::BadMessage);
            }
            const auto GatewayProtocol =
                Request.Protocol == Preview::Recognition::ProtocolType::Tuic
                    ? Preview::Quic::ConnectionProtocol::Tuic
                    : Preview::Quic::ConnectionProtocol::H3;
            const auto RegisterResult = RegisterTypedConnection(
                Request.Connection, GatewayProtocol, Request.Alpn, Request.PeerSource);
            if (RegisterResult != Preview::Error::None)
            {
                return Reject(RegisterResult);
            }
            BindingState Binding;
            Binding.Protocol = Request.Protocol;
            Binding.Alpn = Request.Alpn;
            Binding.PeerSource = Request.PeerSource;
            Binding.AllowStreams = RegistrationIterator->second.AllowStreams;
            Binding.AllowDatagrams = RegistrationIterator->second.AllowDatagrams;
            auto [It, Inserted] = Bindings_.emplace(Request.Connection, std::move(Binding));
            if (!Inserted)
            {
                (void)EraseConnection(Request.Connection);
                return Reject(Preview::Error::ProtocolError);
            }
            It->second.Authenticated = true;
            LastError_ = Preview::Error::None;
            return Preview::Error::None;
        }

        [[nodiscard]] auto OpenStream(QuicStreamRequest Request)
            -> Net::awaitable<Adapters::DataPlaneResult>
        {
            auto It = Bindings_.find(Request.Connection);
            if (It == Bindings_.end() || !Request.Provider)
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (It->second.Draining || Draining_)
            {
                co_return RejectPlane(Preview::Error::Canceled);
            }
            if (Request.Provider->IsClosed())
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (!It->second.AllowStreams)
            {
                co_return RejectPlane(Preview::Error::NotSupported);
            }
            const auto ProviderExecutor = Request.Provider->Executor();
            if (ProviderExecutor == Net::any_io_executor{} ||
                ProviderExecutor != Options_.Executor)
            {
                co_return RejectPlane(Preview::Error::IoError);
            }
            ReapClosedCarriers(It->second.Streams);
            if (It->second.Streams.size() >= Options_.MaxStreamsPerConnection)
            {
                co_return RejectPlane(Preview::Error::NotSupported);
            }
            auto Adapter = std::make_shared<Preview::Quic::StreamAdapter>(
                Options_.Executor, Request.Provider);
            It->second.Streams.push_back(Adapter);
            LastError_ = Preview::Error::None;
            co_return Adapters::DataPlaneResult::Stream(std::move(Adapter));
        }

        [[nodiscard]] auto OpenDatagram(QuicDatagramRequest Request)
            -> Net::awaitable<Adapters::DataPlaneResult>
        {
            auto It = Bindings_.find(Request.Connection);
            if (It == Bindings_.end() || !Request.Provider)
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (It->second.Draining || Draining_)
            {
                co_return RejectPlane(Preview::Error::Canceled);
            }
            if (Request.Provider->IsClosed())
            {
                co_return RejectPlane(Preview::Error::NotOpen);
            }
            if (!It->second.AllowDatagrams)
            {
                co_return RejectPlane(Preview::Error::NotSupported);
            }
            ReapClosedCarriers(It->second.Datagrams);
            if (It->second.Datagrams.size() >= Options_.MaxDatagramsPerConnection)
            {
                co_return RejectPlane(Preview::Error::NotSupported);
            }
            if (Request.Provider->Executor() == Net::any_io_executor{} ||
                Request.Provider->Executor() != Options_.Executor)
            {
                co_return RejectPlane(Preview::Error::IoError);
            }
            auto Adapter = std::make_shared<Preview::Quic::DatagramAdapter>(
                Request.Provider);
            It->second.Datagrams.push_back(Adapter);
            LastError_ = Preview::Error::None;
            co_return Adapters::DataPlaneResult::Datagram(std::move(Adapter));
        }

        [[nodiscard]] auto CloseConnection(const ConnKey Key) -> bool
        {
            const auto It = Bindings_.find(Key);
            if (It == Bindings_.end())
            {
                LastError_ = Preview::Error::NotOpen;
                return false;
            }
            const auto DrainResult = BeginDrain(Key);
            if (DrainResult != Preview::Error::None)
            {
                LastError_ = DrainResult;
                return false;
            }
            CloseBinding(It->second);
            Bindings_.erase(It);
            if (!EraseConnection(Key))
            {
                LastError_ = Preview::Error::ProtocolError;
                return false;
            }
            LastError_ = Preview::Error::None;
            return true;
        }

        [[nodiscard]] auto StreamCount(const ConnKey Key) const noexcept -> std::size_t
        {
            const auto It = Bindings_.find(Key);
            return It == Bindings_.end() ? 0 : CountOpen(It->second.Streams);
        }

        [[nodiscard]] auto DatagramCount(const ConnKey Key) const noexcept -> std::size_t
        {
            const auto It = Bindings_.find(Key);
            return It == Bindings_.end() ? 0 : CountOpen(It->second.Datagrams);
        }

        /**
         * @brief 停止接受新的 QUIC 连接和 carrier
         */
        auto Drain() noexcept -> void
        {
            if (Closed_)
            {
                return;
            }
            Draining_ = true;
            for (auto &[Key, Binding] : Bindings_)
            {
                (void)BeginDrain(Key);
                Binding.Draining = true;
            }
        }

        /**
         * @brief 关闭所有连接、stream 和数据报 provider
         */
        auto Close() noexcept -> void
        {
            Drain();
            for (auto It = Bindings_.begin(); It != Bindings_.end();)
            {
                const auto Key = It->first;
                CloseBinding(It->second);
                (void)EraseConnection(Key);
                It = Bindings_.erase(It);
            }
            LastError_ = Preview::Error::None;
            Closed_ = true;
        }

        [[nodiscard]] auto Health() const noexcept -> QuicFrontHealth
        {
            const auto Bound = !Bindings_.empty();
            if (LastError_ != Preview::Error::None &&
                LastError_ != Preview::Error::Unsupported)
            {
                return QuicFrontHealth{Bound, false, false, Draining_, LastError_};
            }
            if (Draining_)
            {
                return QuicFrontHealth{Bound, false, false, true, Preview::Error::Canceled};
            }
            // 当前接口只接收外部 provider，未持有多连接 UDP socket/CID
            // 路由服务，连接表成功不等于 QUIC front service ready。
            return QuicFrontHealth{Bound, false, true, false,
                                   LastError_ == Preview::Error::None
                                       ? Preview::Error::Unsupported
                                       : LastError_};
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

        [[nodiscard]] static auto EqualAscii(std::string_view Left,
                                              std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                const auto ToLower = [](const char Character) noexcept -> char
                {
                    if (Character >= 'A' && Character <= 'Z')
                    {
                        return static_cast<char>(Character + ('a' - 'A'));
                    }
                    return Character;
                };
                if (ToLower(Left[Index]) != ToLower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] static auto CountOpen(
            const std::vector<Preview::SharedTransmission> &Planes) noexcept -> std::size_t
        {
            return static_cast<std::size_t>(std::count_if(
                Planes.begin(), Planes.end(),
                [](const auto &Plane) { return Plane && Plane->IsOpen(); }));
        }

        static auto ReapClosedCarriers(std::vector<Preview::SharedTransmission> &Planes) noexcept
            -> void
        {
            Planes.erase(std::remove_if(Planes.begin(), Planes.end(),
                                        [](const auto &Plane)
                                        { return !Plane || !Plane->IsOpen(); }),
                         Planes.end());
        }

        static auto CloseTransport(const Preview::SharedTransmission &Transport) noexcept -> void
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        struct BindingState
        {
            Preview::Recognition::ProtocolType Protocol;
            std::string Alpn;
            std::uint64_t PeerSource{0};
            std::vector<Preview::SharedTransmission> Streams;
            std::vector<Preview::SharedTransmission> Datagrams;
            bool AllowStreams{false};
            bool AllowDatagrams{false};
            bool Authenticated{false};
            bool Draining{false};
        };

        static auto CloseBinding(BindingState &Binding) noexcept -> void
        {
            for (const auto &Stream : Binding.Streams)
            {
                CloseTransport(Stream);
            }
            for (const auto &Datagram : Binding.Datagrams)
            {
                CloseTransport(Datagram);
            }
            Binding.Streams.clear();
            Binding.Datagrams.clear();
        }

        QuicFrontOptions Options_;
        std::unordered_map<Preview::Recognition::ProtocolType, QuicProtocolRegistration>
            Protocols_;
        std::unordered_map<ConnKey, BindingState> Bindings_;
        Preview::Error LastError_{Preview::Error::None};
        bool Draining_{false};
        bool Closed_{false};
    };

} // namespace Preview::Runtime::Front
