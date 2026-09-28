/**
 * @file VlessXudp.hpp
 * @brief VLESS XUDP（CommandMux）数据面解析与 UDP relay
 * @details 对齐 metacubex/sing-vmess v0.2.5 `xudp.go` / `mux.go` 的真实 wire：
 *          - 帧头 [2B Length][2B SessionId][1B Status][1B Option]
 *          - Length = 4 + body；body = [Network 1B][port-first AddrPort][globalID?]
 *          - payload 长度位于 body 之后，独立 2B 大端
 *          - 地址族：IPv4=0x01 / Fqdn=0x02 / IPv6=0x03；端口先于地址族字节
 *          - New 帧携带目标；Keep 短帧（Length=4）沿用会话已存目标
 *          - OptionError 表示远端关闭；OptionData 未置位表示空载荷控制帧
 * @note 回包帧使用长格式（network + 源地址），与 sing 服务端 writePacketFrame 对齐。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Protocols/Mux/SessionReadLoop.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Composition::VlessXudp
{

    namespace Net = boost::asio;

    /// XUDP 帧状态（对齐 sing-vmess Status* 常量）
    enum class Status : std::uint8_t
    {
        New = 1,
        Keep = 2,
        End = 3,
        KeepAlive = 4,
    };

    /// 帧选项位（对齐 sing-vmess Option* 常量）
    inline constexpr std::uint8_t OptionData = 0x01U;
    inline constexpr std::uint8_t OptionError = 0x02U;
    /// XUDP 网络类型：UDP（对齐 sing-vmess NetworkUDP）
    inline constexpr std::uint8_t NetworkUdp = 0x02U;
    /// 地址族（对齐 sing-vmess AddressSerializer 映射）
    inline constexpr std::uint8_t FamilyIpv4 = 0x01U;
    inline constexpr std::uint8_t FamilyFqdn = 0x02U;
    inline constexpr std::uint8_t FamilyIpv6 = 0x03U;
    /// 单包最大载荷（UDP 上限）
    inline constexpr std::size_t MaxDatagram = 65535U;
    /// 上游回包等待上限（避免静默上游长期占用会话）
    inline constexpr auto ResponseTimeout = std::chrono::seconds(5);

    /**
     * @struct Frame
     * @brief 解析后的 XUDP 帧
     */
    struct Frame final
    {
        std::uint16_t SessionId{0};
        Status StatusValue{Status::Keep};
        bool HasTarget{false};
        std::string Host;
        std::uint16_t Port{0};
        std::vector<std::uint8_t> Payload;
    };

    /**
     * @brief 解析 port-first 地址（[Port 2B BE][Family 1B][Addr body]）
     * @param Data 帧体
     * @param Offset 读写偏移（解析成功后前移到地址末尾）
     * @param Host 输出主机（IPv4 点分 / Fqdn / IPv6 压缩文本）
     * @param Port 输出端口
     * @return 解析成功返回 true
     * @note 允许调用方在地址之后保留 globalID 等尾随字节。
     */
    [[nodiscard]] inline auto ReadAddress(std::span<const std::uint8_t> Data,
                                          std::size_t &Offset, std::string &Host,
                                          std::uint16_t &Port) -> bool
    {
        if (Data.size() - Offset < 2U)
        {
            return false;
        }
        Port = static_cast<std::uint16_t>(Data[Offset] << 8U | Data[Offset + 1U]);
        Offset += 2U;
        if (Offset >= Data.size())
        {
            return false;
        }
        const auto Family = Data[Offset++];
        if (Family == FamilyIpv4)
        {
            if (Data.size() - Offset < 4U)
            {
                return false;
            }
            Host = std::to_string(Data[Offset]) + "." + std::to_string(Data[Offset + 1U]) +
                   "." + std::to_string(Data[Offset + 2U]) + "." +
                   std::to_string(Data[Offset + 3U]);
            Offset += 4U;
            return true;
        }
        if (Family == FamilyFqdn)
        {
            if (Offset >= Data.size())
            {
                return false;
            }
            const auto Length = static_cast<std::size_t>(Data[Offset++]);
            if (Data.size() - Offset < Length)
            {
                return false;
            }
            Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), Length);
            Offset += Length;
            return true;
        }
        if (Family == FamilyIpv6)
        {
            if (Data.size() - Offset < 16U)
            {
                return false;
            }
            Net::ip::address_v6::bytes_type Bytes{};
            std::copy_n(Data.begin() + static_cast<std::ptrdiff_t>(Offset), 16U, Bytes.begin());
            Host = Net::ip::address_v6(Bytes).to_string();
            Offset += 16U;
            return true;
        }
        return false;
    }

    /**
     * @brief 读取一个 XUDP 帧
     * @param Inbound MUX 根传输（已通过 VLESS 握手）
     * @return 帧；nullopt 表示底层读失败或协议错误；Status::End 表示远端正常结束
     * @note New/Keep 帧的 Length 覆盖 [Network][AddrPort][globalID?]，
     *       payload 长度在其后独立 2B。
     */
    [[nodiscard]] inline auto ReadFrame(Preview::SharedTransmission Inbound)
        -> Net::awaitable<std::optional<Frame>>
    {
        std::array<std::uint8_t, 6> Prefix{};
        if (!co_await Preview::Mux::Detail::ReadExact(Inbound, Prefix))
        {
            co_return std::nullopt;
        }
        const auto Length = static_cast<std::size_t>(Prefix[0] << 8U | Prefix[1]);
        Frame Result;
        Result.SessionId = static_cast<std::uint16_t>(Prefix[2] << 8U | Prefix[3]);
        Result.StatusValue = static_cast<Status>(Prefix[4]);
        const auto Option = Prefix[5];
        if (Result.StatusValue == Status::End)
        {
            co_return Result;
        }
        if (Result.StatusValue != Status::New && Result.StatusValue != Status::Keep &&
            Result.StatusValue != Status::KeepAlive)
        {
            co_return std::nullopt;
        }
        if (Length < 4U)
        {
            co_return std::nullopt;
        }
        if (Length > 4U)
        {
            std::vector<std::uint8_t> Body(Length - 4U);
            if (!co_await Preview::Mux::Detail::ReadExact(Inbound, Body) || Body.empty())
            {
                co_return std::nullopt;
            }
            if (Body[0] != NetworkUdp)
            {
                co_return std::nullopt;
            }
            std::size_t Offset = 1U;
            if (!ReadAddress(std::span<const std::uint8_t>(Body), Offset, Result.Host,
                             Result.Port))
            {
                co_return std::nullopt;
            }
            Result.HasTarget = true;
        }
        if ((Option & OptionError) != 0U)
        {
            co_return std::nullopt;
        }
        if ((Option & OptionData) == 0U)
        {
            co_return Result;
        }
        std::array<std::uint8_t, 2> PayloadLengthWire{};
        if (!co_await Preview::Mux::Detail::ReadExact(Inbound, PayloadLengthWire))
        {
            co_return std::nullopt;
        }
        const auto PayloadLength = static_cast<std::size_t>(
            PayloadLengthWire[0] << 8U | PayloadLengthWire[1]);
        Result.Payload.resize(PayloadLength);
        if (!co_await Preview::Mux::Detail::ReadExact(Inbound, Result.Payload))
        {
            co_return std::nullopt;
        }
        co_return Result;
    }

    /**
     * @brief 写回一个 XUDP 数据帧（长格式：network + port-first 源地址）
     * @param Inbound MUX 根传输
     * @param SessionId 会话号
     * @param Source 上游响应源端点
     * @param Payload 载荷
     * @return 写成功返回 true
     */
    [[nodiscard]] inline auto WriteDatagram(Preview::SharedTransmission Inbound,
                                            std::uint16_t SessionId,
                                            const Net::ip::udp::endpoint &Source,
                                            std::span<const std::uint8_t> Payload)
        -> Net::awaitable<bool>
    {
        if (Payload.size() > MaxDatagram)
        {
            co_return false;
        }
        const auto IsV4 = Source.address().is_v4();
        const auto AddressBodySize = IsV4 ? 7U : 19U; // port 2B + family 1B + addr
        const auto BodyLength = static_cast<std::uint16_t>(1U + AddressBodySize);
        const auto FrameLength = static_cast<std::uint16_t>(4U + BodyLength);
        std::vector<std::uint8_t> Wire;
        Wire.reserve(static_cast<std::size_t>(FrameLength) + 2U + Payload.size());
        Wire.push_back(static_cast<std::uint8_t>(FrameLength >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(FrameLength & 0xFFU));
        Wire.push_back(static_cast<std::uint8_t>(SessionId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(SessionId & 0xFFU));
        Wire.push_back(static_cast<std::uint8_t>(Status::Keep));
        Wire.push_back(OptionData);
        Wire.push_back(NetworkUdp);
        Wire.push_back(static_cast<std::uint8_t>(Source.port() >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Source.port() & 0xFFU));
        if (IsV4)
        {
            Wire.push_back(FamilyIpv4);
            const auto Bytes = Source.address().to_v4().to_bytes();
            Wire.insert(Wire.end(), Bytes.begin(), Bytes.end());
        }
        else
        {
            Wire.push_back(FamilyIpv6);
            const auto Bytes = Source.address().to_v6().to_bytes();
            Wire.insert(Wire.end(), Bytes.begin(), Bytes.end());
        }
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFFU));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());

        std::size_t Offset = 0;
        while (Offset < Wire.size())
        {
            std::error_code ErrorCode;
            const auto Written = co_await Inbound->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Wire.data() + Offset),
                                           Wire.size() - Offset),
                ErrorCode);
            if (ErrorCode || Written == 0 || Written > Wire.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    /// 单会话状态：上游 UDP socket + 最近目标
    struct SessionState final
    {
        explicit SessionState(Net::any_io_executor Executor) : Socket(std::move(Executor)) {}

        Net::ip::udp::socket Socket;
        Net::ip::udp::endpoint Target;
        bool HasTarget{false};
        bool RequestLogged{false};
    };

    [[nodiscard]] inline auto MakeLogContext(
        const Preview::Middleware::Context *RequestContext) noexcept
        -> Preview::Diagnose::ContextState
    {
        auto Result = Preview::Diagnose::ContextState::Empty();
        if (!RequestContext)
        {
            return Result;
        }
        try
        {
            if (RequestContext->TaskIdentity.WorkerId)
            {
                Result = Result.With(Preview::Diagnose::Fields::Worker,
                                     RequestContext->TaskIdentity.WorkerId);
            }
            if (RequestContext->TaskIdentity.SessionId)
            {
                Result = Result.With(Preview::Diagnose::Fields::Session,
                                     RequestContext->TaskIdentity.SessionId);
            }
            if (RequestContext->TaskIdentity.TaskId &&
                (!RequestContext->TaskIdentity.SessionId ||
                 RequestContext->TaskIdentity.TaskId.Value() !=
                     RequestContext->TaskIdentity.SessionId.Value()))
            {
                Result = Result.With(Preview::Diagnose::Fields::Task,
                                     RequestContext->TaskIdentity.TaskId);
            }
            if (RequestContext->TaskIdentity.Generation &&
                RequestContext->TaskIdentity.Generation.Value() > 1U)
            {
                Result = Result.With(Preview::Diagnose::Fields::Generation,
                                     RequestContext->TaskIdentity.Generation);
            }
        }
        catch (...)
        {
            return Preview::Diagnose::ContextState::Empty();
        }
        return Result;
    }

    struct SessionSummary final
    {
        const Preview::Middleware::Context *RequestContext{nullptr};
        std::size_t Flows{0};
        std::uint64_t Datagrams{0};
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};

        ~SessionSummary() noexcept
        {
            if (!Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Trace))
            {
                return;
            }
            try
            {
                (void)Preview::Diagnose::Trace(
                    MakeLogContext(RequestContext),
                    "UdpSessionSummary Protocol=VlessXudp Flows={} Datagrams={} UpBytes={} DownBytes={}",
                    Flows, Datagrams, UpBytes, DownBytes);
            }
            catch (...)
            {
            }
        }
    };

    /**
     * @brief 解析帧目标为 UDP 端点
     * @param Host 目标主机
     * @param Port 目标端口
     * @param Resolver DNS 解析器（可空）
     * @return 端点；解析失败返回 nullopt
     */
    [[nodiscard]] inline auto ResolveTarget(std::string_view Host, std::uint16_t Port,
                                            std::shared_ptr<Preview::Network::Dns::Resolver> Resolver)
        -> Net::awaitable<std::optional<Net::ip::udp::endpoint>>
    {
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(std::string(Host), AddressError);
        if (!AddressError)
        {
            co_return Net::ip::udp::endpoint(Address, Port);
        }
        if (!Resolver)
        {
            co_return std::nullopt;
        }
        std::error_code ResolveError;
        const auto Addresses = co_await Resolver->AsyncResolve(Host, ResolveError);
        if (ResolveError || Addresses.empty())
        {
            co_return std::nullopt;
        }
        co_return Net::ip::udp::endpoint(Addresses.front(), Port);
    }

    /**
     * @brief XUDP 数据面主循环（CommandMux 根传输）
     * @param Inbound MUX 根传输
     * @param Resolver DNS 解析器（可空；仅 IP 目标时可为空）
     * @return 结束码；正常远端 End 返回 Success，其余返回 BadGateway
     */
    [[nodiscard]] inline auto Run(Preview::SharedTransmission Inbound,
                                  std::shared_ptr<Preview::Network::Dns::Resolver> Resolver,
                                  const Preview::Middleware::Context *RequestContext = nullptr)
        -> Net::awaitable<Preview::Fault::Code>
    {
        using Net::experimental::awaitable_operators::operator||;
        std::unordered_map<std::uint16_t, std::shared_ptr<SessionState>> Sessions;
        SessionSummary Summary{RequestContext};
        while (Inbound && Inbound->IsOpen())
        {
            const auto Frame = co_await ReadFrame(Inbound);
            if (!Frame)
            {
                co_return Preview::Fault::Code::BadGateway;
            }
            if (Frame->StatusValue == Status::End)
            {
                co_return Preview::Fault::Code::Success;
            }
            if (Frame->Payload.empty())
            {
                continue;
            }
            auto &State = Sessions[Frame->SessionId];
            if (!State)
            {
                State = std::make_shared<SessionState>(Inbound->Executor());
            }
            Summary.Flows = Sessions.size();
            Net::ip::udp::endpoint Target;
            if (Frame->HasTarget)
            {
                if (!State->RequestLogged && RequestContext &&
                    !Frame->Host.empty() && Frame->Port != 0U)
                {
                    State->RequestLogged = true;
                    if (Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Info))
                    {
                        try
                        {
                            const auto Stream = RequestContext->TaskIdentity.StreamId
                                                    ? RequestContext->TaskIdentity.StreamId
                                                    : Preview::StreamId{Frame->SessionId};
                            const auto LogContext = MakeLogContext(RequestContext);
                            const auto SourceIp = RequestContext->SourceIp.empty()
                                                      ? std::string_view{"Unknown"}
                                                      : std::string_view{RequestContext->SourceIp};
                            const auto User = RequestContext->UserForLog();
                            const auto Host = std::string_view{
                                Frame->Host.data(), Frame->Host.size()};
                            const auto Port = std::to_string(Frame->Port);
                            if (User.empty())
                            {
                                (void)Preview::Diagnose::Info(
                                    LogContext, "Request StreamId={} SourceIp={} Target={}:{}",
                                    Stream.Value(), SourceIp, Host, Port);
                            }
                            else
                            {
                                (void)Preview::Diagnose::Info(
                                    LogContext,
                                    "Request StreamId={} SourceIp={} Target={}:{} User={}",
                                    Stream.Value(), SourceIp, Host, Port, User);
                            }
                        }
                        catch (...)
                        {
                        }
                    }
                }
                const auto Resolved = co_await ResolveTarget(Frame->Host, Frame->Port, Resolver);
                if (!Resolved)
                {
                    co_return Preview::Fault::Code::BadGateway;
                }
                Target = *Resolved;
                State->Target = Target;
                State->HasTarget = true;
                boost::system::error_code CloseError;
                State->Socket.close(CloseError);
                boost::system::error_code OpenError;
                State->Socket.open(Target.protocol(), OpenError);
                if (OpenError)
                {
                    co_return Preview::Fault::Code::BadGateway;
                }
            }
            else if (State->HasTarget)
            {
                Target = State->Target;
            }
            else
            {
                co_return Preview::Fault::Code::BadGateway;
            }
            boost::system::error_code SendError;
            (void)co_await State->Socket.async_send_to(
                Net::buffer(Frame->Payload), Target,
                Net::redirect_error(Net::use_awaitable, SendError));
            if (SendError)
            {
                co_return Preview::Fault::Code::BadGateway;
            }
            ++Summary.Datagrams;
            Summary.UpBytes += Frame->Payload.size();
            std::array<std::uint8_t, MaxDatagram> Response{};
            Net::ip::udp::endpoint Source;
            boost::system::error_code ReceiveError;
            Net::steady_timer Timer(Inbound->Executor());
            Timer.expires_after(ResponseTimeout);
            auto Receive = State->Socket.async_receive_from(
                Net::buffer(Response), Source,
                Net::redirect_error(Net::use_awaitable, ReceiveError));
            auto Outcome = co_await (std::move(Receive) || Timer.async_wait(Net::use_awaitable));
            if (Outcome.index() == 1)
            {
                continue; // 上游静默：等待下一个客户端数据包
            }
            const auto Count = std::get<0>(std::move(Outcome));
            if (ReceiveError || Count == 0)
            {
                continue;
            }
            if (!co_await WriteDatagram(Inbound, Frame->SessionId, Source,
                                        std::span<const std::uint8_t>(Response).first(Count)))
            {
                co_return Preview::Fault::Code::BadGateway;
            }
            Summary.DownBytes += Count;
        }
        co_return Preview::Fault::Code::Success;
    }

} // namespace Preview::Composition::VlessXudp
