/**
 * @file UdpAssoc.hpp
 * @brief SOCKS5 UDP ASSOCIATE 服务端数据面（RFC 1928 真实 UDP 语义）
 * @details TCP 控制通道握手完成后，由本服务接管 UDP 数据面：
 *          - Bind 本地 UDP 端口，BND 地址通过 TCP 应答返回客户端
 *          - 帧循环：收客户端帧 → 解帧（RSV/FRAG/ATYP/ADDR/PORT）→
 *            转发载荷到目标端点 → 收上游回包 → 封帧回客户端源端点
 *          - 空闲超时与 TCP 控制连接断开都请求统一 retirement owner 关闭关联
 * @note 与 Dgram.hpp（帧 over 流的编解码测试模型）不同，本服务
 *       使用真实 UDP socket，对齐生产端 Socks5::handler::async_associate。
 */

#pragma once
#include <Preview/Protocols/Socks5/Detail/Target.hpp>
#include <Preview/Contract/Ingress/DatagramSession.hpp>
#include <Preview/Protocols/Common/DatagramObservation.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Common/DatagramDeadline.hpp>
#include <Preview/Protocols/Socks5/UdpAssocRetirement.hpp>
#include <Preview/Protocols/Socks5/UdpAssocBindGate.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>
#include <expected>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    namespace Net = boost::asio;

    /**
     * @struct UdpAssocOptions
     * @brief UDP 关联数据面选项
     */
    struct UdpAssocOptions
    {
        /// 空闲超时（0 = 禁用回收）
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        /// 目标解析回调：socks5 地址 → UDP 端点（nullptr = 按 IP/域名直解）
        std::function<Net::awaitable<std::expected<Net::ip::udp::endpoint,
            Preview::Fault::Failure>>(const Address &)>
            Resolve{};
        /// owning 流量统计 sink；为空时不统计。
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic{};
        Preview::Lifecycle::TaskIdentity TaskIdentity{};
        Preview::AccountId AccountId{};
        /// 首个有效数据报的实际目标（供会话请求日志使用）
        std::function<void(const Address &)> OnFirstTarget{};
        std::function<void(const Preview::Protocols::DatagramSummary&)> OnSessionEnd{};
    };

    /**
     * @class UdpAssoc
     * @brief SOCKS5 UDP ASSOCIATE 数据面服务
     * @details 持有已握手的 TCP 控制连接；Bind 本地 UDP 端口后
     *          通过 TCP 发送 BND 应答，随后进入双向帧循环。
     *          运行期由 idle timer 与 TCP 控制通道 EOF 双重守护，
     *          任一触发都请求统一 retirement owner 关闭资源；只有 Activity()->Drain()
     *          在原 executor 上观察到所有操作和 TCP 各层完成后才确认退休。
     */
    class UdpAssoc : public Preview::Contract::DatagramSession, public std::enable_shared_from_this<UdpAssoc>
    {
    public:
        /**
         * @brief 构造
         * @param Executor 执行器
         * @param Tcp 已握手的 TCP 控制连接（所有权移交）
         * @param Options 数据面选项
         */
        UdpAssoc(Net::any_io_executor Executor, std::shared_ptr<Conn<>> Tcp,
                  UdpAssocOptions Options)
            : Ex_(Net::make_strand(std::move(Executor))),
              Retirement_(std::make_shared<UdpAssocRetirement>(Ex_, std::move(Tcp))),
              BindGate_(std::make_shared<UdpAssocBindGate>(Ex_, Retirement_)),
              Opts_(std::move(Options))
        {
            Observation_.Sink = std::move(Opts_.Traffic);
            Observation_.Owner = Preview::Foundation::TrafficEvent{
                .Generation = Opts_.TaskIdentity.Generation,
                .Worker = Opts_.TaskIdentity.WorkerId,
                .Session = Opts_.TaskIdentity.SessionId,
                .Stream = Opts_.TaskIdentity.StreamId,
                .Task = Opts_.TaskIdentity.TaskId,
                .Account = Opts_.AccountId};
        }

        /**
         * @brief 通过唯一 bind gate 共享 BND 写入与 typed 结果。
         * @return BND wire 字节数或协议码、Native cause 与 partial progress。
         * @note 每个调用在 gate 内持 operation reservation 至真实退栈。
         */
        [[nodiscard]] auto BindAndReply() -> Net::awaitable<ReplyResult<std::size_t>>
        {
            [[maybe_unused]] const auto Self = shared_from_this();
            co_return co_await BindGate_->Run();
        }

        /**
         * @brief 获取 BND 端点（BindAndReply 成功后有效）
         * @return 本地 UDP 端点
         */
        [[nodiscard]] auto BindEndpoint() const -> Net::ip::udp::endpoint
        {
            return BindGate_->LocalEndpoint();
        }

        [[nodiscard]] auto DatagramCount() const noexcept -> std::size_t { return DatagramCount_; }

        [[nodiscard]] auto SentBytes() const noexcept -> std::size_t { return SentBytes_; }

        [[nodiscard]] auto ReceivedBytes() const noexcept -> std::size_t { return RecvBytes_; }

        /**
         * @brief 运行数据面（帧循环 + 控制通道守护，任一结束即收尾）
         * @return 首个 typed 失败；只有真实 Drain 成功后才返回成功。
         */
        /** @brief 在控制流 executor 上运行一次；取消传播到解析及全部 I/O。 */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            auto Self = shared_from_this();
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            auto Admission = Retirement_->BeginRun();
            if (!Admission)
            {
                const auto Failure = Admission.error();
                if (Failure.Code == Preview::Fault::Code::InvalidArgument)
                    co_return std::unexpected(Failure);
                const auto CloseWasRequested = Retirement_->IsCloseRequested();
                RequestRetirement();
                const auto Drain = co_await Retirement_->RunDrain();
                if (!Drain) co_return std::unexpected(Drain.error());
                if (!Retirement_->IsCancelled() && CloseWasRequested &&
                    Failure.Code == Preview::Fault::Code::Canceled)
                {
                    co_return std::expected<void, Preview::Fault::Failure>{};
                }
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            auto Reservation = std::move(*Admission);
            auto Result = Preview::Fault::Code::Success;
            try
            {
                Result = co_await Net::co_spawn(Ex_, Self->Execute(),
                    Net::bind_cancellation_slot(
                        Retirement_->CancellationSlot(), Net::use_awaitable));
            }
            catch (const boost::system::system_error& ErrorValue)
            {
                Result = Preview::Fault::ToCode(ErrorValue.code());
                if (Result == Preview::Fault::Code::Canceled)
                {
                    RequestCancellationRetirement();
                }
                else
                {
                    (void)Retirement_->RecordException(std::current_exception());
                }
            }
            catch (...)
            {
                (void)Retirement_->RecordException(std::current_exception());
                Result = Preview::Fault::Code::IoError;
            }
            const auto CloseWasRequested = Retirement_->IsCloseRequested();
            Reservation.Complete();
            RequestRetirement();
            const auto Drain = co_await Retirement_->RunDrain();
            if (!Drain) co_return std::unexpected(Drain.error());
            if (Retirement_->IsCancelled())
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            if (CloseWasRequested && Result == Preview::Fault::Code::Canceled)
                co_return std::expected<void, Preview::Fault::Failure>{};
            if (Preview::Fault::Failed(Result))
                co_return std::unexpected(Preview::Fault::Failure{Result});
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 返回拥有 TCP 各层及 UDP 操作预约的真实关闭与退栈能力。 */
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            PinRetirementOwner();
            return Retirement_;
        }

        /** @brief 可跨线程请求取消；最终错误和完成由 Activity()->Drain() 返回。 */
        auto Cancel() noexcept -> void override
        { RequestRetirement(true); }

    private:
        auto Execute() -> Net::awaitable<Preview::Fault::Code>
        {
            const auto Reply = co_await BindAndReply();
            if (!Reply)
            {
                if (Reply.error().Transport.Failed())
                    co_return Reply.error().Transport.Code;
                co_return Preview::Fault::ToCode(
                    Preview::make_error_code(Reply.error().Protocol));
            }
            co_return co_await RunCore();
        }

    private:
        [[nodiscard]] auto RunCore() -> Net::awaitable<Preview::Fault::Code>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            auto Self = shared_from_this();
            auto Result = co_await (Self->FrameLoop() || Self->TcpWatch());
            co_return Result.index() == 0 ? std::get<0>(Result) : Preview::Fault::Code::Success;
        }

    public:
        /** @brief 可跨线程请求原 executor 关闭；错误与真实退栈由 Activity()->Drain() 交付。 */
        auto Close() noexcept -> void override
        { RequestRetirement(); }

    private:
        auto PinRetirementOwner() const noexcept -> void
        {
            try
            {
                const auto Owner = std::const_pointer_cast<UdpAssoc>(weak_from_this().lock());
                if (!Owner) return;
                const std::weak_ptr<UdpAssoc> Weak = Owner;
                Retirement_->PinOwner(
                    std::static_pointer_cast<void>(Owner),
                    [Weak]
                    {
                        if (const auto Value = Weak.lock()) Value->Report();
                    });
            }
            catch (...)
            {
                Retirement_->RecordFailure({Preview::Fault::Code::Blocked});
            }
        }

        auto RequestRetirement(const bool Cancelled = false) noexcept -> void
        {
            auto Owner = weak_from_this().lock();
            if (!Owner)
            {
                Retirement_->RequestClose();
                return;
            }
            try
            {
                const std::weak_ptr<UdpAssoc> Weak = Owner;
                auto Completion = [Weak]
                {
                    if (const auto Value = Weak.lock()) Value->Report();
                };
                auto OwnerPin = std::static_pointer_cast<void>(std::move(Owner));
                if (Cancelled)
                    Retirement_->RequestCancel(std::move(OwnerPin), std::move(Completion));
                else
                    Retirement_->RequestClose(std::move(OwnerPin), std::move(Completion));
            }
            catch (...)
            {
                Retirement_->RecordFailure({Preview::Fault::Code::Blocked});
            }
        }

        auto Report() noexcept -> void
        {
            if (Reported_) return;
            Reported_ = true;
            Observation_.Complete();
            if (Opts_.OnSessionEnd)
            {
                try { Opts_.OnSessionEnd({DatagramCount_, SentBytes_, RecvBytes_}); } catch (...) {}
            }
        }

        auto RequestCancellationRetirement() noexcept -> void
        {
            if (!Retirement_->IsCloseRequested()) RequestRetirement(true);
        }

        [[nodiscard]] auto ObserveNativeError(
            const boost::system::error_code &ErrorCode) noexcept -> Preview::Fault::Code
        {
            const auto Code = Preview::Fault::ToCode(ErrorCode);
            if (Code == Preview::Fault::Code::Canceled)
                RequestCancellationRetirement();
            else
                Retirement_->RecordNative(ErrorCode);
            return Code;
        }

    private:
        struct ReceiveOptions
        {
            Net::ip::udp::socket &Socket;
            Net::steady_timer &Idle;
            std::span<std::byte> Buffer;
            Net::ip::udp::endpoint &Endpoint;
            boost::system::error_code &Error;
        };

        /**
         * @brief 数据面帧循环：解帧转发 + 回包封帧
         * @details 每次网络等待（收客户端帧 / 收上游回包）都与空闲定时器竞速，
         *          任一阶段超时即终止；TCP 控制断开由 TcpWatch 并行守护。
         */
        struct AcceptedDatagram final
        {
            Address Target;
            std::span<const std::uint8_t> Payload;
            Net::ip::udp::endpoint Peer;
        };

        struct ReplyWorkspace final
        {
            std::vector<std::byte> Payload = std::vector<std::byte>(65535);
            std::vector<std::uint8_t> Wire;
        };

        [[nodiscard]] auto FrameLoop() -> Net::awaitable<Preview::Fault::Code>
        {
            Net::steady_timer Idle(Ex_);
            std::vector<std::byte> Rx(65535);
            ReplyWorkspace Reply;
            while (true)
            {
                if (Retirement_->IsCloseRequested())
                    co_return Preview::Fault::Code::Canceled;
                Net::ip::udp::endpoint ClientEp;
                boost::system::error_code ErrorCode;
                ReceiveOptions Receive{Retirement_->Ingress(), Idle, Rx, ClientEp, ErrorCode};
                const auto Size = co_await RecvGuarded(Receive);
                if (ErrorCode)
                {
                    const auto Code = ObserveNativeError(ErrorCode);
                    if (Code == Preview::Fault::Code::Canceled) co_return Code;
                    co_return Preview::Fault::Code::Success;
                }
                if (!Size) co_return Preview::Fault::Code::Success;
                const auto ControlPeer = BindGate_->ControlPeer();
                if (!ControlPeer || ClientEp.address() != ControlPeer->address()) continue;
                AcceptedDatagram Packet;
                const auto Window = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(Rx.data()), *Size);
                if (ParseUdpDatagram(Window, Packet.Target, Packet.Payload) != Error::None) continue;
                Packet.Peer = ClientEp;
                ++DatagramCount_;
                if (!FirstTargetReported_ && !Packet.Target.Host.empty() && Packet.Target.Port != 0U)
                {
                    FirstTargetReported_ = true;
                    if (Opts_.OnFirstTarget)
                    {
                        try { Opts_.OnFirstTarget(Packet.Target); } catch (...) {}
                    }
                }
                const auto Status = co_await Preview::Protocols::AwaitDatagramDeadline(
                    Exchange(Packet, Reply), {Ex_, Opts_.IdleTimeout});
                if (Preview::Fault::Failed(Status)) co_return Status;
            }
        }

        /** @brief 接收窗口和应答工作区借用到返回；解析、双向发送与接收共享期限。 */
        auto Exchange(const AcceptedDatagram& Packet, ReplyWorkspace& Reply)
            -> Net::awaitable<Preview::Fault::Code>
        {
            auto Target = co_await ResolveTarget(Packet.Target);
            if (Retirement_->IsCloseRequested())
                co_return Preview::Fault::Code::Canceled;
            if (!Target)
            {
                if (Target.error().Code == Preview::Fault::Code::Canceled)
                    RequestCancellationRetirement();
                else
                    Retirement_->RecordFailure(Target.error());
                co_return Target.error().Code;
            }
            boost::system::error_code ErrorCode;
            auto &Egress = Retirement_->Egress();
            auto &Ingress = Retirement_->Ingress();
            if (!Egress.is_open())
            {
                Egress.open(Target->protocol(), ErrorCode);
            }
            else
            {
                const auto Local = Egress.local_endpoint(ErrorCode);
                if (ErrorCode || Local.protocol() != Target->protocol())
                {
                    if (ErrorCode &&
                        ObserveNativeError(ErrorCode) == Preview::Fault::Code::Canceled)
                    {
                        co_return Preview::Fault::Code::Canceled;
                    }
                    const auto Close = Retirement_->CloseEgress();
                    if (Close.Failed()) co_return Close.Code;
                    ErrorCode.clear();
                    Egress.open(Target->protocol(), ErrorCode);
                }
            }
            if (ErrorCode)
            {
                co_return ObserveNativeError(ErrorCode);
            }
            const auto Sent = co_await Egress.async_send_to(
                Net::buffer(Packet.Payload.data(), Packet.Payload.size()), *Target,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return ObserveNativeError(ErrorCode);
            }
            if (Retirement_->IsCloseRequested())
                co_return Preview::Fault::Code::Canceled;
            SentBytes_ += Sent;
            Observation_.Transfer(
                Sent, Preview::Foundation::TrafficObservation::Direction::Upload);
            Net::ip::udp::endpoint Source;
            std::size_t Size = 0;
            for (;;)
            {
                Size = co_await Egress.async_receive_from(Net::buffer(Reply.Payload), Source,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    co_return ObserveNativeError(ErrorCode);
                }
                if (Source == *Target)
                {
                    break;
                }
            }
            if (Retirement_->IsCloseRequested())
                co_return Preview::Fault::Code::Canceled;
            BuildUdpDatagram(Detail::EndpointToAddress(Source),
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(Reply.Payload.data()), Size),
                Reply.Wire);
            co_await Ingress.async_send_to(Net::buffer(Reply.Wire), Packet.Peer,
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return ObserveNativeError(ErrorCode);
            }
            RecvBytes_ += Size;
            Observation_.Transfer(
                Size, Preview::Foundation::TrafficObservation::Direction::Download);
            co_return Preview::Fault::Code::Success;
        }

        /**
         * @brief 单次网络接收（与空闲定时器竞速）
         * @param Options 接收 socket、缓冲区、定时器和输出状态
         * @return 实际字节数；nullopt = 空闲超时
         * @note IdleTimeout 为 0 时禁用超时，直接阻塞等待接收。
         */
        [[nodiscard]] auto RecvGuarded(ReceiveOptions Options)
            -> Net::awaitable<std::optional<std::size_t>>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            if (Opts_.IdleTimeout.count() <= 0)
            {
                auto Receive = Options.Socket.async_receive_from(
                    Net::buffer(Options.Buffer),
                    Options.Endpoint,
                    Net::redirect_error(Net::use_awaitable, Options.Error));
                co_return co_await std::move(Receive);
            }
            Options.Idle.expires_after(Opts_.IdleTimeout);
            auto Receive = Options.Socket.async_receive_from(
                Net::buffer(Options.Buffer),
                Options.Endpoint,
                Net::redirect_error(Net::use_awaitable, Options.Error));
            auto Wait = Options.Idle.async_wait(Net::use_awaitable);
            auto Result = co_await (std::move(Receive) || std::move(Wait));
            Options.Idle.cancel();
            if (Result.index() == 1)
            {
                co_return std::nullopt; // 空闲超时
            }
            co_return std::get<0>(Result);
        }

        /**
         * @brief 控制通道守护：TCP 关闭（EOF/错误）即终止数据面
         */
        [[nodiscard]] auto TcpWatch() -> Net::awaitable<void>
        {
            const auto Tcp = Retirement_->Tcp();
            if (!Tcp)
            {
                co_return;
            }
            std::array<std::byte, 1> Probe{};
            const auto Result = co_await Tcp->ReadSome(std::span(Probe));
            if (Result.Failure.Code == Preview::Fault::Code::Canceled)
            {
                RequestCancellationRetirement();
            }
            else if (Result.Failure.Native &&
                     Result.Failure.Code != Preview::Fault::Code::Eof)
                Retirement_->RecordFailure(Result.Failure);
            co_return;
        }

        /**
         * @brief 解析目标地址为 UDP 端点
         * @param Target 帧内目标地址
         * @return 错误码与端点
         */
        [[nodiscard]] auto ResolveTarget(const Address &Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Preview::Fault::Failure>>
        {
            if (Opts_.Resolve)
            {
                co_return co_await Opts_.Resolve(Target);
            }
            // 默认：IP 直解，域名尝试（失败返回 bad_address）
            const auto Value = Preview::Socks5::Detail::ToNetworkTarget(Target);
            if (!Value)
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
            const auto Ip = Preview::Network::IpAddress(Value->Host);
            if (!Ip)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
            }
            co_return Net::ip::udp::endpoint(*Ip, Target.Port);
        }

        Net::any_io_executor Ex_;                       ///< 执行器
        std::shared_ptr<UdpAssocRetirement> Retirement_; ///< TCP 全层、UDP socket 与 Run 退役 owner
        std::shared_ptr<UdpAssocBindGate> BindGate_;      ///< 一次性 bind/reply 与 waiter 结果 owner
        UdpAssocOptions Opts_;                          ///< 数据面选项
        Preview::Foundation::TrafficObservation Observation_;
        /// 客户端→上游载荷字节（up 口径，对齐 relay）
        std::size_t SentBytes_{0};
        /// 上游→客户端载荷字节（down 口径，对齐 relay）
        std::size_t RecvBytes_{0};
        std::size_t DatagramCount_{0}; ///< 已解析的有效客户端数据报数
        bool FirstTargetReported_{false}; ///< 是否已报告首个有效目标
        bool Reported_{false}; ///< 观察和会话结束回调只允许一次
    };

} // namespace Preview::Socks5
