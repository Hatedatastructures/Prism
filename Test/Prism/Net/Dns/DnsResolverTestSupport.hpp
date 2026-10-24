/**
 * @file DnsResolverTestSupport.hpp
 * @brief DnsResolverNgxTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file DnsResolverTest.cpp
 * @brief DNS 解析器测试（T3-3）
 * @details 覆盖：
 *          - LRU 缓存命中/未命中（loopback 域名）
 *          - 负缓存（不可解析域名）
 *          - 缓存过期（短 TTL）
 *          - LRU 淘汰（容量限制）
 * @note 测试用真实 Resolver（本地 hosts/loopback），避免外部网络
 */

#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/Dns/Detail/Maintenance.hpp>
#include <Prism/Net/Dns/Detail/ResolverFailure.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>

#include <chrono>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using ResolveFailure = Prism::Fault::Failure;
    using ResolveResult = std::expected<Prism::Network::Dns::AddressList, ResolveFailure>;
    using GateChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using Prism::Network::Dns::Config;

    auto CaptureResolveResult(ResolveResult Outcome, std::vector<Net::ip::address> &Addresses,
                              ResolveFailure &Failure) -> void
    {
        Addresses.clear();
        if (!Outcome)
        {
            Failure = Outcome.error();
            return;
        }
        Failure = {};
        Addresses.assign(Outcome->begin(), Outcome->end());
    }

    auto CaptureResolveResult(ResolveResult Outcome, ResolveFailure &Failure) -> void
    {
        Failure = Outcome ? ResolveFailure{} : Outcome.error();
    }

    struct ResolveLifetimeRequest final
    {
        Net::io_context &Ioc;
        std::unique_ptr<Prism::Network::Dns::Resolver> &Owner;
        std::unique_ptr<std::string> &Input;
        ResolveFailure &Failure;
        std::vector<Net::ip::address> &Addresses;
        int &Completions;
        bool &ExecutorDrained;
    };

    auto ResolveLifetimeProbe(ResolveLifetimeRequest Request) -> Net::awaitable<void>
    {
        CaptureResolveResult(co_await Request.Owner->AsyncResolve(*Request.Input),
                             Request.Addresses, Request.Failure);
        ++Request.Completions;
        Request.Owner.reset();
        Request.Input.reset();
        Net::post(Request.Ioc, [&ExecutorDrained = Request.ExecutorDrained]
        { ExecutorDrained = true; });
        co_return;
    }

    struct MaintenanceProbeCache
    {
        void EvictExpired()
        {
        }
    };

    struct MaintenanceProbeCoalescer
    {
        void FlushCleanup()
        {
        }
    };

    struct MaintenanceProbeTimer
    {
        void expires_after(std::chrono::seconds)
        {
        }

        auto async_wait(auto) -> Net::awaitable<void>
        {
            co_return;
        }
    };

    struct MaintenanceProbeUpstream
    {
        void ClearIdleConns()
        {
        }
    };

    struct MaintenanceProbeState
    {
        std::shared_ptr<std::atomic<bool>> Alive_{std::make_shared<std::atomic<bool>>(false)};
        MaintenanceProbeTimer MaintenanceTimer_;
        MaintenanceProbeCache Cache_;
        MaintenanceProbeCoalescer Coalescer_;
        std::shared_ptr<MaintenanceProbeUpstream> Upstream_ =
            std::make_shared<MaintenanceProbeUpstream>();
    };

    struct ResolverCancellationProbe final
    {
        Prism::Network::Dns::Resolver *ResolverOwner{nullptr};
        std::string Domain;
        std::vector<Net::ip::address> Addresses;
        ResolveFailure Error;
        bool Completed{false};
    };

    auto RunResolverCancellationProbe(
        const std::shared_ptr<ResolverCancellationProbe> &Probe) -> Net::awaitable<void>
    {
        try
        {
            auto Outcome = co_await Probe->ResolverOwner->AsyncResolve(Probe->Domain);
            Probe->Completed = Outcome.has_value();
            CaptureResolveResult(std::move(Outcome), Probe->Addresses, Probe->Error);
        }
        catch (const boost::system::system_error &Error)
        {
            Probe->Error = Prism::Network::Dns::Detail::ResolverFailureFromBoost(Error.code());
        }
        catch (...)
        {
            Probe->Error = ResolveFailure{Prism::Fault::Code::IoError, {}};
        }
    }

    [[nodiscard]] auto IsCancellationFailure(const std::exception_ptr &Failure) noexcept -> bool
    {
        if (!Failure)
        {
            return false;
        }
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const boost::system::system_error &Error)
        {
            return Error.code() == boost::asio::error::operation_aborted;
        }
        catch (const std::system_error &Error)
        {
            return Error.code() == std::make_error_code(std::errc::operation_canceled);
        }
        catch (...)
        {
            return false;
        }
    }

    struct ResolverCancellationCompletion final
    {
        std::shared_ptr<ResolverCancellationProbe> Probe;
        std::shared_ptr<GateChannel> Done;

        auto operator()(std::exception_ptr Failure) const -> void
        {
            if (Failure)
            {
                Probe->Error = IsCancellationFailure(Failure)
                    ? ResolveFailure{Prism::Fault::Code::Canceled,
                                     std::make_error_code(std::errc::operation_canceled)}
                    : ResolveFailure{Prism::Fault::Code::IoError, {}};
                Probe->Completed = false;
            }
            (void)Done->try_send(boost::system::error_code{});
        }
    };

    using MaintenanceFunction = Net::awaitable<void> (*)(std::shared_ptr<MaintenanceProbeState>);
    static_assert(std::is_same_v<decltype(&Prism::Network::Dns::Detail::MaintenanceLoop<MaintenanceProbeState>),
                                 MaintenanceFunction>,
                  "MaintenanceLoop must own its State shared_ptr by value");

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        auto KeepAlive = std::make_shared<A>(std::move(Coro));
        Net::co_spawn(
            Ioc,
            [KeepAlive]() -> Net::awaitable<void>
            {
                co_await (*KeepAlive)();
            },
            [&](std::exception_ptr e)
            {
                Exception = e;
                Ioc.stop();
            });
        Ioc.restart(); // 清除上一次 stop() 状态，使后续 run() 真正执行新协程
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
} // namespace








using Prism::Network::Dns::Resolver;
using Prism::Network::Dns::Server;
using Prism::Network::Dns::StalePolicy;

/// 本地回环 UDP DNS 服务器（Answer/NxDomain/Silent），带查询计数
class MiniDnsServer : public std::enable_shared_from_this<MiniDnsServer>
{
public:
    enum class Behavior
    {
        Answer,      ///< 返回固定地址记录（TTL 60s）
        MixedAnswer, ///< A/AAAA 返回不同 TTL 的地址记录
        NxDomain,    ///< 返回 NXDOMAIN（Rcode=3，零应答）
        Silent,      ///< 收到查询不应答
    };

    MiniDnsServer(Net::io_context &ioc, const Behavior behavior, const std::uint32_t ttlSec = 60)
        : Ex_(ioc.get_executor()), Behavior_(behavior), TtlSec_(ttlSec),
          Udp_(ioc, Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
    {
    }

    void Start()
    {
        Port_ = Udp_.local_endpoint().port();
        Addr_ = Udp_.local_endpoint().address().to_string();
        auto self = shared_from_this();
        Net::co_spawn(Ex_, [self]() { return self->Loop(); }, Net::detached);
    }

    /// 构造对应 Resolver 上游配置
    [[nodiscard]] auto MakeConfig() const -> Server
    {
        Server s;
        s.Address = Addr_;
        s.Port = Port_;
        return s;
    }

    [[nodiscard]] auto QueryCount() const -> std::size_t
    {
        return QueryCount_;
    }

    [[nodiscard]] auto ResponseCount() const -> std::size_t
    {
        return ResponseCount_;
    }

    void Close()
    {
        Stopped_ = true;
        boost::system::error_code ec;
        Udp_.close(ec);
        if (FirstResponseGate_)
        {
            (void)FirstResponseGate_->try_send(boost::system::error_code{});
        }
    }

    void HoldFirstResponse(std::shared_ptr<GateChannel> Gate)
    {
        HoldFirstResponse_ = true;
        FirstResponseGate_ = std::move(Gate);
    }

    void ObserveQueries(Net::io_context &Observer, std::shared_ptr<GateChannel> Signal)
    {
        QueryObserver_ = &Observer;
        QuerySignal_ = std::move(Signal);
    }

private:
    static void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    static void PutU32(std::vector<std::uint8_t> &out, const std::uint32_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 24));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    auto Loop() -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> buf(4096);
        Net::ip::udp::endpoint sender;
        for (;;)
        {
            boost::system::error_code ec;
            const auto n = co_await Udp_.async_receive_from(
                Net::buffer(buf), sender, Net::redirect_error(Net::use_awaitable, ec));
            // UDP 对端已取消时的 ICMP 不可达不能终止仍服务其他请求的测试 server。
            if (ec == Net::error::connection_reset && !Stopped_) continue;
            if (ec == Net::error::operation_aborted && Stopped_) co_return;
            if (ec || Stopped_ || n < 12)
            {
                std::fprintf(stderr, "dns-mini-receive-close error=%s/%d/%s count=%zu\n",
                    ec.category().name(), ec.value(), ec.message().c_str(), n);
                co_return;
            }
            ++QueryCount_;
            if (QueryObserver_ && QuerySignal_)
            {
                const auto Signal = QuerySignal_;
                Net::post(*QueryObserver_, [Signal]
                { (void)Signal->try_send(boost::system::error_code{}); });
            }
            if (Behavior_ == Behavior::Silent)
            {
                continue;
            }
            // 定位问题段结束（QNAME + QTYPE + QCLASS）
            std::size_t off = 12;
            while (off < static_cast<std::size_t>(n) && buf[off] != 0)
            {
                off += static_cast<std::size_t>(buf[off]) + 1;
            }
            const auto QEnd = off + 5;
            if (QEnd > static_cast<std::size_t>(n))
            {
                continue;
            }
            const bool Nx = Behavior_ == Behavior::NxDomain;
            const auto QueryType = static_cast<std::uint16_t>((buf[off + 1] << 8) | buf[off + 2]);
            const bool Aaaa = QueryType == 28;
            const bool Full = Behavior_ == Behavior::Answer || Behavior_ == Behavior::MixedAnswer;
            std::vector<std::uint8_t> out;
            PutU16(out, static_cast<std::uint16_t>((buf[0] << 8) | buf[1])); // 回显 Id
            std::uint16_t ResponseFlags = 0x8180u;
            if (Nx)
            {
                ResponseFlags |= 0x0003u;
            }
            PutU16(out, ResponseFlags); // QR|RD|RA (+Rcode=3)
            PutU16(out, 1);
            std::uint16_t AnswerCount = 0;
            if (Full)
            {
                AnswerCount = 1;
            }
            PutU16(out, AnswerCount);
            PutU16(out, 0);
            PutU16(out, 0);
            out.insert(out.end(), buf.begin() + 12,
                       buf.begin() + static_cast<std::ptrdiff_t>(QEnd));
            if (Full)
            {
                PutU16(out, 0xC00Cu); // 压缩指针指向问题段名字
                std::uint16_t RecordType = 1;
                if (Aaaa)
                {
                    RecordType = 28;
                }
                PutU16(out, RecordType); // type A / AAAA
                PutU16(out, 1);       // class IN
                std::uint32_t Ttl = TtlSec_;
                if (Behavior_ == Behavior::MixedAnswer)
                {
                    Ttl = 60u;
                    if (Aaaa)
                    {
                        Ttl = 1u;
                    }
                }
                PutU32(out, Ttl);
                if (Aaaa)
                {
                    PutU16(out, 16);
                    // 使用文档保留地址，避免把未指定地址 :: 混入地址族合并测试。
                    out.insert(out.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 1});
                }
                else
                {
                    PutU16(out, 4); // rdlength
                    out.insert(out.end(), {1, 2, 3, 4});
                }
            }
            if (HoldFirstResponse_ && !FirstResponseHeld_ && FirstResponseGate_)
            {
                FirstResponseHeld_ = true;
                boost::system::error_code GateError;
                co_await FirstResponseGate_->async_receive(
                    Net::redirect_error(Net::use_awaitable, GateError));
                if (GateError)
                {
                    co_return;
                }
            }
            co_await Udp_.async_send_to(
                Net::buffer(out), sender, Net::redirect_error(Net::use_awaitable, ec));
            if (!ec)
            {
                ++ResponseCount_;
            }
        }
    }

    Net::any_io_executor Ex_;
    Behavior Behavior_;
    std::uint32_t TtlSec_{60};
    Net::ip::udp::socket Udp_;
    std::uint16_t Port_{0};
    std::string Addr_;
    Net::io_context *QueryObserver_{nullptr};
    std::shared_ptr<GateChannel> QuerySignal_;
    std::shared_ptr<GateChannel> FirstResponseGate_;
    std::size_t QueryCount_{0};
    std::size_t ResponseCount_{0};
    bool HoldFirstResponse_{false};
    bool FirstResponseHeld_{false};
    bool Stopped_{false};
};







