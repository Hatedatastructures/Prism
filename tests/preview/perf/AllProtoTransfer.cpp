/**
 * @file AllProtoTransfer.cpp
 * @brief 全部 TCP 协议传输基准（Release，本机真实 TCP）
 * @details 每个协议 Client Conn ↔ Server Conn 256MB 传输：
 * socks5（透传）/ trojan（透传）/ vless（透传）/ vmess（加密 chunk）
 * / ss2022（加密 chunk）
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Transport/Reliable.hpp>
#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>

using Clock = std::chrono::steady_clock;
namespace Net = boost::asio;

namespace
{
    auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }

    auto Report(const char *Name, std::size_t Bytes, std::int64_t MedianNanoseconds) -> void
    {
        const double Megabytes = static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const double Seconds = static_cast<double>(MedianNanoseconds) / 1e9;
        std::printf("%-40s %7.1f MB  med=%7.2f ms  => %9.1f MB/s  %5.1f Gbps\n",
                    Name,
                    Megabytes,
                    Seconds * 1000,
                    Megabytes / Seconds,
                    Megabytes / Seconds * 8 / 1000);
    }

    /// 性能门禁：全部样本数据面完成 + 吞吐下限（防断链静默/死循环挂死/完全退化）
    auto Gate(const char *Name, std::size_t Bytes, const std::array<std::int64_t, 3> &Samples) -> bool
    {
        constexpr double MinMbps = 50.0; // 宽松下限（本地 TCP 基线数百 MB/s，防 10x+ 劣化）
        auto Sorted = Samples;
        std::sort(Sorted.begin(), Sorted.end());
        Report(Name, Bytes, Sorted[1]);
        // 任一运行断链/未完成即 FAIL（部分失败不得被中位数掩盖）
        if (std::any_of(Sorted.begin(), Sorted.end(), [](std::int64_t Value) { return Value <= 0; }))
        {
            std::printf("FAIL %s: 存在数据面未完成运行（断链/死循环）\n", Name);
            return false;
        }
        const double MegabitsPerSecond =
            static_cast<double>(Bytes) / (1024.0 * 1024.0) /
            (static_cast<double>(Sorted[1]) / 1e9);
        if (MegabitsPerSecond < MinMbps)
        {
            std::printf("FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n",
                        Name,
                        MegabitsPerSecond,
                        MinMbps);
            return false;
        }
        return true;
    }

    template <typename Connection>
    auto ToTransmission(Preview::Error ErrorCode, Connection ConnectionValue)
        -> Preview::SharedTransmission
    {
        if (ErrorCode == Preview::Error::None)
        {
            return std::move(ConnectionValue);
        }
        return {};
    }

    struct BenchOptions
    {
        std::size_t Total;
        std::size_t Block;
    };

    template <typename ConnectFn, typename AcceptFn>
    auto BenchConn(BenchOptions Options, ConnectFn &&ConnectFunction, AcceptFn &&AcceptFunction)
        -> std::int64_t
    {
        Net::io_context IoContext;
        Net::ip::tcp::acceptor Acceptor(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        std::vector<std::uint8_t> Chunk(Options.Block, 0x5A);

        const auto StartNanoseconds = NowNs();
        int Completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                Net::ip::tcp::socket Socket(IoContext);
                co_await Acceptor.async_accept(Socket, Net::use_awaitable);
                auto Upstream = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
                auto Conn = co_await AcceptFunction(Upstream);
                if (!Conn)
                {
                    co_return;
                }
                std::vector<std::uint8_t> Buffer(Options.Block);
                std::error_code ErrorCode;
                std::size_t Done = 0;
                while (Done < Options.Total)
                {
                    const auto ReadBuffer = std::span<std::byte>(
                        reinterpret_cast<std::byte *>(Buffer.data()),
                        Buffer.size());
                    auto ReadOperation = Conn->async_read_some(ReadBuffer, ErrorCode);
                    const auto Count = co_await std::move(ReadOperation);
                    if (ErrorCode || Count == 0)
                    {
                        break;
                    }
                    Done += Count;
                }
                Conn->Close();
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            auto Upstream = std::make_shared<Preview::Transport::Reliable>(IoContext.get_executor());
            const auto ConnectError = co_await Upstream->Connect(
                Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), Port));
            if (ConnectError)
            {
                IoContext.stop();
                co_return;
            }
            auto Conn = co_await ConnectFunction(Upstream);
            if (!Conn)
            {
                IoContext.stop();
                co_return;
            }
            std::size_t Done = 0;
            std::error_code ErrorCode;
            while (Done < Options.Total)
            {
                const auto WriteBuffer = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Chunk.data()),
                    Chunk.size());
                auto WriteOperation = Conn->async_write_some(WriteBuffer, ErrorCode);
                const auto Count = co_await std::move(WriteOperation);
                if (ErrorCode || Count == 0)
                {
                    break; // 断链：返回 0 让门禁 FAIL，避免死循环挂死
                }
                Done += Count;
            }
            if (Done < Options.Total)
            {
                Completed = 0;
            }
            Conn->Close();
        }, [&](std::exception_ptr) { IoContext.stop(); });
        IoContext.run();
        if (Completed == 0)
        {
            return 0;
        }
        return NowNs() - StartNanoseconds;
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    constexpr std::size_t BlockBytes = 262144;
    const auto Uuid = std::array<std::uint8_t, 16>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

    // socks5
    {
        std::array<std::int64_t, 3> Samples{};
        for (std::size_t Index = 0; Index < Samples.size(); ++Index)
        {
            Samples[Index] = BenchConn(BenchOptions{TotalBytes, BlockBytes},
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  auto [ErrorCode, Conn] = co_await Preview::Socks5::Connect(
                                      Upstream,
                                      Preview::Socks5::ClientConfig{},
                                      Preview::Socks5::Address{
                                          Preview::Socks5::AddressType::Domain,
                                          "t.internal",
                                          443});
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              },
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  auto [ErrorCode, Request, Conn] = co_await Preview::Socks5::Accept(
                                      Upstream,
                                      Preview::Socks5::ServerConfig{});
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              });
        }
        std::sort(Samples.begin(), Samples.end());
        if (!Gate("socks5 Conn<->Conn (透传)", TotalBytes, Samples))
        {
            return 1;
        }
    }

    // trojan
    {
        std::array<std::int64_t, 3> Samples{};
        for (std::size_t Index = 0; Index < Samples.size(); ++Index)
        {
            Samples[Index] = BenchConn(BenchOptions{TotalBytes, BlockBytes},
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Trojan::ClientConfig Config;
                                  Config.password = "prism";
                                  auto [ErrorCode, Conn] = co_await Preview::Trojan::Connect(
                                      Upstream,
                                      Config,
                                      Preview::Trojan::Address{
                                          Preview::Trojan::AddressType::Domain,
                                          "t.internal",
                                          443});
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              },
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Trojan::ServerConfig Config;
                                  Config.password = "prism";
                                  auto [ErrorCode, Request, Conn] = co_await Preview::Trojan::Accept(
                                      Upstream,
                                      Config);
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              });
        }
        std::sort(Samples.begin(), Samples.end());
        if (!Gate("trojan Conn<->Conn (透传)", TotalBytes, Samples))
        {
            return 1;
        }
    }

    // vless
    {
        std::array<std::int64_t, 3> Samples{};
        for (std::size_t Index = 0; Index < Samples.size(); ++Index)
        {
            Samples[Index] = BenchConn(BenchOptions{TotalBytes, BlockBytes},
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Vless::ClientConfig Config;
                                  Config.uuid = Uuid;
                                  auto [ErrorCode, Conn] = co_await Preview::Vless::Connect(
                                      Upstream,
                                      Config,
                                      Preview::Vless::Address{
                                          Preview::Vless::AddressType::Domain,
                                          "t.internal",
                                          443});
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              },
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Vless::ServerConfig Config;
                                  Config.uuid = Uuid;
                                  auto [ErrorCode, Request, Conn] = co_await Preview::Vless::Accept(
                                      Upstream,
                                      Config);
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              });
        }
        std::sort(Samples.begin(), Samples.end());
        if (!Gate("vless Conn<->Conn (透传)", TotalBytes, Samples))
        {
            return 1;
        }
    }

    // vmess
    {
        std::array<std::int64_t, 3> Samples{};
        for (std::size_t Index = 0; Index < Samples.size(); ++Index)
        {
            Samples[Index] = BenchConn(BenchOptions{TotalBytes, BlockBytes},
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Vmess::ClientConfig Config;
                                  Config.uuid = Uuid;
                                  auto [ErrorCode, Conn] = co_await Preview::Vmess::Connect(
                                      Upstream,
                                      Config,
                                      Preview::Vmess::Address{
                                          Preview::Vmess::AddressType::Domain,
                                          "t.internal",
                                          443});
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              },
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Vmess::ServerConfig Config;
                                  Config.uuid = Uuid;
                                  auto [ErrorCode, Request, Conn] = co_await Preview::Vmess::Accept(
                                      Upstream,
                                      Config);
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              });
        }
        std::sort(Samples.begin(), Samples.end());
        if (!Gate("vmess Conn<->Conn (加密16KB)", TotalBytes, Samples))
        {
            return 1;
        }
    }

    // ss2022
    {
        std::array<std::int64_t, 3> Samples{};
        for (std::size_t Index = 0; Index < Samples.size(); ++Index)
        {
            Samples[Index] = BenchConn(BenchOptions{TotalBytes, BlockBytes},
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Shadowsocks2022::ClientConfig Config;
                                  Config.password = "prism";
                                  auto [ErrorCode, Conn] = co_await Preview::Shadowsocks2022::Connect(
                                      Upstream,
                                      Config,
                                      Preview::Shadowsocks2022::Address{
                                          Preview::Shadowsocks2022::AddressType::Domain,
                                          "t.internal",
                                          443});
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              },
                              [&](auto Upstream) -> Net::awaitable<Preview::SharedTransmission>
                              {
                                  Preview::Shadowsocks2022::ServerConfig Config;
                                  Config.password = "prism";
                                  auto [ErrorCode, Request, Conn] = co_await Preview::Shadowsocks2022::Accept(
                                      Upstream,
                                      Config);
                                  co_return ToTransmission(ErrorCode, std::move(Conn));
                              });
        }
        std::sort(Samples.begin(), Samples.end());
        if (!Gate("ss2022 Conn<->Conn (加密16KB)", TotalBytes, Samples))
        {
            return 1;
        }
    }
    std::printf("AllProtoTransfer: ALL PASS\n");
    return 0;
}
