/**
 * @file WorkerDialService.hpp
 * @brief Worker-owned DNS、地址选择和 TCP outbound 拨号服务。
 * @details Resolver、地址列表和每次 Dial 的临时状态都绑定到 Worker
 *          executor；调用者只提交 owner-held Target，不接触 resolver、
 *          socket 或内部缓存。域名不会落回 Dialer 的系统 resolver。
 */
#pragma once

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Target.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <charconv>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Network::Services
{

    namespace Net = boost::asio;

    struct WorkerDialOptions final
    {
        Net::any_io_executor Executor;
        Preview::Network::Dns::Config Dns;
        std::chrono::milliseconds Timeout{std::chrono::seconds(10)};
        bool EnableIpv6{true};
    };

    class WorkerDialService final
    {
    public:
        explicit WorkerDialService(WorkerDialOptions OptionsValue)
            : Options_(std::move(OptionsValue)),
              Resolver_(std::make_shared<Preview::Network::Dns::Resolver>(
                  Options_.Executor, Options_.Dns))
        {
        }

        [[nodiscard]] auto Connect(Preview::Network::Target Target)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            const std::string Host(Target.Host.data(), Target.Host.size());
            const std::string PortText(Target.Port.data(), Target.Port.size());
            std::uint32_t PortValue = 0;
            const auto [End, ParseError] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), PortValue, 10);
            if (Host.empty() || ParseError != std::errc{} || End != PortText.data() + PortText.size() ||
                PortValue == 0U || PortValue > 65535U)
            {
                co_return std::pair{Preview::Fault::Code::InvalidArgument,
                                    Preview::SharedTransmission{}};
            }

            std::error_code ResolveError;
            std::vector<Net::ip::address> Addresses;
            boost::system::error_code LiteralError;
            const auto Literal = Net::ip::make_address(Host, LiteralError);
            if (!LiteralError)
            {
                Addresses.push_back(Literal);
            }
            else
            {
                ResolveError.clear();
                Addresses = co_await Resolver_->AsyncResolve(Host, ResolveError);
            }
            if (Addresses.empty())
            {
                co_return std::pair{ResolveError ? Preview::Fault::Code::DnsFailed
                                                 : Preview::Fault::Code::DnsFailed,
                                    Preview::SharedTransmission{}};
            }

            std::error_code LastError = ResolveError;
            for (const auto &Address : Addresses)
            {
                if (Address.is_v6() && !Options_.EnableIpv6)
                {
                    continue;
                }
                Preview::Network::Dialer::Dialer Dialer(
                    Options_.Executor,
                    Preview::Network::Dialer::DialOptions{Options_.Timeout, Options_.EnableIpv6});
                std::error_code Error;
                auto Outbound = co_await Dialer.Connect(
                    Address.to_string(), static_cast<std::uint16_t>(PortValue), Error);
                if (Outbound)
                {
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Outbound)};
                }
                LastError = Error;
            }
            if (LastError == std::make_error_code(std::errc::timed_out))
            {
                co_return std::pair{Preview::Fault::Code::Timeout,
                                    Preview::SharedTransmission{}};
            }
            if (LastError == std::make_error_code(std::errc::connection_refused))
            {
                co_return std::pair{Preview::Fault::Code::ConnectionRefused,
                                    Preview::SharedTransmission{}};
            }
            co_return std::pair{Preview::Fault::Code::Unreachable,
                                Preview::SharedTransmission{}};
        }

        [[nodiscard]] auto Resolver() const noexcept
            -> const std::shared_ptr<Preview::Network::Dns::Resolver> &
        {
            return Resolver_;
        }

    private:
        WorkerDialOptions Options_;
        std::shared_ptr<Preview::Network::Dns::Resolver> Resolver_;
    };

} // namespace Preview::Network::Services
