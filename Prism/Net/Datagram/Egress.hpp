/**
 * @file Egress.hpp
 * @brief 拥有私有 UDP socket 的通用解析、交换和回包服务。
 */
#pragma once

#include <Prism/Contract/Services/DatagramEgress.hpp>
#include <Prism/Net/Dns/Resolver.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <variant>

namespace Prism::Network
{
    namespace Net = boost::asio;

    /**
     * @class DatagramEgress
     * @brief 以一次交换为边界的 UDP resolve/send/receive owner。
     * @details 输入请求按值接管，Resolver 由共享引用持有，socket 由交换协程的本地对象拥有并关闭。
     *          统一超时覆盖 DNS、发送和接收；当前协程 executor 驱动交换，调用方取消或超时会收束本次操作，
     *          组合分支结束后私有 socket 由协程释放。UDP 不支持数据流半关闭，本服务也不暴露半关闭操作。
     *          返回的 Failure 是唯一错误事实；接收失败时 Uploaded 仍保留已完成发送字节数。
     */
    class DatagramEgress final : public Prism::Contract::DatagramEgress
    {
    public:
        /** @brief 接管 DNS resolver 的共享所有权。 */
        explicit DatagramEgress(std::shared_ptr<Prism::Network::Dns::Resolver> Resolver)
            : Resolver_(std::move(Resolver))
        {
        }

        /**
         * @brief 执行一次拥有型 UDP 交换。
         * @param Request 目标、payload、账户和超时预算；调用后由返回协程帧接管。
         * @return source、reply payload、上传字节数及唯一 Failure；DNS、socket、timeout/native cause 不被压平。
         * @note 调用同步复制 Resolver owner 后才创建 awaitable，服务对象可在交换期间释放。
         */
        [[nodiscard]] auto Exchange(Prism::Contract::DatagramExchangeRequest Request)
            -> Net::awaitable<Prism::Contract::DatagramExchangeResult> override
        {
            return ExchangeOwned(Resolver_, std::move(Request));
        }

    private:
        /** @brief 保留截止或取消竞争前已完成发送的唯一部分进度。 */
        struct ExchangeProgress final
        {
            std::atomic<std::size_t> Uploaded{0};
        };

        [[nodiscard]] static auto ExchangeOwned(
            std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner,
            Prism::Contract::DatagramExchangeRequest Request)
            -> Net::awaitable<Prism::Contract::DatagramExchangeResult>
        {
            const auto Executor = co_await Net::this_coro::executor;
            auto Progress = std::make_shared<ExchangeProgress>();
            Net::steady_timer Deadline(Executor);
            Deadline.expires_after(Request.Timeout);

            try
            {
                using Net::experimental::awaitable_operators::operator||;
                auto Outcome = co_await (
                    ExchangeCore(std::move(ResolverOwner), std::move(Request), Progress) ||
                    Deadline.async_wait(Net::use_awaitable));
                if (Outcome.index() == 1U)
                {
                    Prism::Contract::DatagramExchangeResult Result;
                    Result.Failure = Prism::Fault::Failure{Prism::Fault::Code::Timeout, {}};
                    Result.Uploaded = Progress->Uploaded.load(std::memory_order_acquire);
                    co_return Result;
                }
                co_return std::move(std::get<0>(Outcome));
            }
            catch (const boost::system::system_error &Error)
            {
                Prism::Contract::DatagramExchangeResult Result;
                Result.Failure = Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
                Result.Uploaded = Progress->Uploaded.load(std::memory_order_acquire);
                co_return Result;
            }
            catch (const std::system_error &Error)
            {
                Prism::Contract::DatagramExchangeResult Result;
                Result.Failure = Prism::Fault::FromNative(Error.code());
                Result.Uploaded = Progress->Uploaded.load(std::memory_order_acquire);
                co_return Result;
            }
        }

        [[nodiscard]] static auto ExchangeCore(
            std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner,
            Prism::Contract::DatagramExchangeRequest Request,
            const std::shared_ptr<ExchangeProgress> &Progress)
            -> Net::awaitable<Prism::Contract::DatagramExchangeResult>
        {
            if (Request.Target.Host.Empty() || Request.Target.Port == 0U)
            {
                co_return Prism::Contract::DatagramExchangeResult{
                    .Failure = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}}};
            }

            const auto Literal = Prism::Network::IpAddress(Request.Target.Host);
            std::optional<Net::ip::address> Address;
            if (Literal)
            {
                Address = *Literal;
            }
            else if (ResolverOwner)
            {
                const auto *Domain = std::get_if<Prism::Network::DomainName>(
                    &Request.Target.Host.Get());
                if (Domain == nullptr)
                {
                    co_return Prism::Contract::DatagramExchangeResult{
                        .Failure = Prism::Fault::Failure{
                            Prism::Fault::Code::UnsupportedAddress, {}}};
                }
                const auto Addresses = co_await ResolverOwner->AsyncResolve(Domain->View());
                if (!Addresses)
                {
                    co_return Prism::Contract::DatagramExchangeResult{
                        .Failure = Addresses.error()};
                }
                if (!Addresses->Empty())
                {
                    Address = (*Addresses)[0];
                }
            }
            if (!Address)
            {
                co_return Prism::Contract::DatagramExchangeResult{
                    .Failure = Prism::Fault::Failure{Prism::Fault::Code::DnsFailed, {}}};
            }

            const Net::ip::udp::endpoint Target(*Address, Request.Target.Port);
            const auto Executor = co_await Net::this_coro::executor;
            Net::ip::udp::socket Socket(Executor);
            boost::system::error_code ErrorValue;
            Socket.open(Target.protocol(), ErrorValue);
            if (ErrorValue)
            {
                co_return Prism::Contract::DatagramExchangeResult{
                    .Failure = Prism::Fault::FromNative(static_cast<std::error_code>(ErrorValue))};
            }

            Prism::Contract::DatagramExchangeResult Result;
            Result.Failure = {};
            Result.Uploaded = co_await Socket.async_send_to(
                Net::buffer(Request.Payload), Target,
                Net::redirect_error(Net::use_awaitable, ErrorValue));
            Progress->Uploaded.store(Result.Uploaded, std::memory_order_release);
            if (ErrorValue)
            {
                Result.Failure = Prism::Fault::FromNative(static_cast<std::error_code>(ErrorValue));
                co_return Result;
            }

            Result.Payload.resize(65535U);
            for (;;)
            {
                const auto Received = co_await Socket.async_receive_from(
                    Net::buffer(Result.Payload), Result.Source,
                    Net::redirect_error(Net::use_awaitable, ErrorValue));
                if (ErrorValue)
                {
                    Result.Failure = Prism::Fault::FromNative(
                        static_cast<std::error_code>(ErrorValue));
                    Result.Payload.clear();
                    co_return Result;
                }
                if (Result.Source != Target)
                {
                    continue;
                }
                Result.Payload.resize(Received);
                co_return Result;
            }
        }

        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver_;
    };
} // namespace Prism::Network
