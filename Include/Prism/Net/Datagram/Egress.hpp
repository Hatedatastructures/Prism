/**
 * @file Egress.hpp
 * @brief 拥有私有 UDP socket 的通用解析、交换和回包服务。
 */
#pragma once

#include <Prism/Contract/Services/Datagram/Egress.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>

namespace Prism::Network::Dns
{
    class Resolver;
}

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
        explicit DatagramEgress(std::shared_ptr<Prism::Network::Dns::Resolver> Resolver);

        /**
         * @brief 执行一次拥有型 UDP 交换。
         * @param Request 目标、payload、账户和超时预算；调用后由返回协程帧接管。
         * @return source、reply payload、上传字节数及唯一 Failure；DNS、socket、timeout/native cause 不被压平。
         * @note 调用同步复制 Resolver owner 后才创建 awaitable，服务对象可在交换期间释放。
         */
        [[nodiscard]] auto Exchange(Prism::Contract::DatagramExchangeRequest Request)
            -> Net::awaitable<Prism::Contract::DatagramExchangeResult> override;

    private:
        struct ExchangeProgress;

        [[nodiscard]] static auto ExchangeOwned(
            std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner,
            Prism::Contract::DatagramExchangeRequest Request)
            -> Net::awaitable<Prism::Contract::DatagramExchangeResult>;

        [[nodiscard]] static auto ExchangeCore(
            std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner,
            Prism::Contract::DatagramExchangeRequest Request,
            const std::shared_ptr<ExchangeProgress> &Progress)
            -> Net::awaitable<Prism::Contract::DatagramExchangeResult>;

        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver_;
    };
} // namespace Prism::Network
