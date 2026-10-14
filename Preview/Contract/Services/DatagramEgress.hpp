/** @file DatagramEgress.hpp @brief 解析/交换和回包的独立数据报服务端口。 */
#pragma once
#include <Preview/Contract/Services/Datagram.hpp>
#include <Preview/Contract/Ingress/RawDatagramIngress.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
namespace Preview::Contract
{
    struct DatagramExchangeRequest final
    {
        Preview::Network::Target Target;
        std::vector<std::byte> Payload;
        Preview::AccountId AccountId;
        std::chrono::milliseconds Timeout{2000};
    };
    struct DatagramExchangeResult final
    {
        Preview::Fault::Failure Failure{Preview::Fault::Code::IoError, {}}; ///< 唯一失败值；成功时实现显式写入成功值。
        boost::asio::ip::udp::endpoint Source;
        std::vector<std::byte> Payload;
        std::size_t Uploaded{0}; ///< 已发送进度；后续接收失败时仍保留。
    };
    /**
     * @brief 接管请求字节并返回数据报交换结果。
     * @details 实现使用调用者当前 executor；取消与 timeout 作为唯一 Failure 返回。若发送完成而接收失败，
     *          返回仍包含已发送字节数，因而错误与部分进度由同一结果值携带。UDP 无半关闭；服务实现关闭其私有 socket。
     */
    class DatagramEgress
    {
    public:
        virtual ~DatagramEgress() = default;
        [[nodiscard]] virtual auto Exchange(DatagramExchangeRequest Request)
            -> boost::asio::awaitable<DatagramExchangeResult> = 0;
    };
    /** @brief 接管回包字节到发送完成；sender 借用公共 socket，不拥有关闭权，无半关闭。 */
    class DatagramSender
    {
    public:
        virtual ~DatagramSender() = default;
        [[nodiscard]] virtual auto Send(DatagramPacket Packet)
            -> boost::asio::awaitable<boost::system::error_code> = 0;
    };
}
