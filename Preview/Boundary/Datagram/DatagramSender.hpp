/** @file DatagramSender.hpp @brief 公共 Boundary socket 的中立回包服务；不授予协议关闭权。 */
#pragma once
#include <Preview/Contract/Services/DatagramEgress.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
namespace Preview::Boundary
{
    class DatagramSender final : public Preview::Contract::DatagramSender
    {
    public:
        explicit DatagramSender(std::shared_ptr<boost::asio::ip::udp::socket> Socket):Socket_(Socket){}
        /** @brief 接管字节到发送完成，在 socket executor 发包；取消传递，无关闭或 half-close 权。 */
        auto Send(Preview::Contract::DatagramPacket Packet)->boost::asio::awaitable<boost::system::error_code> override
        {
            const auto Socket=Socket_.lock();
            if(!Socket)co_return boost::asio::error::operation_aborted;
            co_return co_await boost::asio::co_spawn(Socket->get_executor(),SendOnExecutor(Socket,std::move(Packet)),
                boost::asio::use_awaitable);
        }
    private:
        static auto SendOnExecutor(std::shared_ptr<boost::asio::ip::udp::socket> Socket,
            Preview::Contract::DatagramPacket Packet)->boost::asio::awaitable<boost::system::error_code>
        {
            if(!Socket->is_open())co_return boost::asio::error::operation_aborted;
            boost::system::error_code ErrorValue;
            co_await Socket->async_send_to(boost::asio::buffer(Packet.Payload),Packet.Peer,
                boost::asio::redirect_error(boost::asio::use_awaitable,ErrorValue));
            co_return ErrorValue;
        }
        std::weak_ptr<boost::asio::ip::udp::socket> Socket_;
    };
}
