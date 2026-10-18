/** @file InteropProviderDatagrams.cpp @brief 实际 Prism listener 的 SOCKS BND/control 与 SS raw 客户端。 */
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <Prism/Protocols/Socks5/Codec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Codec.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>
#include <array>
#include <cstdio>
#include <cstring>
namespace Net=boost::asio;
using Udp=Net::ip::udp;using Tcp=Net::ip::tcp;
namespace Ss=Prism::Shadowsocks2022;
constexpr std::string_view Payload="prepared-provider-real-udp-payload";
auto ReceiveCore(Udp::socket& Socket,std::span<std::uint8_t> Buffer)
    ->Net::awaitable<std::pair<std::size_t,boost::system::error_code>>
{
    Net::steady_timer Deadline(co_await Net::this_coro::executor);
    Deadline.expires_after(std::chrono::milliseconds(800));
    Udp::endpoint Peer;boost::system::error_code ErrorValue;
    using Net::experimental::awaitable_operators::operator||;
    auto Result=co_await(Socket.async_receive_from(Net::buffer(Buffer.data(),Buffer.size()),Peer,
        Net::redirect_error(Net::use_awaitable,ErrorValue))||Deadline.async_wait(Net::use_awaitable));
    if(Result.index()==1)co_return std::pair{std::size_t{0},boost::system::error_code(Net::error::timed_out)};
    co_return std::pair{std::get<0>(Result),ErrorValue};
}
auto Receive(Udp::socket& Socket,std::span<std::uint8_t> Buffer)
    ->std::pair<std::size_t,boost::system::error_code>
{
    auto& Io=static_cast<Net::io_context&>(Socket.get_executor().context());Io.restart();
    std::pair<std::size_t,boost::system::error_code> Result;std::exception_ptr Failure;
    Net::co_spawn(Io,ReceiveCore(Socket,Buffer),[&](std::exception_ptr Error,auto Value){Failure=Error;Result=Value;});
    Io.run();if(Failure)std::rethrow_exception(Failure);return Result;
}
auto Socks(Net::io_context& Io,char** Args)->int
{
    const auto Port=static_cast<unsigned short>(std::stoi(Args[2]));
    const auto Echo=static_cast<unsigned short>(std::stoi(Args[3]));
    Tcp::socket Control(Io);Control.connect({Net::ip::address_v4::loopback(),Port});
    const std::array<std::uint8_t,3> Greeting{5,1,2};Net::write(Control,Net::buffer(Greeting));
    std::array<std::uint8_t,2> Method{};Net::read(Control,Net::buffer(Method));if(Method!=std::array<std::uint8_t,2>{5,2})return 1;
    const auto Auth=Prism::Socks5::BuildUserpass("user",Args[4]);Net::write(Control,Net::buffer(Auth));
    Net::read(Control,Net::buffer(Method));if(Method[1])return 1;
    const std::array<std::uint8_t,10> Associate{5,3,0,1,0,0,0,0,0,0};Net::write(Control,Net::buffer(Associate));
    std::array<std::uint8_t,10> Reply{};Net::read(Control,Net::buffer(Reply));if(Reply[1] || Reply[3]!=1)return 1;
    const unsigned short Bound=static_cast<unsigned short>((Reply[8]<<8)|Reply[9]);
    Udp::socket Client(Io,Udp::endpoint(Net::ip::address_v4::loopback(),0));
    const Prism::Socks5::Address Target{Prism::Socks5::AddressType::Ipv4,"127.0.0.1",Echo};
    const auto Wire=Prism::Socks5::BuildUdpDatagram(Target,std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(Payload.data()),Payload.size()));
    Client.send_to(Net::buffer(Wire),{Net::ip::address_v4::loopback(),Bound});
    std::array<std::uint8_t,4096> Response{};const auto [Size,ReceiveError]=Receive(Client,Response);if(ReceiveError)return 1;
    Prism::Socks5::Address Source;std::span<const std::uint8_t> Plain;
    if(Prism::Socks5::ParseUdpDatagram(std::span(Response).first(Size),Source,Plain)!=Prism::Error::None
        || Plain.size()!=Payload.size() || std::memcmp(Plain.data(),Payload.data(),Plain.size()))return 1;
    Control.shutdown(Tcp::socket::shutdown_send);
    std::array<std::uint8_t,1> EofProbe{};boost::system::error_code EofError;
    const auto EofBytes=Control.read_some(Net::buffer(EofProbe),EofError);
    if(EofBytes || EofError!=Net::error::eof)return 1;
    Control.close();Client.send_to(Net::buffer(Wire),{Net::ip::address_v4::loopback(),Bound});
    const auto ErrorValue=Receive(Client,Response).second;
    if(!ErrorValue)return 1;
    std::printf("PASS: socksudp bytes=%zu payload=%.*s BND_PORT=%u controlEOF_no_response=true\n",
        Plain.size(),static_cast<int>(Payload.size()),Payload.data(),Bound);return 0;
}
auto Raw(Net::io_context& Io,char** Args)->int
{
    const auto Port=static_cast<unsigned short>(std::stoi(Args[2]));
    const auto Echo=static_cast<unsigned short>(std::stoi(Args[3]));
    const auto Bytes=Prism::Crypto::Base64Decode(Args[4]);if(Bytes.size()!=16)return 2;
    std::array<std::uint8_t,16> Key{};std::memcpy(Key.data(),Bytes.data(),16);
    const Ss::Address Target{Ss::AddressType::Ipv4,"127.0.0.1",Echo};
    Udp::socket Client(Io,Udp::endpoint(Net::ip::address_v4::loopback(),0));
    std::vector<std::uint8_t> Wire;
    for(std::uint64_t Id=0;Id<2048;++Id)
    {
        Wire=Ss::BuildUdpPacket(Ss::UdpBuildInput{Key,Id,&Target,std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(Payload.data()),Payload.size())});
        if((Wire[0]&0xC0)==0x40)break;
    }
    if((Wire[0]&0xC0)!=0x40)return 1;
    Client.send_to(Net::buffer(Wire),{Net::ip::address_v4::loopback(),Port});
    std::array<std::uint8_t,4096> Response{};auto [Size,ErrorValue]=Receive(Client,Response);
    if(std::string_view(Args[1])=="ssbad")
    { if(!ErrorValue)return 1;std::printf("PASS: ssbad no_response=true\n");return 0; }
    if(ErrorValue)return 1;
    Ss::Address Source;std::vector<std::uint8_t> Plain;std::uint8_t Type=0;
    if(Ss::ParseUdpPacket(Ss::UdpParseInput{Key,std::span(Response).first(Size),&Source,&Plain,nullptr,nullptr,
        nullptr,&Type})!=Prism::Error::None || Type!=Ss::HeaderTypeServer || Plain.size()!=Payload.size()
        || std::memcmp(Plain.data(),Payload.data(),Plain.size()))return 1;
    Client.send_to(Net::buffer(Wire),{Net::ip::address_v4::loopback(),Port});
    ErrorValue=Receive(Client,Response).second;if(!ErrorValue)return 1;
    std::printf("PASS: ssudp bytes=%zu payload=%.*s quic_like=true replay_no_response=true\n",
        Plain.size(),static_cast<int>(Payload.size()),Payload.data());return 0;
}
auto main(int Count,char** Args)->int
{
    if(Count!=5)return 2;
    try{Net::io_context Io;return std::string_view(Args[1])=="socksudp"?Socks(Io,Args):Raw(Io,Args);}
    catch(const std::exception& ErrorValue){std::fprintf(stderr,"FAIL: %s\n",ErrorValue.what());return 1;}
}
