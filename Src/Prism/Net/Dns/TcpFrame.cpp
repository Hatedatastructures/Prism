/** @file TcpFrame.cpp @brief DNS TCP/DoT 帧编码实现。 */
#include <Prism/Net/Dns/Detail/Wire.hpp>

#include <boost/system/errc.hpp>

namespace Prism::Network::Dns::Detail
{
    auto MakeTcpFrame(const std::span<const std::uint8_t> Wire)
        -> EcResult<std::vector<std::uint8_t>>
    {
        if (Wire.size() > MaxFrameBytes)
        {
            return std::unexpected(
                boost::system::errc::make_error_code(boost::system::errc::message_size));
        }
        std::vector<std::uint8_t> Frame;
        Frame.reserve(Wire.size() + 2);
        Frame.push_back(static_cast<std::uint8_t>(Wire.size() >> 8));
        Frame.push_back(static_cast<std::uint8_t>(Wire.size() & 0xFF));
        Frame.insert(Frame.end(), Wire.begin(), Wire.end());
        return Frame;
    }
}
