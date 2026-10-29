/** @file DatagramTestSupport.hpp @brief Trojan UDP 会话测试构造辅助。 */
#pragma once

#include <Prism/Protocols/Trojan/Datagram/Session.hpp>

#include <memory>
#include <stdexcept>
#include <utility>

namespace Prism::Testing::TrojanDatagram
{
    /** @brief 创建测试 carrier 的会话；无效 fixture 作为测试 setup 错误抛出。 */
    [[nodiscard]] inline auto MakeSession(
        std::shared_ptr<Prism::Trojan::Dgram<>> Carrier,
        Prism::Trojan::DatagramSession::Options Options)
        -> std::shared_ptr<Prism::Trojan::DatagramSession>
    {
        auto Result = Prism::Trojan::DatagramSession::Create(
            std::move(Carrier), std::move(Options));
        if (!Result)
        {
            throw std::logic_error("valid Trojan datagram test carrier was rejected");
        }
        return std::move(*Result);
    }
} // namespace Prism::Testing::TrojanDatagram
