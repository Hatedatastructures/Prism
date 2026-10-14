/**
 * @file StreamClientState.hpp
 * @brief XHTTP Stream-one 客户端的生命周期状态 owner。
 * @details 状态持有加密流、HTTP/2 session、wire writer 与逻辑传输；关闭先提交，
 *          再等待写队列、加密活动和 driver 全部退栈。
 */
#pragma once

#include <Preview/Protocols/Xhttp/Detail/Common.hpp>
#include <Preview/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Preview/Protocols/Xhttp/Detail/StreamTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/Wire.hpp>
#include <Preview/Transport/Encrypted.hpp>

#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <exception>
#include <memory>

namespace Preview::Xhttp::Detail
{
    struct ClientState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<XhttpTransport> Transport;
        std::shared_ptr<ResponseChannel> Response;
        std::shared_ptr<DriverCompletionChannel> DriverDone;
        bool DriverStarted{false};
        bool DriverCompleted{false};
        std::atomic_bool Closing{false};

        [[nodiscard]] auto HasCloseFailure() const noexcept -> bool
        {
            return Transport && Transport->CloseFailure().Failed();
        }

        [[nodiscard]] auto CloseFailureValue() const noexcept -> Preview::Fault::Failure
        {
            if (Transport)
            {
                return Transport->CloseFailure();
            }
            return {};
        }

        [[nodiscard]] auto CloseAndDrain()
            -> Net::awaitable<FactoryRetirementReceipt>
        {
            return Detail::CloseAndDrainState(*this);
        }
    };
} // namespace Preview::Xhttp::Detail
