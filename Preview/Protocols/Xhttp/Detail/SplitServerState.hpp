/**
 * @file SplitServerState.hpp
 * @brief XHTTP Stream-up 与 Packet-up 服务端的共享 owning 状态。
 * @details 该状态由接受工厂、帧回调和单一 HTTP/2 driver 在同一 executor 使用。
 */
#pragma once

#include <Preview/Protocols/Xhttp/Detail/Common.hpp>
#include <Preview/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Preview/Protocols/Xhttp/Detail/SplitTransport.hpp>
#include <Preview/Protocols/Xhttp/Detail/Wire.hpp>
#include <Preview/Transport/Encrypted.hpp>

#include <boost/asio/experimental/channel.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Preview::Xhttp::Detail
{
    using SplitReadyChannel = Net::experimental::channel<
        void(boost::system::error_code, Preview::Fault::Failure, bool)>;

    /**
     * @struct SplitServerState
     * @brief 持有 split carrier 的 HTTP/2 stream、driver 与缓冲状态。
     */
    struct SplitServerState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<SplitReadyChannel> Ready;
        std::shared_ptr<DriverCompletionChannel> DriverDone;
        std::shared_ptr<SplitTransport> Transport;
        Config Cfg;
        std::string SessionId;
        std::int32_t UploadStream{-1};
        std::int32_t DownloadStream{-1};
        bool DriverStarted{false};
        bool DriverCompleted{false};
        Preview::Fault::Failure DriverFailure;
        bool UploadEnded{false};
        bool ReadySignaled{false};
        std::vector<std::vector<std::byte>> PendingUpload;
        std::map<std::int32_t, std::vector<std::byte>> PacketBodies;
        Preview::Fault::Failure CloseFailure;

        [[nodiscard]] auto CloseAndDrain() -> Net::awaitable<FactoryRetirementReceipt>;
    };
} // namespace Preview::Xhttp::Detail
