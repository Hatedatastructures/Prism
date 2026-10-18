/**
 * @file SplitClientState.hpp
 * @brief XHTTP Split 客户端的生命周期状态 owner。
 * @details 持有上传/下载 stream 元数据、session、加密流和 wire queue；退休只在
 *          Cancel、Close 与真实 I/O/driver drain 完成后报告成功。
 */
#pragma once

#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Wire.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/this_coro.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace Prism::Xhttp::Detail
{
    struct SplitClientState final
    {
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<SplitTransport> Transport;
        std::shared_ptr<ResponseChannel> Response;
        std::shared_ptr<DriverCompletionChannel> DriverDone;
        Config Cfg;
        std::string Host;
        std::string SessionId;
        std::int32_t UploadStream{-1};
        std::int32_t DownloadStream{-1};
        std::uint64_t NextSequence{0};
        bool DriverStarted{false};
        bool DriverCompleted{false};
        Prism::Fault::Failure CloseFailure;
        bool CloseStarted{false};

        [[nodiscard]] auto CloseAndDrain()
            -> Net::awaitable<FactoryRetirementReceipt>
        {
            return Detail::CloseAndDrainState(*this);
        }
    };
} // namespace Prism::Xhttp::Detail
