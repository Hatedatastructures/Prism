/**
 * @file NativeTls.hpp
 * @brief Preview 的原生 TLS admission 适配。
 * @details 只负责识别入站连接是否以 TLS ClientHello 开始，并在同一
 *          executor 上完成服务端握手。非 TLS 数据会使用回放传输原样
 *          交还给上层协议识别器，不改变代理数据面。
 */
#pragma once

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Transport/Encrypted.hpp>
#include <Preview/Transport/Preview.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>

namespace Preview::Transport
{

    namespace Net = boost::asio;

    struct NativeTlsResult final
    {
        Preview::Fault::Code Code{Preview::Fault::Code::Success};
        SharedTransmission Transport{};
        boost::system::error_code NativeError{};
        bool Attempted{false};
    };

    struct NativeTlsRequest final
    {
        SharedTransmission Inbound{};
        std::shared_ptr<Net::ssl::context> Context{};
        std::chrono::steady_clock::duration Timeout{Encrypted::DefaultHandshakeTimeout};
    };

    /**
     * @brief 按首两个字节选择裸流或 Native TLS。
     * @param Inbound 入站传输，所有权转移。
     * @param Context 可选的服务端 TLS context；为空时保持裸流。
     * @return 传输结果；非 TLS 输入会完整回放已预读字节。
     */
    [[nodiscard]] inline auto UpgradeNativeTls(NativeTlsRequest Request) -> Net::awaitable<NativeTlsResult>
    {
        auto Inbound = std::move(Request.Inbound);
        auto Context = std::move(Request.Context);
        NativeTlsResult Result;
        if (!Inbound)
        {
            Result.Transport = std::move(Inbound);
            co_return Result;
        }
        if (Request.Timeout <= std::chrono::steady_clock::duration::zero())
        {
            Result.Code = Preview::Fault::Code::Timeout;
            Inbound->Cancel();
            Inbound->Close();
            co_return Result;
        }
        if (!Context)
        {
            Result.Transport = std::move(Inbound);
            co_return Result;
        }

        std::array<std::byte, 2> Prefix{};
        std::size_t ReadBytes = 0;
        while (ReadBytes < Prefix.size())
        {
            std::error_code Error;
            const auto Count = co_await Inbound->async_read_some(
                std::span<std::byte>(Prefix).subspan(ReadBytes), Error);
            if (Count > Prefix.size() - ReadBytes)
            {
                Result.Code = Preview::Fault::Code::IoError;
                Inbound->Close();
                co_return Result;
            }
            ReadBytes += Count;

            // 先按已经取得的字节完成非 TLS 分流，再处理同一次读取携带的终止错误，
            // 确保已取得的前缀始终由回放传输继续持有。
            if (ReadBytes == 1 && std::to_integer<unsigned char>(Prefix[0]) != 0x16U)
            {
                Result.Transport = WrapWithPreview(std::move(Inbound),
                                                   std::span<const std::byte>(Prefix).first(1));
                co_return Result;
            }

            if (ReadBytes == Prefix.size())
            {
                const auto First = std::to_integer<unsigned char>(Prefix[0]);
                const auto Second = std::to_integer<unsigned char>(Prefix[1]);
                if (First != 0x16U || Second != 0x03U)
                {
                    Result.Transport = WrapWithPreview(std::move(Inbound), Prefix);
                    co_return Result;
                }
            }

            if (Error || Count == 0)
            {
                Result.Code = Preview::Fault::ToCode(Error);
                if (Result.Code == Preview::Fault::Code::Success)
                {
                    Result.Code = Preview::Fault::Code::Eof;
                }
                Inbound->Close();
                co_return Result;
            }
        }

        const auto First = std::to_integer<unsigned char>(Prefix[0]);
        const auto Second = std::to_integer<unsigned char>(Prefix[1]);
        if (First != 0x16U || Second != 0x03U)
        {
            Result.Transport = WrapWithPreview(std::move(Inbound), Prefix);
            co_return Result;
        }

        Result.Attempted = true;
        auto Replayed = WrapWithPreview(std::move(Inbound), Prefix);
        auto Handshake = co_await Encrypted::SslHandshakeDetailed(
            Encrypted::HandshakeRequest{std::move(Replayed), Context, Request.Timeout});
        Result.Code = Handshake.Code;
        Result.NativeError = Handshake.NativeError;
        if (Handshake.Code == Preview::Fault::Code::Success && Handshake.Stream)
        {
            Result.Transport = MakeEncrypted(std::move(Handshake.Stream));
            co_return Result;
        }
        if (Handshake.Recovered)
        {
            Handshake.Recovered->Cancel();
            Handshake.Recovered->Close();
        }
        co_return Result;
    }

    [[nodiscard]] inline auto UpgradeNativeTls(
        SharedTransmission Inbound,
        const std::shared_ptr<Net::ssl::context> &Context) -> Net::awaitable<NativeTlsResult>
    {
        return UpgradeNativeTls(NativeTlsRequest{std::move(Inbound), Context});
    }

} // namespace Preview::Transport
