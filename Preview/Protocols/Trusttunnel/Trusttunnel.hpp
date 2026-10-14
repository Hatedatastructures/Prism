/**
 * @file Trusttunnel.hpp
 * @brief TrustTunnel 唯一 public stream/datagram factory。
 * @details 请求按值拥有握手输入；成功结果含目标和唯一 connection/datagram owner。
 *          失败以 Fault::Failure 返回，由 factory Cancel、Close 并等待 Activity Drain。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Conn.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Conn.hpp>
#include <Preview/Protocols/Trusttunnel/Dgram.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Dgram.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>

#include <expected>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <system_error>
#include <utility>

namespace Preview::Trusttunnel
{
    struct ConnectParameters final
    {
        SharedTransmission Upstream;
        ClientConfig Configuration;
        std::string Target;
        std::uint16_t Port{0};
    };

    struct AcceptedConnection final
    {
        std::string Target;
        SharedConn Connection;
    };

    struct AcceptedDatagram final
    {
        std::string Target;
        SharedDgram Datagram;
    };

    /**
     * @brief 建立带 Basic Auth 的 TCP CONNECT。
     * @param Parameters 按值拥有上游、认证配置、目标和端口，覆盖全部挂起握手时段。
     * @return 唯一 expected 结果；失败保留 Code/Native，工厂执行 Cancel、Close 与 Activity Drain。
     * @details executor 固定为上游原 executor；成功 Conn 拥有唯一连接，WriteShutdown 保留反向读取，
     *          最终 Close 由调用者发起并通过 Activity Drain 等待实际退出。
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedConn, Preview::Fault::Failure>>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Parameters.Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Detail::Conn<>::Create(ConnRequest{
                std::move(Parameters.Upstream),
                Parameters.Configuration.username,
                Parameters.Configuration.password});
            if (!Created)
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            auto Connection = std::move(*Created);
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Preview::Transmission>(Connection));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            const auto Handshake = co_await Connection->WriteHandshake(Parameters.Target, Parameters.Port);
            if (!Handshake)
            {
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            }
            Admission.Release();
            co_return Connection;
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Preview::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    /**
     * @brief 建立 CONNECT 后的数据报装饰器。
     * @param Parameters 按值拥有上游、配置和目标；配置跨异步握手期间保持有效。
     * @return 唯一 expected 结果；失败退休同一 connection owner，成功值只保留 Dgram owner。
     * @details 使用上游 executor；半关闭由 Dgram/Conn 的传输语义决定，最终 Close 与 Activity Drain 归调用者。
     */
    [[nodiscard]] inline auto ConnectPacket(ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedDgram, Preview::Fault::Failure>>
    {
        auto Connected = co_await Connect(std::move(Parameters));
        if (!Connected) co_return std::unexpected(Connected.error());
        auto Connection = std::move(*Connected);
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(
            std::static_pointer_cast<Preview::Transmission>(Connection));
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Detail::Dgram::Create(
                DgramRequest{std::static_pointer_cast<Preview::Transmission>(Connection)});
            if (!Created)
            {
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            }
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Preview::Transmission>(*Created));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            Connection.reset();
            Admission.Release();
            co_return SharedDgram(std::move(*Created));
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Preview::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    /**
     * @brief 接收服务端 CONNECT 并验证 Basic Auth。
     * @param Upstream 按值接管的单一上游传输。
     * @param Configuration 按值拥有的认证配置，在协程挂起期间有效。
     * @return 唯一 expected 结果；成功值同时拥有请求目标和 stream，失败保留 Code/Native 且完成清理。
     * @details 握手与失败清理使用上游原 executor；成功半关闭只关本端写方向，最终 Close/Drain 归调用者。
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        ServerConfig Configuration)
        -> Net::awaitable<std::expected<AcceptedConnection, Preview::Fault::Failure>>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Detail::Conn<>::Create(ConnRequest{
                std::move(Upstream), Configuration.username, Configuration.password});
            if (!Created)
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            auto Connection = std::move(*Created);
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Preview::Transmission>(Connection));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            std::string Target;
            const auto Handshake = co_await Connection->ReadHandshake(Target);
            if (!Handshake)
            {
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            }
            Admission.Release();
            co_return AcceptedConnection{std::move(Target), std::move(Connection)};
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Preview::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    /**
     * @brief 接收服务端 CONNECT 并创建 datagram owner。
     * @param Upstream 按值接管的单一上游传输。
     * @param Configuration 按值拥有的认证配置。
     * @return 唯一 expected 结果；失败由 factory 关闭并排空 connection，成功只留下拥有它的 Dgram。
     * @details 使用上游原 executor；最终关闭与 Activity Drain 由成功 Dgram 的调用者负责。
     */
    [[nodiscard]] inline auto AcceptPacket(
        SharedTransmission Upstream,
        ServerConfig Configuration)
        -> Net::awaitable<std::expected<AcceptedDatagram, Preview::Fault::Failure>>
    {
        auto Accepted = co_await Accept(std::move(Upstream), std::move(Configuration));
        if (!Accepted) co_return std::unexpected(Accepted.error());
        auto Result = std::move(*Accepted);
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(
            std::static_pointer_cast<Preview::Transmission>(Result.Connection));
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Detail::Dgram::Create(
                DgramRequest{std::static_pointer_cast<Preview::Transmission>(Result.Connection)});
            if (!Created)
            {
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            }
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Preview::Transmission>(*Created));
            if (!Tracked)
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            Result.Connection.reset();
            Admission.Release();
            co_return AcceptedDatagram{std::move(Result.Target), SharedDgram(std::move(*Created))};
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Preview::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }
} // namespace Preview::Trusttunnel
