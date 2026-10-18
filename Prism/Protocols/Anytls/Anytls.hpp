/**
 * @file Anytls.hpp
 * @brief AnyTLS 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，认证帧 + 数据透传）
 * - 编解码/认证：Codec.hpp（密码哈希 + 认证帧编解码）
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <expected>
#include <new>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Anytls/Codec.hpp>
#include <Prism/Protocols/Anytls/Conn.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/Retirement.hpp>
#include <Prism/Protocols/Anytls/Types.hpp>
#include <Prism/Protocols/Anytls/Frame.hpp>

namespace Prism::Anytls
{
    namespace Detail
    {
        /** @brief 捕获握手边界异常并保留标准/Boost 原生身份。 */
        [[nodiscard]] inline auto FailureFromException(const std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure
        {
            try
            {
                if (Exception) std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error &Error)
            {
                return Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error &Error)
            {
                return Prism::Fault::FromNative(Error.code());
            }
            catch (const std::bad_alloc &)
            {
                return {Prism::Fault::Code::ResourceUnavailable};
            }
            catch (...)
            {
                return {Prism::Fault::Code::IoError};
            }
            return {Prism::Fault::Code::IoError};
        }

        /** @brief 保留握手首因类别，并在首因缺 Native 时补入清理观察到的原生 cause。 */
        static auto PreserveNative(
            Prism::Fault::Failure &Primary,
            const Prism::Fault::Failure &Cleanup) noexcept -> void
        {
            if (!Primary.Native && Cleanup.Native) Primary.Native = Cleanup.Native;
        }

        /** @brief 构造 Conn 失败时也用预留 owner 关闭并 drain 原始传输。 */
        [[nodiscard]] inline auto RetireConstructionFailure(
            const std::shared_ptr<Detail::TransportRetirement> &Retirement,
            const SharedTransmission &Upstream,
            Prism::Fault::Failure Primary)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            auto Transport = Upstream;
            const auto Attached = Retirement->Attach(
                std::move(Transport), Prism::Account::StreamLease{});
            if (!Attached)
            {
                PreserveNative(Primary, Attached.error());
                co_return Primary;
            }
            Retirement->RetainForRetry();
            try
            {
                const auto Retired = co_await Retirement->RetireAndDrain();
                if (!Retired) PreserveNative(Primary, Retired.error());
            }
            catch (...)
            {
                Retirement->RequestRetirement();
                PreserveNative(Primary, FailureFromException(std::current_exception()));
            }
            co_return Primary;
        }
    }

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief AnyTLS 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端认证密码
        std::string Password;
    };

    /**
     * @struct ServerConfig
     * @brief AnyTLS 服务端配置
     * @details 控制服务端的行为：认证密码。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端认证密码
        std::string Password;
    };

    namespace Detail
    {
        /** @brief 使用调用方预留 owner 完成服务端握手，失败时同一 owner 持有实物至退休。 */
        [[nodiscard]] inline auto AcceptWithRetirement(
            SharedTransmission Upstream,
            const ServerConfig &Config,
            const std::shared_ptr<Detail::TransportRetirement> &Retirement)
            -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
        {
            if (!Upstream || !Retirement)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            SharedConn Connection;
            std::exception_ptr ConstructionFailure;
            try
            {
                Connection = std::make_shared<Conn<>>(Upstream, Config.Password);
            }
            catch (...)
            {
                ConstructionFailure = std::current_exception();
            }
            if (ConstructionFailure)
            {
                const auto Failure = co_await RetireConstructionFailure(
                    Retirement, Upstream, FailureFromException(ConstructionFailure));
                co_return std::unexpected(Failure);
            }
            auto Attached = Retirement->Attach(
                std::static_pointer_cast<Prism::Transmission>(Connection),
                Prism::Account::StreamLease{});
            if (!Attached) co_return std::unexpected(Attached.error());
            Upstream.reset();

            std::expected<void, Prism::Fault::Failure> Handshake;
            try { Handshake = co_await Connection->ReadHandshake(); }
            catch (...)
            {
                Handshake = std::unexpected(FailureFromException(std::current_exception()));
            }
            if (!Handshake)
            {
                auto Failure = Handshake.error();
                Retirement->RetainForRetry();
                try
                {
                    const auto Retired = co_await Retirement->RetireAndDrain();
                    if (!Retired) PreserveNative(Failure, Retired.error());
                }
                catch (...)
                {
                    Retirement->RequestRetirement();
                    PreserveNative(Failure, FailureFromException(std::current_exception()));
                }
                co_return std::unexpected(Failure);
            }
            co_return Connection;
        }
    }

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @return 成功时唯一协议连接；失败时唯一 Fault::Failure，Native 保留底层首因
     * @details 输入传输在调用时移交；partial write/取消失败会先由预构造 retirement owner
     *          取消、关闭并等待所有 Activity 真实退栈。成功连接由调用者拥有并负责后续半关闭/最终关闭。
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = Detail::TransportRetirement::Prepare();
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Retirement = std::move(*Prepared);
        SharedConn Connection;
        std::exception_ptr ConstructionFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(Upstream, Config.Password);
        }
        catch (...)
        {
            ConstructionFailure = std::current_exception();
        }
        if (ConstructionFailure)
        {
            auto Failure = co_await Detail::RetireConstructionFailure(
                Retirement, Upstream, Detail::FailureFromException(ConstructionFailure));
            co_return std::unexpected(Failure);
        }
        auto Attached = Retirement->Attach(
            std::static_pointer_cast<Prism::Transmission>(Connection),
            Prism::Account::StreamLease{});
        if (!Attached) co_return std::unexpected(Attached.error());
        Upstream.reset();

        std::expected<void, Prism::Fault::Failure> Handshake;
        try { Handshake = co_await Connection->WriteHandshake(); }
        catch (...) { Handshake = std::unexpected(
            Detail::FailureFromException(std::current_exception())); }
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            Retirement->RetainForRetry();
            try
            {
                const auto Retired = co_await Retirement->RetireAndDrain();
                if (!Retired) Detail::PreserveNative(Failure, Retired.error());
            }
            catch (...)
            {
                Retirement->RequestRetirement();
                Detail::PreserveNative(
                    Failure, Detail::FailureFromException(std::current_exception()));
            }
            co_return std::unexpected(Failure);
        }
        co_return Connection;
    }

    /**
     * @brief 接收服务端流连接并完成认证校验
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 成功时唯一协议连接；失败时唯一 Fault::Failure，Native 保留底层首因
     * @details 输入传输在调用时移交；partial read、EOF、取消和坏口令互不折叠。失败时预构造
     *          owner 负责取消、最终关闭及全部 Activity 真实退栈，executor 为上游固定 executor。
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = Detail::TransportRetirement::Prepare();
        if (!Prepared) co_return std::unexpected(Prepared.error());
        co_return co_await Detail::AcceptWithRetirement(
            std::move(Upstream), Config, *Prepared);
    }

} // namespace Prism::Anytls
