/**
 * @file TypedResult.hpp
 * @brief 旧 handler 接口到 typed data-plane 结果的唯一转换点。
 * @details 该转换只依赖 Runtime contract 和通用 Transmission。它不按协议
 *          dynamic_cast，也不把 production handler 作为失败回退。
 */

#pragma once

#include <functional>
#include <string>
#include <utility>

#include <Preview/Composition/Adapters/DataPlane.hpp>
#include <Preview/Runtime/Contract/Handler.hpp>

namespace Preview::Composition::Adapters
{

    namespace Net = boost::asio;

    struct TypedAcceptResult
    {
        Preview::Error Status{Preview::Error::None};
        Preview::Network::Target Target;
        DataPlaneResult Data;
        std::string identity;
        Preview::AccountId AccountId{};
        bool ProtocolAuthenticated{false};
        Preview::Account::AccountLease AccountLease{};
        std::function<Net::awaitable<void>(Preview::Fault::Code)> PostDial;
    };

    /**
     * @brief 检查协议成功结果是否携带完整 typed 账户认证
     * @param Result 协议处理器结果
     * @return 未声明协议认证，或同时具备账户身份和有效租约时返回 true
     */
    [[nodiscard]] inline auto HasValidProtocolAuthentication(
        const Preview::Runtime::Handler::AcceptResult &Result) noexcept -> bool
    {
        if (!Result.ProtocolAuthenticated)
        {
            return true;
        }
        if (!Result.AccountLeaseRequired)
        {
            return true;
        }
        const auto HasLease = static_cast<bool>(Result.AccountLease) ||
                              (Result.DataPlane.AccountLease &&
                               static_cast<bool>(*Result.DataPlane.AccountLease));
        return (static_cast<bool>(Result.AccountId) || static_cast<bool>(Result.DataPlane.AccountId)) &&
               HasLease;
    }

    /**
     * @brief 清理并拒绝半认证结果
     * @param Result 待清理的协议结果
     * @details 关闭所有已产生的传输，释放租约并丢弃身份文本；不把凭据
     *          或认证失败原因写入可观察身份字段。
     */
    inline auto RejectProtocolAuthentication(
        Preview::Runtime::Handler::AcceptResult &Result) noexcept -> void
    {
        if (Result.Transmission)
        {
            Result.Transmission->Close();
        }
        if (const auto Transport = Result.DataPlane.Transport())
        {
            Transport->Close();
        }
        Result.Transmission.reset();
        Result.DataPlane = {};
        Result.AccountLease.Release();
        Result.Target = Preview::Network::Target{};
        Result.AccountId = {};
        Result.identity.clear();
        Result.ProtocolAuthenticated = false;
        Result.AccountLeaseRequired = false;
        Result.IsDgram = false;
        Result.PostDial = {};
        Result.err = Preview::Error::BadAuth;
    }

    /**
     * @brief 在具体协议适配器边界执行认证完整性门禁
     * @param Result 已物化的协议结果
     * @return 结果可继续进入 runtime 时返回 true
     */
    [[nodiscard]] inline auto EnforceProtocolAuthentication(
        Preview::Runtime::Handler::AcceptResult &Result) noexcept -> bool
    {
        if (Result.err == Preview::Error::None &&
            (Result.Transmission || Result.DataPlane.HasTransport()) &&
            !HasValidProtocolAuthentication(Result))
        {
            RejectProtocolAuthentication(Result);
            return false;
        }
        return true;
    }

    /**
     * @brief 在 Composition 边界物化 Runtime 的 typed root data plane。
     * @param Result handler 结果；只在握手成功且有传输时写入。
     * @param Datagram 是否构造数据报根。
     */
    inline auto MaterializeTypedDataPlane(
        Preview::Runtime::Handler::AcceptResult &Result,
        const bool Datagram) -> void
    {
        if (Result.err != Preview::Error::None || !Result.Transmission ||
            Result.DataPlane.HasTransport())
        {
            return;
        }
        Preview::Runtime::ProtocolDataPlane Plane;
        Plane.Target = Result.Target;
        Plane.Identity = Result.identity;
        Plane.AccountId = Result.AccountId;
        Plane.ProtocolAuthenticated = Result.ProtocolAuthenticated;
        Plane.PostDial = Result.PostDial;
        if (Datagram)
        {
            Plane.Root = Preview::Runtime::DatagramDataPlane{Result.Transmission, {}};
        }
        else
        {
            Plane.Root = Preview::Runtime::StreamDataPlane{Result.Transmission};
        }
        Result.DataPlane = std::move(Plane);
    }

    inline auto MaterializeMuxDataPlane(
        Preview::Runtime::Handler::AcceptResult &Result,
        std::string Mode = "auto") -> void
    {
        if (Result.err != Preview::Error::None || !Result.Transmission ||
            Result.DataPlane.HasTransport())
        {
            return;
        }
        Preview::Runtime::ProtocolDataPlane Plane;
        Plane.Root = Preview::Runtime::MuxRootDataPlane{
            Result.Transmission, std::move(Mode)};
        Plane.Target = Result.Target;
        Plane.Identity = Result.identity;
        Plane.AccountId = Result.AccountId;
        Plane.ProtocolAuthenticated = Result.ProtocolAuthenticated;
        if (Result.AccountLease)
        {
            Plane.AccountLease.emplace(std::move(Result.AccountLease));
        }
        Plane.PostDial = std::move(Result.PostDial);
        Result.DataPlane = std::move(Plane);
    }

    /**
     * @brief 将旧 AcceptResult 的数据面标记收敛为 variant 类型。
     * @param Result handler 握手结果（所有权按值移交）。
     * @return 带有 typed stream/datagram data plane 的结果。
     */
    [[nodiscard]] inline auto ToTypedResult(
        Preview::Runtime::Handler::AcceptResult Result) -> TypedAcceptResult
    {
        TypedAcceptResult Typed;
        if (Result.err == Preview::Error::None && Result.Transmission &&
            !HasValidProtocolAuthentication(Result))
        {
            RejectProtocolAuthentication(Result);
        }
        Typed.Status = Result.err;
        Typed.Target = std::move(Result.Target);
        Typed.identity = std::move(Result.identity);
        Typed.AccountId = Result.AccountId;
        Typed.ProtocolAuthenticated = Result.ProtocolAuthenticated;
        Typed.AccountLease = std::move(Result.AccountLease);
        Typed.PostDial = std::move(Result.PostDial);

        if (Result.DataPlane.HasTransport())
        {
            Typed.Data.Data = std::move(Result.DataPlane);
            if (!Typed.AccountId)
            {
                Typed.AccountId = Typed.Data.Data.AccountId;
            }
            if (!Typed.AccountLease && Typed.Data.Data.AccountLease)
            {
                Typed.AccountLease = std::move(*Typed.Data.Data.AccountLease);
            }
            if (Typed.Data.Data.Target.Host.empty() && Typed.Data.Data.Target.Port.empty())
            {
                Typed.Data.Data.Target = Typed.Target;
            }
            return Typed;
        }

        if (!Result.Transmission)
        {
            if (Typed.Status == Preview::Error::None)
            {
                Typed.Status = Preview::Error::IoError;
            }
            Typed.Data = DataPlaneResult::Failure(Typed.Status);
            return Typed;
        }

        if (Typed.Status != Preview::Error::None)
        {
            Result.Transmission->Close();
            Typed.Data = DataPlaneResult::Failure(Typed.Status);
            return Typed;
        }

        if (Result.IsDgram)
        {
            Typed.Data = DataPlaneResult::Datagram(std::move(Result.Transmission));
        }
        else
        {
            Typed.Data = DataPlaneResult::Stream(std::move(Result.Transmission));
        }
        return Typed;
    }

} // namespace Preview::Composition::Adapters
