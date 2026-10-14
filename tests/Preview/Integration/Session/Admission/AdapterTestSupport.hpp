/**
 * @file AdapterTestSupport.hpp
 * @brief AdapterTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Http1/Binding.hpp>
#include <Preview/Protocols/Trojan/Binding.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vless/Binding.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/Binding.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <stdexcept>
#include <utility>

namespace Preview::Testing
{
    /** @brief 为 Admission 用例构造完整 owning stream 输入。 */
    inline auto MakeAdapterAcceptInput(
        Preview::SharedTransmission Inbound,
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState = {})
        -> Preview::Contract::StreamAcceptInput
    {
        return Preview::Contract::StreamAcceptInput{
            std::move(Inbound), {},
            std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 8}),
            std::move(GenerationUseState)};
    }

    /** @brief 以正式账户 authority prepare HTTP binding，并设置 listener 测试认证策略。 */
    inline auto MakeAdapterHttpBinding(
        Preview::Testing::ProviderAccountInput Account,
        const bool RequireAuth,
        boost::asio::any_io_executor Executor)
        -> std::shared_ptr<Preview::Http11::Binding>
    {
        auto Accounts = Preview::Testing::ProviderAccount(std::move(Account));
        auto Prepared = Preview::Http11::PrepareProviderBinding(
            "adapter-http",
            Preview::Contract::AuthenticationServices{
                Accounts->Generation, Accounts->Credentials, Accounts->Authenticator},
            std::move(Executor));
        if (!Prepared)
        {
            throw std::logic_error("adapter HTTP binding preparation failed");
        }
        Prepared->RequireAuth = RequireAuth;
        return Preview::Http11::BindProvider(std::move(*Prepared));
    }

    /** @brief 以原账户目录和同一代次准备 VLESS TCP 接入 owner。 */
    inline auto MakeAdapterVlessIngress(
        Preview::Vless::ServerConfig Configuration,
        const std::shared_ptr<Preview::Testing::ProviderAccounts> &Accounts,
        boost::asio::any_io_executor Executor)
        -> std::shared_ptr<Preview::Vless::IngressFactory>
    {
        auto Authenticator = Configuration.AuthenticatorOwner
            ? Configuration.AuthenticatorOwner : Accounts->Authenticator;
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Prepared = Preview::Vless::PrepareProviderBinding(Preview::Vless::ProviderRequest{
            .Instance = "adapter-vless",
            .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = {}, .GenerationUseState = UseState, .Executor = std::move(Executor),
            .EnableUdp = Configuration.EnableUdp});
        if (!Prepared)
        {
            throw std::logic_error("adapter VLESS binding preparation failed");
        }
        auto Binding = Preview::Vless::BindProvider(std::move(*Prepared));
        auto Ingress = Binding->WithIngress({});
        if (!Ingress) throw std::logic_error("adapter VLESS ingress binding failed");
        return Ingress;
    }

    /** @brief 以原账户目录和同一代次准备 Trojan TCP 接入 owner。 */
    inline auto MakeAdapterTrojanIngress(
        Preview::Trojan::ServerConfig Configuration,
        const std::shared_ptr<Preview::Testing::ProviderAccounts> &Accounts,
        boost::asio::any_io_executor Executor)
        -> std::shared_ptr<Preview::Trojan::IngressFactory>
    {
        auto Authenticator = Configuration.AuthenticatorOwner
            ? Configuration.AuthenticatorOwner : Accounts->Authenticator;
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Prepared = Preview::Trojan::PrepareProviderBinding(Preview::Trojan::ProviderRequest{
            .Instance = "adapter-trojan",
            .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = {}, .GenerationUseState = UseState, .Executor = std::move(Executor),
            .EnableTcp = Configuration.EnableTcp, .EnableUdp = Configuration.EnableUdp,
            .EnableMux = Configuration.EnableMux});
        if (!Prepared)
        {
            throw std::logic_error("adapter Trojan binding preparation failed");
        }
        Prepared->Configuration.Password = std::move(Configuration.Password);
        auto Binding = Preview::Trojan::BindProvider(std::move(*Prepared));
        auto Ingress = Binding->WithIngress({});
        if (!Ingress) throw std::logic_error("adapter Trojan ingress binding failed");
        return Ingress;
    }

    /** @brief 以原账户目录和同一代次准备 VMess TCP 接入 owner。 */
    inline auto MakeAdapterVmessIngress(
        Preview::Vmess::ServerConfig Configuration,
        const std::shared_ptr<Preview::Testing::ProviderAccounts> &Accounts,
        boost::asio::any_io_executor Executor)
        -> std::shared_ptr<Preview::Vmess::IngressFactory>
    {
        auto Authenticator = Configuration.AuthenticatorOwner
            ? Configuration.AuthenticatorOwner : Accounts->Authenticator;
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Prepared = Preview::Vmess::PrepareProviderBinding(Preview::Vmess::ProviderRequest{
            .Instance = "adapter-vmess",
            .Authentication = {Accounts->Generation, Accounts->Credentials, Authenticator},
            .Datagrams = {}, .GenerationUseState = UseState, .Executor = std::move(Executor),
            .EnableUdp = Configuration.EnableUdp, .EnableMux = Configuration.EnableMux});
        if (!Prepared)
        {
            throw std::logic_error("adapter VMess binding preparation failed");
        }
        auto Binding = Preview::Vmess::BindProvider(std::move(*Prepared));
        auto Ingress = Binding->WithIngress({});
        if (!Ingress) throw std::logic_error("adapter VMess ingress binding failed");
        return Ingress;
    }
}
/**
 * @file AdapterTest.cpp
 * @brief adapter 接入缝专项测试（阶段 5 v2）
 * @details 覆盖：
 *          - MakeProtocolAccept 的 ctx 装配（Target/identity/IsDgram/PostDial/Inbound 替换）
 *          - 失败映射（bad_auth/not_supported/io_error/unexpected_eof/未知错误）
 *          - 全枚举黄金断言：Fault::ToCode 的 make_error_code.Protocol 分支映射稳定
 *          - 空传输兜底（无错误但无传输 → io_error）
 *          - Session 分支：IsDgram 但未注册 udp_service → not_supported
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Runtime = Preview::Runtime;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    /// 可识别首包（socks5 Greeting）
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto MakePairShared(Net::io_context &Ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [A, B] = MakeMemoryPair(Ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(A)),
                std::make_shared<MemoryStream>(std::move(B))};
    }

    /// 桩协议处理器：按预设结果返回
    class StubHandler final : public Preview::Contract::StreamFactory
    {
    public:
        explicit StubHandler(Preview::Contract::AcceptOutcome Result) : Result_(std::move(Result)) {}

        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome> override
        {
            (void)Input;
            co_return std::move(Result_);
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "stub"; }

    private:
        Preview::Contract::AcceptOutcome Result_;
    };

    auto MakeStubAccept(Preview::Contract::AcceptOutcome Result)
        -> std::shared_ptr<Preview::Contract::StreamFactory>
    {
        return std::make_shared<StubHandler>(std::move(Result));
    }

    /// 构造成功结果
    auto SuccessResult(std::shared_ptr<MemoryStream> Transmission) -> Preview::Contract::AcceptOutcome
    {
        Preview::Contract::ProtocolDataPlane r;
        r.Target.Host = *Preview::Network::ParseHost("example.com");
        r.Target.Port = 443;
        r.Identity = "alice";
        r.ProtocolAuthenticated = true;
        r.Root = Preview::Contract::DatagramDataPlane{std::move(Transmission), {}};
        return r;
    }













    /// 全枚举黄金断言：Fault::ToCode 的 make_error_code.Protocol 分支映射稳定
    /// （SPEC §3：桥接错误映射只允许一套口径，唯一表在 fault/handling.hpp，
    ///  adapter 层不再保留本地副本）



} // namespace




