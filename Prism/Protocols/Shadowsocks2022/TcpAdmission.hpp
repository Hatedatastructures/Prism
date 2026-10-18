/** @file TcpAdmission.hpp @brief SS2022 多账户 wire 认证；候选检查不取得 quota/rate lease。 */
#pragma once
#include <Prism/Protocols/Shadowsocks2022/Detail/Target.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Prepared.hpp>
#include <Prism/Transport/Replay.hpp>
#include <system_error>
namespace Prism::Shadowsocks2022
{
    namespace Detail
    {
        /** @brief SS2022 私有 wire 错误在 admission 边界转成 code-only 失败。 */
        [[nodiscard]] inline auto FailureForWireError(const Prism::Error Value)
            -> Prism::Fault::Failure
        {
            return {Prism::Fault::Detail::MapProtocolCategoryValue(static_cast<int>(Value)), {}};
        }

        /** @brief 只重试无Native或本协议 BadAuth，真实传输Native失败不尝试第二凭据。 */
        [[nodiscard]] inline auto IsRetryableAuthenticationFailure(
            const Prism::Fault::Failure &Failure) noexcept -> bool
        {
            if (Failure.Code != Prism::Fault::Code::AuthFailed) return false;
            if (!Failure.Native) return true;
            static const auto &ProtocolCategory =
                static_cast<const std::error_category &>(Prism::ErrorCategory());
            return &Failure.Native.category() == &ProtocolCategory &&
                Failure.Native.value() == static_cast<int>(Prism::Error::BadAuth);
        }
    }
    /**
     * @brief 同步借用 Prepared 与 wire 字节做候选检查，不取 quota/rate lease。
     * @param Value 只借用到同步返回；不得在调用完成前销毁或修改 prepared credential。
     * @param Bytes 只借用到同步返回；span 的底层存储由调用者保持有效。
     * @return None 表示某个 key 完整且时间窗有效，NeedMore 表示仍需更多字节，BadAuth
     *         表示候选均失败；没有认证器、网络 executor、取消点或 stream half-close。
     */
    [[nodiscard]] inline auto InspectTcp(const Prepared& Value, std::span<const std::byte> Bytes)
        -> Prism::Error
    {
        bool More = false;
        for (const auto& Credential : Value.Credentials)
        {
            Parser Candidate(WireKey(Credential));
            std::error_code ErrorValue;
            Candidate.Put(Net::const_buffer(Bytes.data(), Bytes.size()), ErrorValue);
            More |= ErrorValue == Prism::make_error_code(Prism::Error::NeedMore);
            if (!ErrorValue && Candidate.IsDone() &&
                Candidate.IsTimestampFresh(Value.Input.Config.TimeWindow))
                return Prism::Error::None;
        }
        return More ? Prism::Error::NeedMore : Prism::Error::BadAuth;
    }
    /**
     * @brief TCP admission 的输入 owner：Inbound 由本值对象接管，Mux 只是共享 cold view。
     * @details AcceptTcp 会移动 Inbound 到 ReplayTransmission；Mux 不复制 prepared 或 lease，
     *          由 root factory 在 winner 成功后创建正式 mux root。
     */
    struct TcpIngress final
    {
        Prism::SharedTransmission Inbound;
        std::shared_ptr<Prism::Mux::RootBinding> Mux;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        Prism::Contract::InboundAdmission Admission;
    };
    /**
     * @brief 在入站 executor 上依次试验 prepared 凭据并发布唯一结果。
     * @param Input 按值接管 Inbound/Mux；调用方在协程返回前保持其 admission 及底层 executor 有效。
     * @param Value 借用整个 co_await 期间；调用者必须保持 Prepared 的 pin/material 有效。
      * @return winner 成功时只移动一次 account lease 并返回 stream/mux plane；仅 BadAuth 会回退
     *         试下个 PSK，全部失败返回 AuthFailed。I/O/wire 终止错误原样保留 Native。
     * @details 每个失败候选 Rewind 保留回放窗口，winner Commit 后才把写侧和真实
     *          connection 交给 stream 或 mux root。plain stream 支持半关闭，mux root 由 engine
     *          管理子流；取消依赖载体关闭与 Asio，不宣称每个错误有专用 cancel token。
     *          调用者 executor 负责驱动 I/O，异常不在此处转换为成功结果。
     */
    [[nodiscard]] inline auto AcceptTcp(TcpIngress Input, const Prepared& Value)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        if (!Input.Bytes)
            co_return co_await Input.Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        auto Created = Prism::Transport::ReplayTransmission::Create(
            Input.Inbound,
            Prism::Transport::ReplayOptions{64U * 1024U,
                Prism::Transport::ReplayMode::Candidate, std::move(Input.Bytes)});
        if (!Created)
        {
            co_return co_await Input.Admission.Reject(Created.error());
        }
        auto Replay = std::move(*Created);
        if (const auto Tracked = Input.Admission.Track(Replay); !Tracked)
        {
            co_return co_await Input.Admission.Reject(Tracked.error());
        }
        Replay->EnableWrites();
        for (const auto& Credential : Value.Credentials)
        {
            ServerConfig Config;
            Config.Psk = WireKey(Credential);
            Config.TimeWindow = Value.Input.Config.TimeWindow;
            Config.Authenticator = Value.Services.Authentication.Authenticator;
            auto Accepted = co_await Prism::Shadowsocks2022::Accept(Replay, Config);
            if (!Accepted)
            {
                const auto Failure = Accepted.error();
                if (Detail::IsRetryableAuthenticationFailure(Failure))
                {
                    const auto Rewound = Replay->Rewind();
                    if (Rewound)
                        continue;
                    co_return co_await Input.Admission.Reject(
                        Rewound.error());
                }
                co_return co_await Input.Admission.Reject(Failure);
            }
            auto Request = std::move(Accepted->Request);
            auto Connection = std::move(Accepted->Connection);
            if (!Connection)
            {
                co_return co_await Input.Admission.Reject(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (const auto Tracked = Input.Admission.Track(Connection); !Tracked)
            {
                co_return co_await Input.Admission.Reject(Tracked.error());
            }
            Replay->Commit();
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Prism::Contract::ProtocolType::Shadowsocks;
            auto Target = Prism::Shadowsocks2022::Detail::ToNetworkTarget(Request.dst);
            if (!Target)
            {
                co_return co_await Input.Admission.Reject(
                    std::move(Plane), Target.error());
            }
            Plane.Target = std::move(*Target);
            Plane.ProtocolAuthenticated = true;
            Plane.AccountId = Connection->AccountId();
            Plane.Identity = std::string(Connection->Identity());
            Plane.AccountLease = Connection->TakeAuthLease();
            if (Input.Mux)
            {
                Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
                const auto UseState = Input.Mux->GenerationUseState();
                if (!UseState)
                {
                    co_return co_await Input.Admission.Reject(
                        std::move(Plane),
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                }
                auto CreateRequest = Prism::Contract::MuxRootCreateRequest::Prepare(
                    Input.Admission.RootCreateOwner(), UseState, std::move(Plane));
                if (!CreateRequest)
                {
                    if (Plane.HasTransport())
                        co_return co_await Input.Admission.Reject(
                            std::move(Plane), CreateRequest.error());
                    co_return std::unexpected(CreateRequest.error());
                }
                auto Created = Input.Mux->Create(std::move(*CreateRequest));
                if (!Created) co_return std::unexpected(Created.error());
                Plane = std::move(Created->Plane);
            }
            else
                Plane.Root = Prism::Contract::StreamDataPlane{std::move(Connection)};
            co_return co_await Input.Admission.Admit(std::move(Plane));
        }
        co_return co_await Input.Admission.Reject(
            Detail::FailureForWireError(Prism::Error::BadAuth));
    }
} // namespace Prism::Shadowsocks2022
