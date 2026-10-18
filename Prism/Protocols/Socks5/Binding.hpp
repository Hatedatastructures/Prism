/** @file Binding.hpp @brief SOCKS5 唯一工厂与活动 association owner。 */
#pragma once
#include <Prism/Protocols/Socks5/Detail/Target.hpp>
#include <Prism/Protocols/Socks5/Prepared.hpp>
#include <Prism/Protocols/Socks5/AssociationFactory.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Common/BindingLifetime.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <exception>
#include <optional>
#include <stop_token>
#include <Prism/Protocols/Mux/RootBinding.hpp>
namespace Prism::Socks5
{
    [[nodiscard]] inline auto PrepareAccountCredential(std::string_view Value)
        ->Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    /**
     * @brief 原 prepared 材料、活动资源与冷 mux factory 的唯一共享关闭 owner。
     * @details 构造时按值接管 Prepared；Material 只保存一份不可变值，派生 view
     *          共享 Lifetime，不复制 secret、AccountLease 或入站载体。关闭请求由
     *          BindingLifetime 投递到记录的服务 executor，Drain 才等待实际 owner 退栈。
     * @note Add 只允许监听前控制线程调用；MuxFactories 是普通 vector，不承诺与 Add
     *       或 Close 的任意并发顺序。每次 Drain waiter 保存自己的 shared factory snapshot，
     *       因此清空原 vector 不会使该 waiter 的跨 await 遍历失效。
     */
    struct BindingState final
    {
        /**
         * @brief 消耗 Prepared，并以其服务 executor 和 generation 建立共享生命周期。
         * @param Value 按值传入并移动，state 接管该 Prepared 值且不复制其中材料；其他独立
         *        shared service handle 的外部 ownership 仍遵循原 shared_ptr 契约。
         * @note 分配或服务 owner 构造异常直接传播；构造阶段没有异步取消点或半关闭。
         */
        explicit BindingState(Prepared Value):Material(std::make_shared<const Prepared>(std::move(Value))),
            Lifetime(std::make_shared<Prism::Protocols::BindingLifetime>(Material.load()->Services.Executor,Material.load()->Input.Generation)){}
        /** @brief 只提交关闭请求；不等待活动 I/O，实际载体仍由各自 executor 关闭。 */
        ~BindingState(){Close();}
        /**
         * @brief 封止新的 activity，并请求已登记 mux root 与原 binding activity 取消。
         * @return 无返回值；调用不会等待，也不执行 stream 半关闭，最终关闭由 Drain
         *        及各 root/association owner 完成。
         * @note noexcept 只覆盖本层请求；关闭失败由 BindingLifetime::Drain 报告。Drain
         *       会使用本次调用的 shared factory snapshot，避免另一 waiter 清空原 vector
         *       影响跨 await 遍历；Add/Close/Drain 的一般并发顺序仍未承诺。
         */
        auto Close() noexcept->void
        {Lifetime->Close();for(const auto& Factory:MuxFactories)Factory->Close();}
        /** @brief 真实 retirement 需 BindingLifetime、每个 mux root 均报告物理退栈。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            if (!Lifetime->IsRetired())
            {
                return false;
            }
            for (const auto& Factory : MuxFactories)
            {
                if (!Factory->IsRetired())
                {
                    return false;
                }
            }
            return true;
        }
        /**
         * @brief 等待所有登记 root、activity 和服务资源实际退栈后释放唯一 material。
         * @return expected<void, Fault::Failure>；保留首个原始类型化原因。错误返回后只有
         *        IsRetired 确认所有 root/activity 退栈时才清理 material。
         * @note 调用者必须驱动相关 Asio executor；本方法没有 stop_token，也不承诺
         *       Add/Close 与 Drain 的任意并发顺序。每个 Drain waiter 独立保存本次
         *       factory snapshot，原 vector 只在所有 owner 等待后清空。
         */
        auto Drain()
            ->Net::awaitable<std::expected<void,Prism::Fault::Failure>>
        {
            auto Factories=MuxFactories;
            Close();
            auto FirstFailure=std::expected<void,Prism::Fault::Failure>{};
            for(const auto& Factory:Factories)
            {
                const auto Result=co_await Factory->Drain();
                if(!Result && FirstFailure)FirstFailure=std::unexpected(Result.error());
            }
            const auto ActivityDrain=co_await Lifetime->Drain();
            if(!ActivityDrain && FirstFailure)FirstFailure=std::unexpected(ActivityDrain.error());
            if(!FirstFailure)
            {
                if (IsRetired())
                {
                    Material.store({});
                    MuxFactories.clear();
                }
                co_return std::unexpected(FirstFailure.error());
            }
            Material.store({});
            MuxFactories.clear();
            co_return std::expected<void,Prism::Fault::Failure>{};
        }
        /**
         * @brief 在监听前控制线程注册不可变 wire 选择；热 Accept 从不修改目录。
         * @param Factory 按值接收 RootBinding 共享句柄；成功后 state 登记共享关闭责任，
         *        Mux view 与 caller 仍可保有同一 shared handle。
         * @return 非空且 state 未关闭时返回 true；空句柄或已关闭返回 false。
         * @note vector 扩容异常不在此处转成 typed failure；没有冷取消点、stream 半关闭
         *       或跨线程同步保证。
         */
        auto Add(std::shared_ptr<Prism::Mux::RootBinding> Factory)->bool
        {if(!Factory||Lifetime->Closed())return false;MuxFactories.push_back(std::move(Factory));return true;}
        std::atomic<std::shared_ptr<const Prepared>> Material;
        std::shared_ptr<Prism::Protocols::BindingLifetime> Lifetime;
        std::vector<std::shared_ptr<Prism::Mux::RootBinding>> MuxFactories;
    };
    /**
     * @brief 接管 Prepared 的 SOCKS5 StreamFactory，并提供冷 admission 派生 view。
     * @details Accept 按 StreamFactory 契约在入站 executor 中运行；Close 只发出取消
     *          请求，Drain 才等待真实 root、association 和 activity 完成。plain stream
     *          的最终关闭交给发布后的数据面 owner，UDP association 或 mux root 各自
     *          关闭其数据面；本对象不是多个调用者并发安全的协调器。
     */
    class Binding final : public Prism::Contract::StreamFactory
    {
    public:
        /** @brief 监听前派生的 command policy；Mux 与 UDP 能力共享同一 material owner。 */
        struct AdmissionPolicy final
        {
            std::shared_ptr<Prism::Mux::RootBinding> Mux;
            std::optional<bool> UdpEnabled;
        };


        friend auto Bind(Prepared, std::stop_token)
            -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>;
        explicit Binding(Prepared Value)
            :UdpEnabled_(Value.Input.Config.EnableUdp),State_(std::make_shared<BindingState>(std::move(Value))){}
        Binding(std::shared_ptr<BindingState> State, AdmissionPolicy Policy)
            :UdpEnabled_(Policy.UdpEnabled.value_or(false)),State_(std::move(State)),Mux_(std::move(Policy.Mux)){}
    public:
        ~Binding() override =default;
        /**
         * @brief 从同一正式 producer 派生冷 admission view，共享 material 和 activity owner。
         * @param Policy 按值传入的 mux/command policy；可选 UDP 覆盖只改变该 view。
         * @return 成功返回新 view；state 已关闭或 mux 登记失败时返回空指针。
         * @note 只能在监听前控制线程调用；没有异步取消、executor 或 stream half-close；
         *       State/Binding owner 负责后续 Close/Drain，分配异常直接传播。
         */
        [[nodiscard]] auto WithAdmission(AdmissionPolicy Policy)->std::shared_ptr<Binding>
        {
            if (!Policy.UdpEnabled)
            {
                Policy.UdpEnabled=UdpEnabled_;
            }
            if(State_->Lifetime->Closed() || (Policy.Mux && !State_->Add(Policy.Mux)))return {};
            return std::shared_ptr<Binding>(new Binding(State_,std::move(Policy)));
        }
        /**
         * @brief 按值接管入站载体，完成认证后只发布一个数据面 owner。
         * @param Inbound 由 admission 守卫接管的共享载体；拒绝、异常或未发布结果时关闭，
         *        成功后由 stream、UDP association 或 mux root 取得最终关闭责任。
         * @param Metadata 按值传入；仅 UDP associate 移入 DatagramObservation，TCP/mux
         *        分支当前不保存该元数据。
         * @return typed AcceptOutcome；Canceled 表示载体、material 或 state 已关闭，协议
         *         错误原样返回，未分类的无错误断开映射为 IoError；异常不在此处伪造成功。
         * @details 在入站 executor 上运行。成功的 plain stream 支持传输层半关闭；UDP
         *          是 datagram，不提供 stream half-close；mux 的半关闭由其子流 engine
         *          处理。Close/Asio cancellation 是取消来源，本接口没有每种错误独立 token。
         */
        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override
        {
            auto PreparedAdmission =
                co_await Prism::Contract::InboundAdmission::Prepare(Input.Inbound);
            if (!PreparedAdmission)
            {
                co_return std::unexpected(PreparedAdmission.error());
            }
            co_return co_await AcceptPrepared(
                std::move(Input), std::move(*PreparedAdmission));
        }



        auto AcceptPrepared(
            Prism::Contract::StreamAcceptInput Input,
            Prism::Contract::InboundAdmission Admission)
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            if (!Input.Inbound || !Input.Bytes)
            {
                co_return co_await Admission.Reject(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            const auto Value=State_->Material.load();
            if (!Input.Inbound || !Value || State_->Lifetime->Closed())
            {
                co_return co_await Admission.Reject(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            auto Activity = State_->Lifetime->Enter(Input.Inbound);
            if (!Activity || State_->Lifetime->Closed())
            {
                co_return co_await Admission.Reject(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            auto Carrier = std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
            if (const auto Tracked = Admission.Track(Carrier); !Tracked)
            {
                co_return co_await Admission.Reject(Tracked.error());
            }
            auto Config=Value->Input.Config;
            Config.EnableUdp=UdpEnabled_;
            auto Accepted = co_await Prism::Socks5::Accept(Carrier, Config);
            if (!Accepted)
            {
                co_return co_await Admission.Reject(Accepted.error());
            }
            auto Request = std::move(Accepted->RequestValue);
            auto Connection = std::move(Accepted->Connection);
            if (const auto Tracked = Admission.Track(Connection); !Tracked)
            {
                co_return co_await Admission.Reject(Tracked.error());
            }
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Prism::Contract::ProtocolType::Socks5;
            auto Target = Prism::Socks5::Detail::ToNetworkTarget(Request.Target);
            if (!Target)
            {
                co_return co_await Admission.Reject(
                    Prism::Contract::FailureFromProtocolError(Prism::Error::BadAddress));
            }
            Plane.Target = std::move(*Target);
            Plane.AccountId = Connection->AccountId();
            Plane.Identity = std::string(Connection->Identity());
            Plane.AccountLease = Connection->TakeAuthLease();
            Plane.DisplayIdentity = std::string(Connection->DisplayIdentity());
            Plane.ProtocolAuthenticated = Config.EnableAuth;
            co_return co_await CompleteAccepted(AcceptedCommand{
                std::move(Value), std::move(Admission), std::move(Request),
                std::move(Connection), std::move(Plane), std::move(Input.Metadata)});
        }
        /** @brief 返回冷候选使用的稳定协议名；不借用或转移任何资源。 */
        [[nodiscard]] auto Name() const -> std::string_view override { return "socks5"; }
        /**
         * @brief 发出 binding、mux root 和 activity 的关闭请求。
         * @note 不等待 executor，也不主动完成 stream half-close；最终关闭者仍是已发布
         *       的 stream/association/root owner，失败由 Drain 的类型化结果报告。
         */
        auto Close() noexcept -> void {State_->Close();}
        /**
         * @brief 等待全部 root、association、activity 退栈后清除唯一 material。
         * @return expected<void, Fault::Failure>；失败来自 State::Drain。
         */
        auto Drain()->Net::awaitable<std::expected<void,Prism::Fault::Failure>>
        {co_return co_await State_->Drain();}
    private:
        struct AcceptedCommand final
        {
            std::shared_ptr<const Prepared> Material;
            Prism::Contract::InboundAdmission Admission;
            Prism::Socks5::Request Request;
            Prism::Socks5::SharedConn Connection;
            Prism::Contract::ProtocolDataPlane Plane;
            Prism::Contract::RequestMetadata Metadata;
        };

        /** @brief 完成已认证请求的 UDP、mux 或 stream 发布并移交 admission owner。 */
        auto CompleteAccepted(AcceptedCommand Accepted)
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            auto &Plane = Accepted.Plane;
            auto &Admission = Accepted.Admission;
            const auto &Connection = Accepted.Connection;
            if (Accepted.Request.Cmd == Command::UdpAssociate)
            {
                Prism::Protocols::DatagramBinding Services{Accepted.Material->Services.Datagrams,
                    Prism::Protocols::DatagramObservation{.Request = std::move(Accepted.Metadata),
                        .Identity = Plane.Identity, .DisplayIdentity = Plane.DisplayIdentity,
                        .Protocol = Plane.Protocol, .AccountId = Plane.AccountId}};
                std::shared_ptr<UdpAssoc> Association;
                Prism::Fault::Failure BindFailure;
                std::exception_ptr BindException;
                try
                {
                    Association = MakeDatagramSession(Connection, std::move(Services));
                    const auto Status = co_await Association->BindAndReply();
                    if (!Status)
                    {
                        BindFailure = Status.error().Transport;
                        if (!BindFailure.Failed())
                        {
                            BindFailure = Prism::Contract::FailureFromProtocolError(
                                Status.error().Protocol);
                        }
                    }
                }
                catch (...)
                {
                    BindException = std::current_exception();
                }
                if (BindFailure.Failed() || BindException)
                {
                    if (Association)
                    {
                        Plane.Root = Prism::Contract::DatagramDataPlane{
                            Connection, std::move(Association)};
                    }
                    auto Failure = BindFailure;
                    if (BindException)
                    {
                        Failure = Prism::Contract::InboundAdmission::ExceptionFailure(BindException);
                    }
                    co_return co_await Admission.Reject(
                        std::move(Plane), Failure);
                }
                Plane.Root = Prism::Contract::DatagramDataPlane{
                    Connection, std::move(Association)};
            }
            else if(Mux_)
            {
                Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
                const auto UseState = Mux_->GenerationUseState();
                if (!UseState)
                {
                    co_return co_await Admission.Reject(
                        std::move(Plane),
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                }
                auto Request = Prism::Contract::MuxRootCreateRequest::Prepare(
                    Admission.RootCreateOwner(), UseState, std::move(Plane));
                if (!Request)
                {
                    if (Plane.HasTransport())
                        co_return co_await Admission.Reject(std::move(Plane), Request.error());
                    co_return std::unexpected(Request.error());
                }
                auto Created = Mux_->Create(std::move(*Request));
                if (!Created) co_return std::unexpected(Created.error());
                Plane = std::move(Created->Plane);
                const auto Reply = co_await SendConnectDeferredReply(
                    Connection, Accepted.Metadata.Trace, Prism::Fault::Failure{});
                if (Reply.Failed())
                {
                    co_return co_await Admission.Reject(
                        std::move(Plane), Reply);
                }
            }
            else
            {
                Plane.Root = Prism::Contract::StreamDataPlane{Connection};
                Plane.PostDial = [Connection, Trace = Accepted.Metadata.Trace](
                    Prism::Fault::Failure Status)
                    -> Net::awaitable<Prism::Fault::Failure>
                {
                    co_return co_await SendConnectDeferredReply(Connection, Trace, Status);
                };
            }
            co_return co_await Admission.Admit(std::move(Plane));
        }

    public:
        /** @brief 读共享 state 的实际活动/root 退栈回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return State_->IsRetired(); }

    private:
        bool UdpEnabled_{false};
        std::shared_ptr<BindingState> State_;
        std::shared_ptr<Prism::Mux::RootBinding> Mux_;
    };
    /**
     * @brief 消耗单次 Prepared，复核 stop 后发布唯一 Binding。
     * @param Value 按值移动进入 Prepare；成功后认证材料由 BindingState 持有。
     * @param Stop 按值读取的冷构造取消请求；在 Prepare 前后各检查一次，不取消网络 I/O。
     * @return 成功返回 owning Binding；stop 返回 typed ProviderError::Cancelled，Prepare
     *         的失败原样传播，后置取消会先关闭已创建 binding；异常不转为成功值。
     * @note 这是同步冷路径，没有 stream 半关闭；运行期关闭由 Binding::Close/Drain 和
     *       实际 protocol owner 完成，调用线程负责相关控制 executor。
     */
    [[nodiscard]] inline auto Bind(Prepared Value, std::stop_token Stop)
        -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>
    {
        if (Stop.stop_requested()) return std::unexpected(Prism::Contract::ProviderFailure{
            Prism::Contract::ProviderError::Cancelled, Value.Input.Instance, "Bind"});
        auto Verified=Prepare(std::move(Value.Input),std::move(Value.Services));
        if(!Verified)return std::unexpected(Verified.error());
        auto Result=std::shared_ptr<Binding>(new Binding(std::move(*Verified)));
        if(Stop.stop_requested())
        {
            Result->Close();
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled,{},"Bind"});
        }
        return Result;
    }
}
