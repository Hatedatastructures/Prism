/** @file Binding.hpp @brief SS2022 prepared 凭据集合的真实 TCP/raw UDP 工厂及最终关闭 owner。 */
#pragma once
#include <Prism/Account/Credential.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Ingress/RawDatagramIngress.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/BindingLifetime.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Prepared.hpp>
#include <Prism/Protocols/Shadowsocks2022/Ss2022Gateway.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <stop_token>
#include <string_view>
#include <vector>

namespace Prism::Shadowsocks2022
{
    /** @brief 将 SS2022 PSK 文本校验并封装为账户凭据。 */
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>;

    /**
     * @brief SS2022 唯一 prepared、raw gateway 与 activity 材料 owner。
     * @details 构造按值接管 Prepared；Material、Gateway 和派生 cold factory 由同一
     *          state 共享，不复制 PSK、认证材料或 account lease。关闭请求沿服务
     *          executor 投递，Drain 才等待真实 TCP/raw UDP/root owner 退栈。
     * @note Add 只属于监听前控制线程；MuxFactories 是普通 vector，不承诺与 Add 或 Close
     *       的任意并发顺序。每次 Drain waiter 保存自己的 shared factory snapshot，因此
     *       清空原 vector 不会使该 waiter 的跨 await 遍历失效。
     */
    struct BindingState final
    {
        /**
         * @brief 消耗 Prepared，并按其 service executor/generation 建立唯一生命周期。
         * @param Value 按值移动，state 接管该 Prepared 值且不复制其中材料；其他独立 shared
         *        service handle 的外部 ownership 仍遵循原 shared_ptr 契约。
         * @note RawUdp 为真时同时建立共享 gateway；分配或构造异常直接传播，构造没有
         *       异步取消点和 stream 半关闭。
         */
        explicit BindingState(Prepared Value);
        /** @brief 只提交关闭请求；不等待 activity、gateway 或 mux root。 */
        ~BindingState();
        /**
         * @brief 封止新 activity，并请求 gateway 与所有已登记 mux root 取消。
         * @return 无返回值；真实载体仍在各自 executor 关闭，datagram 没有 stream half-close。
         * @note noexcept 只涵盖本层请求；关闭失败由 Drain 的类型化结果报告。Drain
         *       会使用本次调用的 shared factory snapshot，避免另一 waiter 清空原 vector
         *       影响跨 await 遍历；Add/Close/Drain 的一般并发顺序仍未承诺。
         */
        auto Close() noexcept -> void;
        /** @brief 真实 retirement 需 TCP lifetime、raw gateway、每个 mux root 都物理退栈。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;
        /**
         * @brief 等待 mux root、raw gateway、activity 全部退栈后清除唯一 material。
         * @return expected<void, Fault::Failure>；当前按顺序等待并原样返回首个错误。只有
         *        IsRetired 确认 TCP/root/raw owner 全部退栈时才清理 material。
         * @note 调用者必须驱动 binding executor；没有 stop_token，也不承诺 Add/Close 与
         *       Drain 的任意并发顺序。每个 Drain waiter 独立保存本次 factory snapshot，
         *       原 vector 只在所有 owner 等待后清空。
         */
        auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /**
         * @brief 只由监听前控制线程注册 cold wire factory，热 Accept 不写集合。
         * @param Factory 按值接收 RootBinding 共享句柄；state 登记共享关闭责任，Mux view
         *        与 caller 仍可保有同一 shared handle。
         * @return Factory 非空且 state 未关闭时返回 true，否则返回 false。
         * @note vector 分配异常直接传播；没有冷取消、stream half-close 或并发访问保证。
         */
        auto Add(std::shared_ptr<Prism::Mux::RootBinding> Factory) -> bool;
        std::atomic<std::shared_ptr<const Prepared>> Material;
        std::shared_ptr<Prism::Protocols::BindingLifetime> Lifetime;
        std::shared_ptr<Ss2022Gateway> Gateway;
        std::vector<std::shared_ptr<Prism::Mux::RootBinding>> MuxFactories;
    };
    /**
     * @brief SS2022 StreamFactory；共享 prepared 认证、TCP admission 和 raw UDP gateway。
     * @details Accept 按入站 executor 契约运行；plain stream 的最终关闭交给发布的
     *          stream owner，mux root 或 raw gateway 各自收口。Close 仅请求取消，Drain
     *          才等待实际 owner；本对象不提供多个调用者并发协调。
     */
    class Binding final : public Prism::Contract::StreamFactory
    {
    private:
        friend auto Bind(Prepared, std::stop_token)
            -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>;
        explicit Binding(Prepared Value);
        Binding(std::shared_ptr<BindingState> State, std::shared_ptr<Prism::Mux::RootBinding> Mux);
    public:
        ~Binding() override =default;
        /**
         * @brief 从同一 prepared producer 派生 cold wire view，不复制 credential trial 或 lease。
         * @param Mux 按值传入的 RootBinding；注册后由共享 state 负责关闭。
         * @return state 已关闭或 Mux 为空时返回空指针，否则返回共享材料的 owning view。
         * @note 只在监听前控制线程调用；无异步取消或半关闭，分配异常直接传播。
         */
        [[nodiscard]] auto WithMux(std::shared_ptr<Prism::Mux::RootBinding> Mux) -> std::shared_ptr<Binding>;
        /**
         * @brief 同步借用 wire 字节进行候选检查，不取 account quota/rate lease。
         * @param Bytes 只借用到同步返回；调用者必须在调用期间保持 span 指向的存储有效。
         * @return NotOpen 表示 state/material 不可用，否则返回 InspectTcp 的 typed wire 结果。
         * @note 纯 cold CPU 检查，不进入 packet/frame 热路径、认证器或 stream half-close；
         *       异常边界不在此处转换。
         */
        [[nodiscard]] auto Inspect(std::span<const std::byte> Bytes) const -> Prism::Error;
        /**
         * @brief 按值接管 TCP 入站载体，执行一次候选 trial 并发布唯一 data plane。
         * @param Inbound admission 守卫取得的共享载体；拒绝或异常时关闭，成功后由
         *        stream 或 mux root 成为最终 owner。
         * @param Metadata 按值接收但当前不保存；SS2022 TCP 的身份来自 wire/auth 结果。
         * @return typed AcceptOutcome；认证失败、无 egress 或关闭条件原样返回，失败不发布
         *         lease。认证成功时只移动 winner 的 account lease，不进行二次认证。
         * @details 在入站 executor 上运行；plain stream 支持半关闭，mux 子流由 root engine
         *          管理。取消依赖 Binding::Close/Asio cancellation，没有每种错误独立 token。
         */
        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override;
        /** @brief 返回稳定协议名；不借用或转移认证材料。 */
        [[nodiscard]] auto Name() const -> std::string_view override { return "ss2022"; }
        /**
         * @brief 返回 raw UDP ingress 的共享 handle，不转移入口 socket 的关闭权。
         * @return RawUdp 未启用时为空；否则返回由 BindingState/Gateway 共同保活的 handle。
         * @note raw datagram 没有 stream half-close；实际 gateway/binding owner 负责取消和
         *       最终关闭，调用者不能把返回值当作独立关闭 owner。
         */
        [[nodiscard]] auto RawIngress() const -> std::shared_ptr<Prism::Contract::RawDatagramIngress>
        { return State_->Gateway; }
        /** @brief 发出 TCP activity、mux root 与 raw gateway 的关闭请求，不等待 executor。 */
        auto Close() noexcept -> void;
        /** @brief 读共享 state 对 TCP、raw UDP 与 mux 的真实退休快照。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return State_->IsRetired(); }
        /**
         * @brief 等待 root、raw peer 与 activity 退栈后清空唯一 material。
         * @return expected<void, Fault::Failure>；调用者驱动 binding executor，失败来自 State::Drain。
         * @note 仍存活的 cold view 共享空状态，不保留 secret 副本；State::Drain 已隔离
         *       多个 waiter 的 vector 遍历，但不扩展为 Add/Close 与 Drain 的一般并发协调协议。
         */
        auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    private:
        std::shared_ptr<BindingState> State_;
        std::shared_ptr<Prism::Mux::RootBinding> Mux_;
    };
    /**
     * @brief 单次接管 Prepared，在取消时拒绝发布唯一 Binding。
     * @param Value 按值移动进入 Prepare；成功后密钥、gateway 与 activity 由 BindingState 持有。
     * @param Stop 按值读取的冷构造取消请求；只在 Prepare 前后检查，不取消网络循环。
     * @return ProviderFailure::Cancelled 表示 stop，Prepare 错误原样返回；后置 stop 会
     *         先 Close 已创建对象再返回失败，分配/构造异常不在此处吞掉。
     * @note 无 stream half-close；运行期最终关闭由 Binding::Close/Drain 和真实 protocol owner 完成。
     */
    [[nodiscard]] auto Bind(Prepared Value, std::stop_token Stop)
        -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>;
}
