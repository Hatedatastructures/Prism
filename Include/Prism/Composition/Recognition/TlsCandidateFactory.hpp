/**
 * @file TlsCandidateFactory.hpp
 * @brief TLS carrier Runtime 候选工厂。
 * @details TLS recognition 与 commit 实现由 Composition 内部拥有；本头公开装配候选所需的
 *          typed carrier callback 和候选数据模型。
 */

#pragma once

#include <utility>

#include <Prism/Composition/Recognition/TlsCandidateModel.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    /**
     * @class TlsCandidateFactory
     * @brief 构造 TLS carrier Runtime 候选。
     */
    class TlsCandidateFactory
    {
    public:
        /**
         * @brief 构造使用普通 carrier 接入回调的 TLS 候选。
         * @param Options TLS 识别规则；候选按值拥有其中的字符串。
         * @param Accept winner 提交后执行的 carrier 接入回调；回调状态由 binding 拥有。
         * @return 可提交到 Profile 的 TLS carrier binding。
         * @details commit 没有取消点或半关闭动作；运行期取消、transport 关闭和
         *          executor 由传入的 typed callback 及其协议 owner 负责。
         */
        [[nodiscard]] static auto Make(TlsCandidateOptions Options,
                                       CarrierAcceptFn Accept)
            -> TlsCandidateBinding;

        /**
         * @brief 构造需要 prepared ClientHello 的 TLS 候选。
         * @param Options TLS 识别规则；候选按值拥有其中的字符串。
         * @param Accept prepared state 接入回调；回调状态由 binding 拥有。
         * @return 可提交到 Profile 的 TLS carrier binding。
         * @details prepared state 与 Inbound 在 commit frame 中按值传递；失败时保留
         *          原始 Inbound，最终关闭仍由 carrier/protocol owner 执行。
         */
        [[nodiscard]] static auto MakePrepared(
            TlsCandidateOptions Options,
            CarrierAcceptPreparedFn Accept) -> TlsCandidateBinding;

    private:
        [[nodiscard]] static auto MakeBinding(
            TlsCandidateOptions Options,
            CarrierAcceptFn Accept,
            CarrierAcceptPreparedFn AcceptPrepared) -> TlsCandidateBinding;
    };

} // namespace Prism::Composition::Recognition
