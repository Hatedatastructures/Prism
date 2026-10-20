/** @file MuxSession.hpp @brief 唯一多路复用根的协议执行和最终关闭契约。 */
#pragma once
#include <boost/asio/awaitable.hpp>
#include <expected>
#include <Prism/Account/Lease.hpp>
#include <Prism/Contract/Ingress/RequestMetadata.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <memory>

namespace Prism::Contract
{
    /** @brief 正式 Run 接管根账户租约和同代状态；metadata 只观察，Request 不 Acquire。 */
    struct MuxRootRequest final
    {
        Prism::Account::AccountLease Lease;
        RequestMetadata Metadata;
        /// 本 Session 的管理查询 owner；只登记真实 live child，不拥有 stream 资源。
        std::shared_ptr<Ingress::StreamCatalog> StreamCatalogOwner;
        /// 所属不可变配置代次；须与冷 RootOptions 精确同指针，Run admission 才 Acquire。
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
    };
    /**
     * @brief 协议根拥有 frame、writer、child、DNS/relay 与终止任务，Runtime 只调用本契约。
     * @details Run 在根传输 executor 接管请求，并按值消费 AccountLease。成功表示协议任务及
     *          child/loop scope 均真实退栈且根租约已释放；失败保留首个领域码和可用 Native。
     *          Cancel/Close 可重复调用并停止本根活动；Cancel 保留显式取消结果，Close 表示正常停止。
     *          最终关闭始终归协议 owner。
     *          根无全局半关闭，可靠 child 按各 wire 实现 Shutdown，不影响兄弟。
     * @note Run 调用者拥有请求直到 await 完成；协议 owner 持有其执行器和异步状态直到 drain。
     */
    class MuxSession
    {
    public:
        virtual ~MuxSession() = default;
        /** @brief 提供根 frame/writer/child/FIN 真实退栈能力；根租约及最终关闭仍归本协议 owner。 */
        [[nodiscard]] virtual auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> = 0;
        /** @brief 一次消费根租约；只在真实关闭和所有 task drain 成功后返回成功。 */
        [[nodiscard]] virtual auto Run(MuxRootRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
        /** @brief 独立报告真实物理退休；历史 Run/Drain Failure 不推导资源仍活或已死。 */
        [[nodiscard]] virtual auto IsRetired() const noexcept -> bool = 0;
        /** @brief 显式取消根并发布取消结果，同时停止本根活动。 */
        virtual auto Cancel() noexcept -> void = 0;
        /** @brief 正常停止并排空本根，不把关闭本身记成显式取消。 */
        virtual auto Close() noexcept -> void = 0;
    };
}
