/** @file SessionRegistryStreamCatalog.hpp @brief 注册会话上的 stream catalog 查询和重置 owner。 */
#pragma once

#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Runtime/SessionRegistryStorage.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace Prism::Runtime::Detail
{
    /**
     * @brief 通过已注册 SessionControl 查询和重置单一 Mux stream。
     * @details 本 owner 固定注册表状态快照，校验 worker、generation、root task 后，
     *          把唯一 stream 的协议 reset 与真实 child retirement 交给该 SessionControl。
     */
    class SessionRegistryStreamCatalog final
    {
        using State = SessionRegistryState;
        using Storage = SessionRegistryStorage;

    public:
        explicit SessionRegistryStreamCatalog(std::shared_ptr<State> StateValue)
            : State_(std::move(StateValue))
        {
        }

        /** @brief 按完整父身份复制真实 protocol stream 描述；不查询 task 表冒充流状态。 */
        [[nodiscard]] auto Find(
            const Prism::Contract::Ingress::StreamIdentity &Identity) const noexcept
            -> Prism::Contract::Ingress::StreamCatalogLookup
        {
            using Lookup = Prism::Contract::Ingress::StreamCatalogLookup;
            using Status = Prism::Contract::Ingress::StreamCatalogStatus;
            const auto NotFound = Lookup{Status::NotFound, {}};
            if (!Identity.Session || !Identity.Id) return NotFound;
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Identity.Session.Value());
            if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
                return NotFound;
            const auto &RecordValue = It->second;
            if (RecordValue.Info.Worker != Identity.Worker ||
                RecordValue.Info.Generation != Identity.Generation) return NotFound;
            const auto Control = Storage::GetActiveControl(RecordValue.Entry);
            if (!Control)
            {
                auto Result = Status::CapabilityUnavailable;
                if (RecordValue.Entry->Removed.load(std::memory_order_seq_cst)) Result = Status::NotFound;
                return {Result, {}};
            }
            const auto Parent = Control->CurrentIdentity();
            if (Parent.SessionId != Identity.Session || Parent.WorkerId != Identity.Worker ||
                Parent.Generation != Identity.Generation) return NotFound;
            const auto Snapshot = Control->FindStream(Identity);
            if (RecordValue.Entry->Removed.load(std::memory_order_seq_cst)) return NotFound;
            return Snapshot;
        }

        /** @brief 按完整父身份枚举该会话的 live stream；缺少真实 catalog 返回 unavailable。 */
        [[nodiscard]] auto List(
            const Prism::Contract::Ingress::StreamListRequest &Request) const
            -> Prism::Contract::Ingress::StreamCatalogPage
        {
            using Status = Prism::Contract::Ingress::StreamCatalogStatus;
            if (!Request.Parent.Session || !Request.Parent.Worker || !Request.Parent.Generation)
            {
                return {Status::NotFound, {}, Request.Cursor, false};
            }
            const auto Current = State_->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Request.Parent.Session.Value());
            if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst) ||
                It->second.Info.Worker != Request.Parent.Worker ||
                It->second.Info.Generation != Request.Parent.Generation)
            {
                return {Status::NotFound, {}, Request.Cursor, false};
            }
            const auto Control = Storage::GetActiveControl(It->second.Entry);
            if (!Control)
            {
                return {Status::CapabilityUnavailable, {}, Request.Cursor, false};
            }
            auto Result = Control->ListStreams(Request);
            if (It->second.Entry->Removed.load(std::memory_order_seq_cst))
            {
                return {Status::NotFound, {}, Request.Cursor, false};
            }
            return Result;
        }

        /** @brief 校验完整 parent scope 后取消单一 stream 并等待真实 child retirement。 */
        [[nodiscard]] auto ResetAndDrain(
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return RunReset(State_, std::move(Request));
        }

    private:
        [[nodiscard]] static auto RunReset(
            std::shared_ptr<State> StateValue,
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            using Failure = Prism::Fault::Failure;
            if (!Request.Identity.Session || !Request.Identity.Worker ||
                !Request.Identity.Generation || !Request.Identity.Id ||
                !Request.Task || !Request.ParentTask)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            const auto Current = StateValue->Records.load(std::memory_order_acquire);
            const auto It = Current->find(Request.Identity.Session.Value());
            if (It == Current->end() || It->second.Entry->Removed.load(std::memory_order_seq_cst))
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            const auto &RecordValue = It->second;
            if (RecordValue.Info.Worker != Request.Identity.Worker ||
                RecordValue.Info.Generation != Request.Identity.Generation)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            const auto Control = Storage::GetActiveControl(RecordValue.Entry);
            if (!Control)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
            const auto Parent = Control->CurrentIdentity();
            if (Parent.SessionId != Request.Identity.Session ||
                Parent.WorkerId != Request.Identity.Worker ||
                Parent.Generation != Request.Identity.Generation ||
                Parent.TaskId != Request.ParentTask)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            co_return co_await Control->ResetStreamAndDrain(std::move(Request));
        }

        std::shared_ptr<State> State_;
    };
}
