/** @file StreamCatalog.hpp @brief 跨 executor 查询的真实多路复用子流值目录。 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace Preview::Contract::Ingress
{
    /** @brief 活跃子流的按值身份；流号只在父 Session 内唯一。 */
    struct StreamIdentity final
    {
        Preview::SessionId Session{};
        Preview::WorkerId Worker{};
        Preview::GenerationId Generation{};
        Preview::StreamId Id{};

        friend auto operator==(const StreamIdentity &, const StreamIdentity &) noexcept -> bool = default;
    };

    enum class StreamState : std::uint8_t
    {
        Active,
        Draining,
        Retired,
    };

    /** @brief 当前有界 catalog 支持的实际 mux wire 类型。 */
    enum class StreamProtocol : std::uint8_t
    {
        Unspecified,
        Smux,
        Yamux,
        H2Mux,
    };

    /** @brief 协议 owner 能证明的 stream 身份、task scope、状态和账户事实。 */
    struct StreamDescriptor final
    {
        StreamIdentity Identity{};
        Preview::TaskId Task{};
        Preview::TaskId ParentTask{};
        Preview::AccountId Account{};
        StreamProtocol Protocol{StreamProtocol::Unspecified};
        StreamState State{StreamState::Active};
    };

    /** @brief 单个子流 reset 操作携带完整父 Session、stream task 与 root task 身份。 */
    struct StreamResetRequest final
    {
        StreamIdentity Identity{};
        Preview::TaskId Task{};
        Preview::TaskId ParentTask{};

        friend auto operator==(const StreamResetRequest &, const StreamResetRequest &) noexcept -> bool = default;
    };

    /**
     * @brief 协议 root 提供的真实 stream reset 与 task retirement owner。
     * @details Request 固定父 Session、stream child task 和 root task。实现只重置该 child，
     *          并在原协议 executor 上等控制写、stream activity drain 与 child task retirement；
     *          失败返回同一个 typed cause，不把交付接受当成退休完成。
     */
    class StreamResetOwner
    {
    public:
        virtual ~StreamResetOwner() = default;
        [[nodiscard]] virtual auto ResetAndDrain(StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
    };

    /** @brief 登记单一 reset owner 的弱引用；实际 task scope 保存在 StreamDescriptor。 */
    struct StreamResetBinding final
    {
        std::weak_ptr<StreamResetOwner> Owner;
    };

    enum class StreamCatalogStatus : std::uint8_t
    {
        Found,
        NotFound,
        CapabilityUnavailable,
    };

    /** @brief 查询结果只复制不可变 descriptor；从不借出目录项或网络 owner。 */
    struct StreamCatalogLookup final
    {
        StreamCatalogStatus Status{StreamCatalogStatus::CapabilityUnavailable};
        StreamDescriptor Value{};
    };

struct StreamParentIdentity final
{
    Preview::SessionId Session{};
    Preview::WorkerId Worker{};
    Preview::GenerationId Generation{};
};

struct StreamListRequest final
{
    StreamParentIdentity Parent{};
    std::uint64_t Cursor{0};
    std::size_t Limit{50};
};

/** @brief 一个已验证父 session 下的有界真实 live stream 值页。 */
struct StreamCatalogPage final
{
    StreamCatalogStatus Status{StreamCatalogStatus::CapabilityUnavailable};
    std::vector<StreamDescriptor> Items;
    std::uint64_t NextCursor{0};
    bool HasMore{false};
};

    /**
     * @class StreamCatalog
     * @brief 单个协议根的有界 live-stream 值目录。
     * @details 唯一写入者是协议根 executor；读取方原子取得不可变目录并按值复制。
     *          容量必须由已执行的 wire engine 上限配置。目录只复制 live 项，Retired
     *          状态无需分配即可发布；登记失败或观察路径不完整时 Disable，禁止假 NotFound。
     */
    class StreamCatalog final
    {
        struct Entry final
        {
            Entry(StreamDescriptor Value, StreamResetBinding Reset)
                : Descriptor(std::move(Value)), Reset(std::move(Reset))
            {
            }

            StreamDescriptor Descriptor;
            StreamResetBinding Reset;
            std::atomic<StreamState> State{StreamState::Active};
        };

        using Directory = std::map<std::uint64_t, std::shared_ptr<Entry>>;

    public:
        /** @brief 只在真实 engine 接受对应上限后启用完整查询能力。 */
        [[nodiscard]] auto Enable(const std::size_t Capacity) noexcept -> bool
        {
            if (Capacity == 0U)
            {
                return false;
            }
            std::size_t Empty = 0U;
            if (!Capacity_.compare_exchange_strong(Empty, Capacity, std::memory_order_acq_rel))
            {
                return Empty == Capacity && IsAvailable();
            }
            Available_.store(true, std::memory_order_release);
            return true;
        }

        /** @brief 目录发生漏记或取消无法精确跟踪时，原子撤回全部查询能力。 */
        auto Disable() noexcept -> void
        {
            Available_.store(false, std::memory_order_release);
        }

        [[nodiscard]] auto IsAvailable() const noexcept -> bool
        {
            return Available_.load(std::memory_order_acquire);
        }

        /** @brief 登记真实 wire stream 和完整 task scope；沿用真实 engine 上限。 */
        [[nodiscard]] auto Register(StreamDescriptor Value, StreamResetBinding Reset)
            -> std::expected<void, Preview::Fault::Failure>
        {
            using Failure = Preview::Fault::Failure;
            if (!IsValid(Value.Identity) || !Value.Task || !Value.ParentTask ||
                Reset.Owner.expired() ||
                (Value.Protocol != StreamProtocol::Smux && Value.Protocol != StreamProtocol::Yamux &&
                 Value.Protocol != StreamProtocol::H2Mux))
            {
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!IsAvailable())
            {
                return std::unexpected(Failure{Preview::Fault::Code::NotSupported});
            }
            const auto Capacity = Capacity_.load(std::memory_order_acquire);
            if (Capacity == 0U)
            {
                return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            try
            {
                while (IsAvailable())
                {
                    auto Current = Directory_.load(std::memory_order_acquire);
                    auto Next = std::make_shared<Directory>();
                    if (Current)
                    {
                        for (const auto &[Id, Existing] : *Current)
                        {
                            if (Existing->State.load(std::memory_order_acquire) != StreamState::Retired)
                            {
                                Next->emplace(Id, Existing);
                            }
                        }
                    }
                    const auto Id = Value.Identity.Id.Value();
                    if (const auto Existing = Next->find(Id); Existing != Next->end())
                    {
                        if (Existing->second->Descriptor.Identity == Value.Identity)
                        {
                            return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
                        }
                        return std::unexpected(Failure{Preview::Fault::Code::Blocked});
                    }
                    if (Next->size() >= Capacity)
                    {
                        return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
                    }
                    Value.State = StreamState::Active;
                    Next->emplace(Id, std::make_shared<Entry>(Value, Reset));
                    std::shared_ptr<const Directory> Published(std::move(Next));
                    if (Directory_.compare_exchange_weak(
                            Current, Published, std::memory_order_acq_rel, std::memory_order_acquire))
                    {
                        return {};
                    }
                }
                return std::unexpected(Failure{Preview::Fault::Code::NotSupported});
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
            }
            catch (...)
            {
                return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
        }

        /** @brief 请求单一 stream RST 并等待其真实协议 drain 与 child task 退休。 */
        [[nodiscard]] auto ResetAndDrain(StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            using Failure = Preview::Fault::Failure;
            if (!IsValid(Request.Identity) || !Request.Task || !Request.ParentTask)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!IsAvailable())
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::NotSupported});
            }
            const auto Item = FindEntry(Request.Identity);
            if (!Item || Item->Descriptor.Task != Request.Task ||
                Item->Descriptor.ParentTask != Request.ParentTask)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
            }
            auto Current = Item->State.load(std::memory_order_acquire);
            if (Current == StreamState::Retired)
            {
                co_return std::expected<void, Failure>{};
            }
            if (Current == StreamState::Active &&
                !Item->State.compare_exchange_strong(
                    Current, StreamState::Draining, std::memory_order_acq_rel))
            {
                if (Current == StreamState::Retired)
                {
                    co_return std::expected<void, Failure>{};
                }
                if (Current != StreamState::Draining)
                {
                    co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
                }
            }
            if (Current != StreamState::Active && Current != StreamState::Draining)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            const auto Owner = Item->Reset.Owner.lock();
            if (!Owner)
            {
                Disable();
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            const auto Result = co_await Owner->ResetAndDrain(std::move(Request));
            if (!Result)
            {
                co_return std::unexpected(Result.error());
            }
            if (Item->State.load(std::memory_order_acquire) != StreamState::Retired)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            co_return std::expected<void, Failure>{};
        }

        /** @brief 发布 FIN/RST/取消后的 drain 状态；不分配、不延长 stream owner 寿命。 */
        [[nodiscard]] auto MarkDraining(const StreamIdentity &Identity) const noexcept -> bool
        {
            const auto Item = FindEntry(Identity);
            if (!Item)
            {
                return false;
            }
            auto Expected = StreamState::Active;
            if (Item->State.compare_exchange_strong(
                    Expected, StreamState::Draining, std::memory_order_acq_rel))
            {
                return true;
            }
            return Expected == StreamState::Draining;
        }

        /** @brief 真实 close 与 protocol Finish drain 成功后无分配地退休目录项。 */
        [[nodiscard]] auto Retire(const StreamIdentity &Identity) const noexcept -> bool
        {
            const auto Item = FindEntry(Identity);
            if (!Item)
            {
                return false;
            }
            auto Expected = StreamState::Draining;
            if (Item->State.compare_exchange_strong(
                    Expected, StreamState::Retired, std::memory_order_acq_rel))
            {
                return true;
            }
            return Expected == StreamState::Retired;
        }

        /** @brief 跨 executor 原子读取并返回完整值快照；退役项精确返回 NotFound。 */
        [[nodiscard]] auto Find(const StreamIdentity &Identity) const noexcept -> StreamCatalogLookup
        {
            if (!IsAvailable())
            {
                return {StreamCatalogStatus::CapabilityUnavailable, {}};
            }
            const auto Item = FindEntry(Identity);
            if (!Item)
            {
                if (!IsAvailable())
                {
                    return {StreamCatalogStatus::CapabilityUnavailable, {}};
                }
                return {StreamCatalogStatus::NotFound, {}};
            }
            const auto State = Item->State.load(std::memory_order_acquire);
            if (State == StreamState::Retired)
            {
                if (!IsAvailable())
                {
                    return {StreamCatalogStatus::CapabilityUnavailable, {}};
                }
                return {StreamCatalogStatus::NotFound, {}};
            }
            auto Snapshot = Item->Descriptor;
            Snapshot.State = State;
            if (!IsAvailable())
            {
                return {StreamCatalogStatus::CapabilityUnavailable, {}};
            }
            return {StreamCatalogStatus::Found, std::move(Snapshot)};
        }

        /** @brief 按固定父身份分页复制真实 live entries；Retired 项不产生伪 NotFound。 */
        [[nodiscard]] auto List(const StreamListRequest &Request) const -> StreamCatalogPage
        {
            StreamCatalogPage Result;
            Result.NextCursor = Request.Cursor;
            if (!IsAvailable())
            {
                return Result;
            }
            if (!Request.Parent.Session || !Request.Parent.Worker || !Request.Parent.Generation)
            {
                Result.Status = StreamCatalogStatus::NotFound;
                return Result;
            }
            const auto Current = Directory_.load(std::memory_order_acquire);
            if (Current)
            {
                constexpr std::size_t MaxPageSize{256U};
                const auto Limit = (std::min)(Request.Limit, MaxPageSize);
                for (auto It = Current->upper_bound(Request.Cursor); It != Current->end(); ++It)
                {
                    const auto &EntryValue = *It->second;
                    const auto &Identity = EntryValue.Descriptor.Identity;
                    if (Identity.Session != Request.Parent.Session ||
                        Identity.Worker != Request.Parent.Worker ||
                        Identity.Generation != Request.Parent.Generation)
                    {
                        continue;
                    }
                    const auto State = EntryValue.State.load(std::memory_order_acquire);
                    if (State == StreamState::Retired)
                    {
                        continue;
                    }
                    if (Result.Items.size() == Limit)
                    {
                        Result.HasMore = true;
                        break;
                    }
                    auto Descriptor = EntryValue.Descriptor;
                    Descriptor.State = State;
                    Result.NextCursor = Identity.Id.Value();
                    Result.Items.push_back(std::move(Descriptor));
                }
            }
            if (!IsAvailable())
            {
                Result.Items.clear();
                Result.NextCursor = Request.Cursor;
                Result.HasMore = false;
                return Result;
            }
            Result.Status = StreamCatalogStatus::Found;
            return Result;
        }

    private:
        [[nodiscard]] static auto IsValid(const StreamIdentity &Identity) noexcept -> bool
        {
            return Identity.Session && Identity.Worker && Identity.Generation && Identity.Id;
        }

        [[nodiscard]] auto FindEntry(const StreamIdentity &Identity) const noexcept
            -> std::shared_ptr<Entry>
        {
            const auto Current = Directory_.load(std::memory_order_acquire);
            if (!Current)
            {
                return {};
            }
            const auto Found = Current->find(Identity.Id.Value());
            if (Found == Current->end() || Found->second->Descriptor.Identity != Identity)
            {
                return {};
            }
            return Found->second;
        }

        std::atomic<std::shared_ptr<const Directory>> Directory_;
        std::atomic<std::size_t> Capacity_{0U};
        std::atomic<bool> Available_{false};
    };
}
