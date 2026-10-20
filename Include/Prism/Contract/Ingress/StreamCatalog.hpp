/** @file StreamCatalog.hpp @brief 跨执行器查询的真实多路复用子流值目录。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <vector>

namespace Prism::Contract::Ingress
{
    /** @brief 活跃子流的按值身份；流号只在父 Session 内唯一。 */
    struct StreamIdentity final
    {
        Prism::SessionId Session{};
        Prism::WorkerId Worker{};
        Prism::GenerationId Generation{};
        Prism::StreamId Id{};

        friend auto operator==(const StreamIdentity &, const StreamIdentity &) noexcept -> bool = default;
    };

    enum class StreamState : std::uint8_t
    {
        Active, ///< 已登记且可查询的活动子流。
        Draining, ///< 已请求 FIN/RST/取消；物理 owner 仍负责排空。
        Retired, ///< 协议 owner 已确认关闭与真实 Finish 排空。
    };

    /** @brief 当前有界目录支持的实际多路复用线协议类型。 */
    enum class StreamProtocol : std::uint8_t
    {
        Unspecified, ///< 尚未绑定实际 wire 协议。
        Smux, ///< smux 多路复用子流。
        Yamux, ///< yamux 多路复用子流。
        H2Mux, ///< HTTP/2 多路复用子流。
    };

    /** @brief 协议所有者可证明的子流身份、任务作用域、状态和账户信息。 */
    struct StreamDescriptor final
    {
        StreamIdentity Identity{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};
        Prism::AccountId Account{};
        StreamProtocol Protocol{StreamProtocol::Unspecified};
        StreamState State{StreamState::Active};
    };

    /** @brief 单个子流重置操作携带完整父 Session、子流任务与根任务身份。 */
    struct StreamResetRequest final
    {
        StreamIdentity Identity{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};

        friend auto operator==(const StreamResetRequest &, const StreamResetRequest &) noexcept -> bool = default;
    };

    /**
     * @brief 协议根提供的真实子流重置与任务退休所有者。
     * @details Request 固定父 Session、子流任务和根任务。实现只重置该子任务，
     *          并在原协议执行器上等待控制写、子流活动排空与子任务退休；
     *          失败返回同一类型的原因，不把交付接受当成退休完成。等待取消或失败时，
     *          协议 owner 仍须保活子流资源并继续完成关闭；此接口不关闭根 carrier。
     */
    class StreamResetOwner
    {
    public:
        virtual ~StreamResetOwner() = default;
        /**
         * @brief 请求单个子流重置并等待控制写、活动和任务真实退休。
         * @param Request 按值移交的完整子流与父任务身份。
         * @return 仅真实退休时成功；实现 Failure 原样返回，不能把命令已投递当成成功。
         * @note 在绑定的协议 executor 驱动；等待取消不转移最终关闭责任，协议 owner 仍保活资源。
         */
        [[nodiscard]] virtual auto ResetAndDrain(StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
    };

    /** @brief 登记单一重置所有者的弱引用；实际任务作用域保存在 StreamDescriptor。 */
    struct StreamResetBinding final
    {
        std::weak_ptr<StreamResetOwner> Owner;
    };

    /** @brief 查询状态；CapabilityUnavailable 不可折叠成 NotFound。 */
    enum class StreamCatalogStatus : std::uint8_t
    {
        Found, ///< 能力可用；Lookup 有值，分页查询已执行（Items 可以为空）。
        NotFound, ///< Lookup 的项不存在，或分页请求的父身份无效。
        CapabilityUnavailable, ///< 目录未启用或已 Disable，不能断言资源不存在。
    };

    /** @brief 查询结果只复制不可变描述；从不借出目录项或网络资源所有者。 */
    struct StreamCatalogLookup final
    {
        StreamCatalogStatus Status{StreamCatalogStatus::CapabilityUnavailable};
        StreamDescriptor Value{};
    };

    struct StreamParentIdentity final
    {
        Prism::SessionId Session{};
        Prism::WorkerId Worker{};
        Prism::GenerationId Generation{};
    };

    struct StreamListRequest final
    {
        StreamParentIdentity Parent{};
        std::uint64_t Cursor{0};
        std::size_t Limit{50};
    };

    /** @brief 一个已验证父会话下的有界真实活动子流值页。 */
    struct StreamCatalogPage final
    {
        StreamCatalogStatus Status{StreamCatalogStatus::CapabilityUnavailable};
        std::vector<StreamDescriptor> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
    };

    /**
     * @class StreamCatalog
     * @brief 单个协议根的有界活动子流值目录。
     * @details 冷装配的容量/目录发布由协议根 executor 执行；读取方可跨 executor 原子取得不可变目录并按值复制。
     *          子流状态以 atomic 转移，允许 Runtime 跨 executor 标记排空/退休。容量必须由已执行的
     *          线协议引擎上限配置。目录不拥有子流、任务或传输，只保存描述
     *          和 reset owner 弱引用。ResetAndDrain 委托协议根在其原 executor 重置并等待子流
     *          真实退休；取消/失败后项仍可能为 Draining，不能据此释放物理 owner。目录不执行
     *          半关闭或最终关闭，责任仍属协议根/子流 owner。观察路径不完整或 reset owner 消失时
     *          Disable；普通参数、重复项或容量拒绝只返回明确 Failure。
     */
    class StreamCatalog final
    {
        struct Entry final
        {
            Entry(StreamDescriptor Value, StreamResetBinding Reset);

            StreamDescriptor Descriptor;
            StreamResetBinding Reset;
            std::atomic<StreamState> State{StreamState::Active};
        };

        using Directory = std::map<std::uint64_t, std::shared_ptr<Entry>>;

    public:
        /**
         * @brief 只在真实引擎接受对应上限后启用完整查询能力。
         * @param Capacity 实际 wire 引擎已接受的非零子流上限；首次设置后不可更换。
         * @return 首次设置成功，或相同上限且仍可用时为 true；零值、不同上限或已 Disable 时为 false。
         * @note 冷装配写操作；不创建子流，也不改变任何资源 owner。
         */
        [[nodiscard]] auto Enable(const std::size_t Capacity) noexcept -> bool;

        /**
         * @brief 观察路径不完整或 reset owner 消失时，原子撤回全部查询能力。
         * @details 只使查询状态变为 CapabilityUnavailable，不取消子流、不关闭或释放协议资源。
         */
        auto Disable() noexcept -> void;

        /** @brief 读取查询能力是否启用；false 不表示流已关闭或物理 owner 已退休。 */
        [[nodiscard]] auto IsAvailable() const noexcept -> bool;

        /**
         * @brief 登记真实线协议子流和完整任务作用域；沿用真实引擎上限。
         * @param Value 按值复制的子流描述；State 由目录设置为 Active。
         * @param Reset 按值保存的 reset owner 弱引用；实际任务与关闭 owner 仍归协议根。
         * @return 空 expected 表示已登记。InvalidArgument 表示身份/任务/owner/protocol 无效或重复身份；
         *         NotSupported 表示目录不可用，Blocked 表示容量未设置/ID 冲突/其它异常，
         *         ResourceUnavailable 表示目录已满或分配失败。登记失败不自动 Disable，也不关闭资源。
         * @note 注册须由协议根 executor 执行；查询和状态原子转移可跨 executor。
         */
        [[nodiscard]] auto Register(StreamDescriptor Value, StreamResetBinding Reset)
            -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 请求单个子流 RST，并等待真实协议排空与子任务退休。
         * @param Request 完整父 session、子流任务与根任务身份；按值交给 reset owner。
         * @return 已退休或成功完成 reset/drain 时成功；InvalidArgument 表示请求身份不合法，
         *         NotSupported 表示目录不可用，ResourceUnavailable 表示目录项/任务身份不符，
         *         Blocked 表示 owner 丢失、目录状态不一致或成功回执未发布 Retired。owner 的 Failure 原样返回。
         * @note 先将目录项置为 Draining，再委托协议根原 executor。等待取消或失败不会回滚该状态，
         *       也不关闭物理资源；协议 owner 必须继续保活并完成退休。
         */
        [[nodiscard]] auto ResetAndDrain(StreamResetRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /**
         * @brief 发布 FIN/RST/取消后的排空状态；不分配、不延长子流资源所有者寿命。
         * @return Active 转为 Draining 或已是 Draining 时为 true；身份不存在或已 Retired 时为 false。
         * @note 仅更新目录值，不发起 I/O、半关闭、取消或最终关闭。
         */
        [[nodiscard]] auto MarkDraining(const StreamIdentity &Identity) const noexcept -> bool;

        /**
         * @brief 真实关闭与协议 Finish 排空成功后无分配地退休目录项。
         * @return Draining 转为 Retired 或已是 Retired 时为 true；身份不存在或尚未 Draining 时为 false。
         * @note 调用者须先取得协议 owner 的真实关闭与 drain 证明；本方法不关闭资源。
         */
        [[nodiscard]] auto Retire(const StreamIdentity &Identity) const noexcept -> bool;

        /**
         * @brief 跨执行器原子读取并返回完整值快照；退役项精确返回 NotFound。
         * @param Identity 完整父 session、worker、generation 与子流身份。
         * @return Found 附带值快照；不存在返回 NotFound；目录不可用返回 CapabilityUnavailable。
         *         结果不拥有子流、任务或传输。
         */
        [[nodiscard]] auto Find(const StreamIdentity &Identity) const noexcept -> StreamCatalogLookup;

        /**
         * @brief 按固定父身份分页复制真实活动条目；Retired 项不产生伪 NotFound。
         * @param Request 固定父身份与游标/上限；按值读取，不转移资源所有权。
         * @return 返回值页及明确 Status；目录不可用时为 CapabilityUnavailable，不伪装为空页。
         *         可用目录返回 Found，即使 Items 为空；父身份无效时返回 NotFound。Limit 最大按 256 截断。
         */
        [[nodiscard]] auto List(const StreamListRequest &Request) const -> StreamCatalogPage;

    private:
        [[nodiscard]] static auto IsValid(const StreamIdentity &Identity) noexcept -> bool;

        [[nodiscard]] auto FindEntry(const StreamIdentity &Identity) const noexcept
            -> std::shared_ptr<Entry>;

        std::atomic<std::shared_ptr<const Directory>> Directory_;
        std::atomic<std::size_t> Capacity_{0U};
        std::atomic<bool> Available_{false};
    };
}
