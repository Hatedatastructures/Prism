/**
 * @file IdSet.hpp
 * @brief 任务身份登记使用的不可变 AVL 节点与拥有型集合快照。
 * @details 集合按值复制共享旧节点；修改只复制搜索路径，发布前由调用者独占副本。
 *          节点持有子节点且没有反向边，旧快照在最后一个持有者释放后回收。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

namespace Prism::Lifecycle::Detail
{
    class TaskIdSet final
    {
        struct Node;
        using NodeOwner = std::shared_ptr<const Node>;

        struct Node final
        {
            Node(std::uint64_t Value, NodeOwner Left, NodeOwner Right);

            std::uint64_t Value;
            NodeOwner Left;
            NodeOwner Right;
            std::size_t Height;
            std::size_t Count;
        };

        static auto HeightOf(const NodeOwner &Value) noexcept -> std::size_t;

        static auto CountOf(const NodeOwner &Value) noexcept -> std::size_t;

        static auto MakeNode(std::uint64_t Value, NodeOwner Left, NodeOwner Right) -> NodeOwner;

        /** @brief 路径重建后恢复 AVL 平衡；三个输入分别是该节点及其两个子树。 */
        static auto Balance(std::uint64_t Value, NodeOwner Left, NodeOwner Right) -> NodeOwner;

        static auto InsertNode(const NodeOwner &Current, std::uint64_t Value) -> NodeOwner;

        static auto EraseNode(const NodeOwner &Current, std::uint64_t Value) -> NodeOwner;

        using VisitorCallback = void (*)(void *, const std::uint64_t &);

        static auto Visit(
            const NodeOwner &Current,
            void *Context,
            VisitorCallback Operation) -> void;

        template <typename Visitor>
        static auto InvokeVisitor(void *Context, const std::uint64_t &Value) -> void
        {
            (*static_cast<Visitor *>(Context))(Value);
        }

    public:
        /** @brief 返回当前快照的身份数量；不转移节点所有权，不调度异步工作。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t;

        /** @brief 同步借用当前快照查身份；返回是否存在，不提供取消或关闭操作。 */
        [[nodiscard]] auto Contains(std::uint64_t Value) const noexcept -> bool;

        /**
         * @brief 在调用者独占的副本中登记身份；重复返回 false，分配失败抛出并保留原快照。
         * @details 调用者负责 CAS 发布，不持有外部资源，不需要 executor/取消/半关闭。
         */
        [[nodiscard]] auto Insert(std::uint64_t Value) -> bool;

        /**
         * @brief 在独占副本中移除身份；不存在返回 false，其他快照保持原身份与节点。
         * @details 分配失败抛出且原快照不变；最终节点关闭者是其最后一个共享持有者。
         */
        [[nodiscard]] auto Erase(std::uint64_t Value) -> bool;

        /**
         * @brief 同步借用访问者按身份递增顺序访问；访问者不逃逸，异常原样传给调用者。
         * @details 本调用保有根快照，访问期间的独立副本修改不会使节点失效。
         */
        template <typename Visitor>
        auto ForEach(Visitor &&Operation) const -> void
        {
            const auto Snapshot = Root_;
            auto Invocation = [&Operation](const std::uint64_t Value) -> void
            {
                Operation(Value);
            };
            Visit(Snapshot, &Invocation, &InvokeVisitor<decltype(Invocation)>);
        }

    private:
        NodeOwner Root_;
    };
}
