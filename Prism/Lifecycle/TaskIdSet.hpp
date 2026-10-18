/**
 * @file TaskIdSet.hpp
 * @brief 任务身份登记使用的不可变 AVL 节点与拥有型集合快照。
 * @details 集合按值复制共享旧节点；修改只复制搜索路径，发布前由调用者独占副本。
 *          节点持有子节点且没有反向边，旧快照在最后一个持有者释放后回收。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Lifecycle::Detail
{
    class TaskIdSet final
    {
        struct Node;
        using NodeOwner = std::shared_ptr<const Node>;

        struct Node final
        {
            Node(std::uint64_t Value, NodeOwner Left, NodeOwner Right)
                : Value(Value), Left(std::move(Left)), Right(std::move(Right)),
                  Height(1U + (std::max)(HeightOf(this->Left), HeightOf(this->Right))),
                  Count(1U + CountOf(this->Left) + CountOf(this->Right))
            {
            }

            std::uint64_t Value;
            NodeOwner Left;
            NodeOwner Right;
            std::size_t Height;
            std::size_t Count;
        };

        static auto HeightOf(const NodeOwner &Value) noexcept -> std::size_t
        {
            return Value ? Value->Height : 0U;
        }

        static auto CountOf(const NodeOwner &Value) noexcept -> std::size_t
        {
            return Value ? Value->Count : 0U;
        }

        static auto MakeNode(std::uint64_t Value, NodeOwner Left, NodeOwner Right) -> NodeOwner
        {
            return std::make_shared<const Node>(Value, std::move(Left), std::move(Right));
        }

        /** @brief 路径重建后恢复 AVL 平衡；三个输入分别是该节点及其两个子树。 */
        static auto Balance(std::uint64_t Value, NodeOwner Left, NodeOwner Right) -> NodeOwner
        {
            const auto LeftHeight = HeightOf(Left);
            const auto RightHeight = HeightOf(Right);
            if (LeftHeight > RightHeight + 1U)
            {
                if (HeightOf(Left->Left) >= HeightOf(Left->Right))
                {
                    auto NewRight = MakeNode(Value, Left->Right, std::move(Right));
                    return MakeNode(Left->Value, Left->Left, std::move(NewRight));
                }
                const auto Pivot = Left->Right;
                auto NewLeft = MakeNode(Left->Value, Left->Left, Pivot->Left);
                auto NewRight = MakeNode(Value, Pivot->Right, std::move(Right));
                return MakeNode(Pivot->Value, std::move(NewLeft), std::move(NewRight));
            }
            if (RightHeight > LeftHeight + 1U)
            {
                if (HeightOf(Right->Right) >= HeightOf(Right->Left))
                {
                    auto NewLeft = MakeNode(Value, std::move(Left), Right->Left);
                    return MakeNode(Right->Value, std::move(NewLeft), Right->Right);
                }
                const auto Pivot = Right->Left;
                auto NewLeft = MakeNode(Value, std::move(Left), Pivot->Left);
                auto NewRight = MakeNode(Right->Value, Pivot->Right, Right->Right);
                return MakeNode(Pivot->Value, std::move(NewLeft), std::move(NewRight));
            }
            return MakeNode(Value, std::move(Left), std::move(Right));
        }

        static auto InsertNode(const NodeOwner &Current, std::uint64_t Value) -> NodeOwner
        {
            if (!Current)
            {
                return MakeNode(Value, {}, {});
            }
            if (Value < Current->Value)
            {
                return Balance(Current->Value, InsertNode(Current->Left, Value), Current->Right);
            }
            return Balance(Current->Value, Current->Left, InsertNode(Current->Right, Value));
        }

        static auto EraseNode(const NodeOwner &Current, std::uint64_t Value) -> NodeOwner
        {
            if (Value < Current->Value)
            {
                return Balance(Current->Value, EraseNode(Current->Left, Value), Current->Right);
            }
            if (Value > Current->Value)
            {
                return Balance(Current->Value, Current->Left, EraseNode(Current->Right, Value));
            }
            if (!Current->Left) { return Current->Right; }
            if (!Current->Right) { return Current->Left; }
            auto Successor = Current->Right;
            while (Successor->Left) { Successor = Successor->Left; }
            return Balance(Successor->Value, Current->Left,
                           EraseNode(Current->Right, Successor->Value));
        }

        template <typename Visitor>
        static auto Visit(const NodeOwner &Current, Visitor &Operation) -> void
        {
            if (!Current) { return; }
            Visit(Current->Left, Operation);
            Operation(Current->Value);
            Visit(Current->Right, Operation);
        }

    public:
        /** @brief 返回当前快照的身份数量；不转移节点所有权，不调度异步工作。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return CountOf(Root_);
        }

        /** @brief 同步借用当前快照查身份；返回是否存在，不提供取消或关闭操作。 */
        [[nodiscard]] auto Contains(std::uint64_t Value) const noexcept -> bool
        {
            auto Current = Root_.get();
            while (Current)
            {
                if (Value == Current->Value) { return true; }
                Current = Value < Current->Value ? Current->Left.get() : Current->Right.get();
            }
            return false;
        }

        /**
         * @brief 在调用者独占的副本中登记身份；重复返回 false，分配失败抛出并保留原快照。
         * @details 调用者负责 CAS 发布，不持有外部资源，不需要 executor/取消/半关闭。
         */
        [[nodiscard]] auto Insert(std::uint64_t Value) -> bool
        {
            if (Contains(Value)) { return false; }
            Root_ = InsertNode(Root_, Value);
            return true;
        }

        /**
         * @brief 在独占副本中移除身份；不存在返回 false，其他快照保持原身份与节点。
         * @details 分配失败抛出且原快照不变；最终节点关闭者是其最后一个共享持有者。
         */
        [[nodiscard]] auto Erase(std::uint64_t Value) -> bool
        {
            if (!Contains(Value)) { return false; }
            Root_ = EraseNode(Root_, Value);
            return true;
        }

        /**
         * @brief 同步借用访问者按身份递增顺序访问；访问者不逃逸，异常原样传给调用者。
         * @details 本调用保有根快照，访问期间的独立副本修改不会使节点失效。
         */
        template <typename Visitor>
        auto ForEach(Visitor &&Operation) const -> void
        {
            const auto Snapshot = Root_;
            Visit(Snapshot, Operation);
        }

    private:
        NodeOwner Root_;
    };
}
