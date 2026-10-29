/** @file IdSet.cpp @brief 任务身份不可变 AVL 集合实现。 */
#include <Prism/Lifecycle/Task/IdSet.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Lifecycle::Detail
{
    TaskIdSet::Node::Node(std::uint64_t Value, NodeOwner Left, NodeOwner Right)
        : Value(Value), Left(std::move(Left)), Right(std::move(Right)),
          Height(1U + (std::max)(HeightOf(this->Left), HeightOf(this->Right))),
          Count(1U + CountOf(this->Left) + CountOf(this->Right))
    {
    }

    auto TaskIdSet::HeightOf(const NodeOwner &Value) noexcept -> std::size_t
    {
        return Value ? Value->Height : 0U;
    }

    auto TaskIdSet::CountOf(const NodeOwner &Value) noexcept -> std::size_t
    {
        return Value ? Value->Count : 0U;
    }

    auto TaskIdSet::MakeNode(std::uint64_t Value, NodeOwner Left, NodeOwner Right) -> NodeOwner
    {
        return std::make_shared<const Node>(Value, std::move(Left), std::move(Right));
    }

    auto TaskIdSet::Balance(std::uint64_t Value, NodeOwner Left, NodeOwner Right) -> NodeOwner
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

    auto TaskIdSet::InsertNode(const NodeOwner &Current, std::uint64_t Value) -> NodeOwner
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

    auto TaskIdSet::EraseNode(const NodeOwner &Current, std::uint64_t Value) -> NodeOwner
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

    auto TaskIdSet::Visit(
        const NodeOwner &Current,
        void *Context,
        VisitorCallback Operation) -> void
    {
        if (!Current) { return; }
        Visit(Current->Left, Context, Operation);
        Operation(Context, Current->Value);
        Visit(Current->Right, Context, Operation);
    }

    auto TaskIdSet::Size() const noexcept -> std::size_t
    {
        return CountOf(Root_);
    }

    auto TaskIdSet::Contains(std::uint64_t Value) const noexcept -> bool
    {
        auto Current = Root_.get();
        while (Current)
        {
            if (Value == Current->Value) { return true; }
            Current = Value < Current->Value ? Current->Left.get() : Current->Right.get();
        }
        return false;
    }

    auto TaskIdSet::Insert(std::uint64_t Value) -> bool
    {
        if (Contains(Value)) { return false; }
        Root_ = InsertNode(Root_, Value);
        return true;
    }

    auto TaskIdSet::Erase(std::uint64_t Value) -> bool
    {
        if (!Contains(Value)) { return false; }
        Root_ = EraseNode(Root_, Value);
        return true;
    }
}
