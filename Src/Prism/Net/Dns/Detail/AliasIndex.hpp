/** @file AliasIndex.hpp @brief 当前完整 DNS 报文的有界 CNAME 偏移索引。 */
#pragma once

#include <Prism/Net/Dns/Detail/Record.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <array>
#include <expected>
#include <optional>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    /** @brief 索引只保存已验证记录的偏移，名字和目标均复用唯一解码事实。 */
    struct AliasEntry final
    {
        std::uint16_t NameOffset{0};
        std::uint16_t TargetOffset{0};
        std::uint16_t TargetLength{0};
    };

    /**
     * @brief 同步关联扫描 owner；八项内联，后续六字节元数据按需进入一个池块。
     * @details 一个 64 KiB 块覆盖最大报文全部记录偏移；排序为原地堆排序，无递归堆分配。
     *          索引仅借用当前完整报文，不能跨异步保留；其 lease 在扫描返回时归还。
     */
    class AliasIndex final
    {
    public:
        explicit AliasIndex(const std::span<const std::uint8_t> Data) noexcept : Data_(Data) {}
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }

        [[nodiscard]] auto TryAppend(const AliasEntry Entry, Memory::BytePool &Pool)
            noexcept -> std::expected<void, Fault::Failure>
        {
            if (Size_ < Inline_.size())
            {
                Inline_[Size_++] = Entry;
                return {};
            }
            if (Storage_.Capacity() == 0)
            {
                if (Pool.BlockSize() < EntrySize)
                    return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
                auto Acquired = Pool.TryAcquire(0);
                if (!Acquired) return std::unexpected(Acquired.error());
                Storage_ = std::move(*Acquired);
            }
            const auto Offset = Storage_.Size();
            if (Storage_.Capacity() - Offset < EntrySize)
                return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
            const auto Resized = Storage_.Resize(Offset + EntrySize);
            if (!Resized) return Resized;
            Store(Size_, Entry);
            ++Size_;
            return {};
        }

        /** @brief 原地 O(N log N) 排序；名称读取失败仍返回原始 Failure，不发布伪索引。 */
        [[nodiscard]] auto Sort() noexcept -> std::expected<void, Fault::Failure>
        {
            for (auto Root = Size_ / 2; Root != 0; --Root)
            {
                const auto Sorted = Sift(Root - 1, Size_);
                if (!Sorted) return Sorted;
            }
            for (auto End = Size_; End > 1; --End)
            {
                Swap(0, End - 1);
                const auto Sorted = Sift(0, End - 1);
                if (!Sorted) return Sorted;
            }
            return {};
        }

        /** @brief 二分定位 owner；同一 owner 的多个目标必须一致，否则为 ProtocolError。 */
        [[nodiscard]] auto Find(const DecodedName &Owner) const noexcept
            -> std::expected<std::optional<DecodedName>, Fault::Failure>
        {
            std::size_t First = 0;
            auto Last = Size_;
            while (First < Last)
            {
                const auto Middle = First + (Last - First) / 2;
                const auto Name = NameAt(Middle);
                if (!Name) return std::unexpected(Name.error());
                if (Name->View() < Owner.View()) First = Middle + 1;
                else Last = Middle;
            }
            std::optional<DecodedName> Target;
            for (auto Index = First; Index < Size_; ++Index)
            {
                const auto Name = NameAt(Index);
                if (!Name) return std::unexpected(Name.error());
                if (Name->View() != Owner.View()) break;
                const auto Entry = Load(Index);
                NameCursor Cursor{Data_, Entry.TargetOffset};
                const auto Next = ReadName(Cursor);
                if (!Next) return std::unexpected(Next.error());
                if (Cursor.Offset != static_cast<std::size_t>(Entry.TargetOffset) + Entry.TargetLength ||
                    (Target && Target->View() != Next->View()))
                    return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
                Target = *Next;
            }
            return Target;
        }

    private:
        static constexpr std::size_t EntrySize = 6;

        [[nodiscard]] auto Load(const std::size_t Index) const noexcept -> AliasEntry
        {
            if (Index < Inline_.size()) return Inline_[Index];
            const auto Bytes = Storage_.Bytes().subspan((Index - Inline_.size()) * EntrySize, EntrySize);
            return {GetOffset(Bytes.first(2)), GetOffset(Bytes.subspan(2, 2)), GetOffset(Bytes.last(2))};
        }

        auto Store(const std::size_t Index, const AliasEntry Entry) noexcept -> void
        {
            if (Index < Inline_.size()) { Inline_[Index] = Entry; return; }
            const auto Bytes = Storage_.WritableBytes().subspan((Index - Inline_.size()) * EntrySize, EntrySize);
            PutOffset(Bytes.first(2), Entry.NameOffset);
            PutOffset(Bytes.subspan(2, 2), Entry.TargetOffset);
            PutOffset(Bytes.last(2), Entry.TargetLength);
        }

        [[nodiscard]] static auto GetOffset(const std::span<const std::byte> Bytes) noexcept
            -> std::uint16_t
        {
            return static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(Bytes[0]) << 8) |
                                              std::to_integer<std::uint8_t>(Bytes[1]));
        }

        static auto PutOffset(const std::span<std::byte> Bytes, const std::uint16_t Value) noexcept -> void
        {
            Bytes[0] = static_cast<std::byte>(Value >> 8);
            Bytes[1] = static_cast<std::byte>(Value & 0xFFu);
        }

        [[nodiscard]] auto NameAt(const std::size_t Index) const noexcept
            -> std::expected<DecodedName, Fault::Failure>
        {
            NameCursor Cursor{Data_, Load(Index).NameOffset};
            return ReadName(Cursor);
        }

        [[nodiscard]] auto Less(const std::size_t Left, const std::size_t Right) const noexcept
            -> std::expected<bool, Fault::Failure>
        {
            const auto First = NameAt(Left);
            if (!First) return std::unexpected(First.error());
            const auto Second = NameAt(Right);
            if (!Second) return std::unexpected(Second.error());
            return First->View() < Second->View();
        }

        auto Swap(const std::size_t Left, const std::size_t Right) noexcept -> void
        {
            const auto First = Load(Left);
            const auto Second = Load(Right);
            Store(Left, Second);
            Store(Right, First);
        }

        [[nodiscard]] auto Sift(std::size_t Root, const std::size_t Count) noexcept
            -> std::expected<void, Fault::Failure>
        {
            while (Root < Count / 2)
            {
                auto Child = Root * 2 + 1;
                if (Child + 1 < Count)
                {
                    const auto Compared = Less(Child, Child + 1);
                    if (!Compared) return std::unexpected(Compared.error());
                    if (*Compared) ++Child;
                }
                const auto Compared = Less(Root, Child);
                if (!Compared) return std::unexpected(Compared.error());
                if (!*Compared) break;
                Swap(Root, Child);
                Root = Child;
            }
            return {};
        }

        std::span<const std::uint8_t> Data_;
        std::array<AliasEntry, 8> Inline_{};
        Memory::OwnedBytes Storage_;
        std::size_t Size_{0};
    };
}
