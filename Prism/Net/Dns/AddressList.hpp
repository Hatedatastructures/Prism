/**
 * @file AddressList.hpp
 * @brief DNS 地址摘要的内联存储和有界可回收溢出存储。
 */
#pragma once

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <boost/asio/ip/address.hpp>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iterator>
#include <utility>

namespace Prism::Network::Dns
{
    /**
     * @brief 独占地址列表；八个地址内联，溢出按需预约真实池块。
     * @details 记录采用一字节地址族和十六字节地址，两个 64 KiB 块足以覆盖
     *          最大 65535 字节 DNS 报文的全部地址记录，不为普通应答预占块。
     *          块和 allocator 状态由 OwnedBytes 保活；移动不分配，析构无分配归还。
     *          只允许串行访问；无 executor、取消、半关闭或网络关闭行为。
     */
    class AddressList final
    {
    public:
        AddressList() noexcept = default;
        AddressList(const AddressList&) = delete;
        auto operator=(const AddressList&) -> AddressList& = delete;
        AddressList(AddressList&& Other) noexcept
            : Inline_(Other.Inline_), Chunks_(std::move(Other.Chunks_)),
              Size_(std::exchange(Other.Size_, 0)) {}
        auto operator=(AddressList&& Other) noexcept -> AddressList&
        {
            if (this != &Other)
            {
                Inline_ = Other.Inline_;
                Chunks_ = std::move(Other.Chunks_);
                Size_ = std::exchange(Other.Size_, 0);
            }
            return *this;
        }

        /** @brief 返回已成功写入的地址数，不包含任何预约但未写入的记录。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }
        /** @brief 是否没有实际地址。 */
        [[nodiscard]] auto Empty() const noexcept -> bool { return Size_ == 0; }

        /** @brief 读取已写地址；Index 必须小于 Size，返回独立地址值。 */
        [[nodiscard]] auto operator[](const std::size_t Index) const noexcept
            -> boost::asio::ip::address
        {
            assert(Index < Size_);
            if (Index < Inline_.size())
            {
                return Inline_[Index];
            }
            auto Position = Index - Inline_.size();
            for (const auto &Chunk : Chunks_)
            {
                const auto Count = Chunk.Size() / RecordSize;
                if (Position < Count)
                {
                    return Decode(Chunk.Bytes().subspan(Position * RecordSize, RecordSize));
                }
                Position -= Count;
            }
            std::unreachable();
        }

        /**
         * @brief 先预约溢出容量再写入地址；失败不修改列表事实。
         * @param Address 同步借用的地址，不保存输入引用。
         * @param Pool 真实有界池；只在调用期间借用，结果租约自行保活存储。
         * @return 真实池容量或两块预算耗尽为 ResourceUnavailable，不做堆回退。
         */
        [[nodiscard]] auto TryAppend(const boost::asio::ip::address &Address, Memory::BytePool &Pool)
            noexcept -> std::expected<void, Fault::Failure>
        {
            if (Address.is_v6() && Address.to_v6().scope_id() != 0)
                return std::unexpected(Fault::Failure{Fault::Code::UnsupportedAddress, {}});
            if (Size_ < Inline_.size())
            {
                Inline_[Size_++] = Address;
                return {};
            }
            for (auto &Chunk : Chunks_)
            {
                if (Chunk.Capacity() == 0)
                {
                    if (Pool.BlockSize() < RecordSize)
                    {
                        return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
                    }
                    auto Acquired = Pool.TryAcquire(0);
                    if (!Acquired)
                    {
                        return std::unexpected(Acquired.error());
                    }
                    Chunk = std::move(*Acquired);
                }
                if (Chunk.Capacity() - Chunk.Size() < RecordSize)
                {
                    continue;
                }
                const auto Offset = Chunk.Size();
                auto Resized = Chunk.Resize(Offset + RecordSize);
                if (!Resized)
                {
                    return std::unexpected(Resized.error());
                }
                Encode(Address, Chunk.WritableBytes().subspan(Offset, RecordSize));
                ++Size_;
                return {};
            }
            return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
        }

        /** @brief 标准只读输入迭代器；标准要求的 traits 名称保留原拼写。 */
        class Iterator final
        {
        public:
            using value_type = boost::asio::ip::address;
            using difference_type = std::ptrdiff_t;
            using iterator_category = std::input_iterator_tag;
            using iterator_concept = std::input_iterator_tag;
            using reference = value_type;
            using pointer = void;

            Iterator() noexcept = default;
            Iterator(const AddressList *Owner, const std::size_t Index) noexcept
                : Owner_(Owner), Index_(Index) {}
            [[nodiscard]] auto operator*() const noexcept -> value_type { return (*Owner_)[Index_]; }
            auto operator++() noexcept -> Iterator& { ++Index_; return *this; }
            auto operator++(int) noexcept -> Iterator { auto Previous = *this; ++Index_; return Previous; }
            [[nodiscard]] auto operator==(const Iterator&) const noexcept -> bool = default;
        private:
            const AddressList *Owner_{nullptr};
            std::size_t Index_{0};
        };

        /** @brief 标准范围入口；迭代器只借用本列表，移动或析构后失效。 */
        [[nodiscard]] auto begin() const & noexcept -> Iterator { return {this, 0}; }
        [[nodiscard]] auto end() const & noexcept -> Iterator { return {this, Size_}; }
        auto begin() const && -> Iterator = delete;
        auto end() const && -> Iterator = delete;

    private:
        static constexpr std::size_t RecordSize = 17;

        [[nodiscard]] static auto Decode(const std::span<const std::byte> Bytes) noexcept
            -> boost::asio::ip::address
        {
            if (std::to_integer<std::uint8_t>(Bytes[0]) == 4)
            {
                boost::asio::ip::address_v4::bytes_type Address{};
                for (std::size_t Index = 0; Index < Address.size(); ++Index)
                    Address[Index] = std::to_integer<unsigned char>(Bytes[Index + 1]);
                return boost::asio::ip::address_v4(Address);
            }
            boost::asio::ip::address_v6::bytes_type Address{};
            for (std::size_t Index = 0; Index < Address.size(); ++Index)
                Address[Index] = std::to_integer<unsigned char>(Bytes[Index + 1]);
            return boost::asio::ip::address_v6(Address);
        }

        static auto Encode(const boost::asio::ip::address &Address,
                           const std::span<std::byte> Bytes) noexcept -> void
        {
            if (Address.is_v4())
            {
                Bytes[0] = std::byte{4};
                const auto Raw = Address.to_v4().to_bytes();
                for (std::size_t Index = 0; Index < Raw.size(); ++Index)
                    Bytes[Index + 1] = static_cast<std::byte>(Raw[Index]);
                return;
            }
            Bytes[0] = std::byte{6};
            const auto Raw = Address.to_v6().to_bytes();
            for (std::size_t Index = 0; Index < Raw.size(); ++Index)
                Bytes[Index + 1] = static_cast<std::byte>(Raw[Index]);
        }

        std::array<boost::asio::ip::address, 8> Inline_{};
        std::array<Memory::OwnedBytes, 2> Chunks_{};
        std::size_t Size_{0};
    };
}
