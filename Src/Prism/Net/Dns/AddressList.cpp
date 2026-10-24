/** @file AddressList.cpp @brief DNS 地址列表的存储与池块编码实现。 */
#include <Prism/Net/Dns/AddressList.hpp>

#include <cassert>
#include <cstdint>
#include <utility>

namespace Prism::Network::Dns
{
    AddressList::AddressList(AddressList &&Other) noexcept
        : Inline_(Other.Inline_), Chunks_(std::move(Other.Chunks_)),
          Size_(std::exchange(Other.Size_, 0))
    {
    }

    auto AddressList::operator=(AddressList &&Other) noexcept -> AddressList &
    {
        if (this != &Other)
        {
            Inline_ = Other.Inline_;
            Chunks_ = std::move(Other.Chunks_);
            Size_ = std::exchange(Other.Size_, 0);
        }
        return *this;
    }

    auto AddressList::Size() const noexcept -> std::size_t
    {
        return Size_;
    }

    auto AddressList::Empty() const noexcept -> bool
    {
        return Size_ == 0;
    }

    auto AddressList::operator[](const std::size_t Index) const noexcept
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

    auto AddressList::TryAppend(const boost::asio::ip::address &Address,
        Memory::BytePool &Pool) noexcept -> std::expected<void, Fault::Failure>
    {
        if (Address.is_v6() && Address.to_v6().scope_id() != 0)
        {
            return std::unexpected(Fault::Failure{Fault::Code::UnsupportedAddress, {}});
        }
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
                    return std::unexpected(
                        Fault::Failure{Fault::Code::ResourceUnavailable, {}});
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

    AddressList::Iterator::Iterator(const AddressList *Owner, const std::size_t Index) noexcept
        : Owner_(Owner), Index_(Index)
    {
    }

    auto AddressList::Iterator::operator*() const noexcept -> value_type
    {
        return (*Owner_)[Index_];
    }

    auto AddressList::Iterator::operator++() noexcept -> Iterator &
    {
        ++Index_;
        return *this;
    }

    auto AddressList::Iterator::operator++(int) noexcept -> Iterator
    {
        auto Previous = *this;
        ++Index_;
        return Previous;
    }

    auto AddressList::begin() const & noexcept -> Iterator
    {
        return {this, 0};
    }

    auto AddressList::end() const & noexcept -> Iterator
    {
        return {this, Size_};
    }

    auto AddressList::Decode(const std::span<const std::byte> Bytes) noexcept
        -> boost::asio::ip::address
    {
        if (std::to_integer<std::uint8_t>(Bytes[0]) == 4)
        {
            boost::asio::ip::address_v4::bytes_type Address{};
            for (std::size_t Index = 0; Index < Address.size(); ++Index)
            {
                Address[Index] = std::to_integer<unsigned char>(Bytes[Index + 1]);
            }
            return boost::asio::ip::address_v4(Address);
        }
        boost::asio::ip::address_v6::bytes_type Address{};
        for (std::size_t Index = 0; Index < Address.size(); ++Index)
        {
            Address[Index] = std::to_integer<unsigned char>(Bytes[Index + 1]);
        }
        return boost::asio::ip::address_v6(Address);
    }

    auto AddressList::Encode(const boost::asio::ip::address &Address,
        const std::span<std::byte> Bytes) noexcept -> void
    {
        if (Address.is_v4())
        {
            Bytes[0] = std::byte{4};
            const auto Raw = Address.to_v4().to_bytes();
            for (std::size_t Index = 0; Index < Raw.size(); ++Index)
            {
                Bytes[Index + 1] = static_cast<std::byte>(Raw[Index]);
            }
            return;
        }
        Bytes[0] = std::byte{6};
        const auto Raw = Address.to_v6().to_bytes();
        for (std::size_t Index = 0; Index < Raw.size(); ++Index)
        {
            Bytes[Index + 1] = static_cast<std::byte>(Raw[Index]);
        }
    }
} // namespace Prism::Network::Dns
