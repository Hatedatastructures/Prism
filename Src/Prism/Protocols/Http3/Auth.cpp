/**
 * @file Auth.cpp
 * @brief HTTP/3 拥有型头块预算与存储实现。
 */
#include <Prism/Protocols/Http3/Auth.hpp>

#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

namespace Prism::Http3
{

    HeaderBlock::HeaderBlock(
        std::shared_ptr<Prism::Memory::SessionResource<>> OwnerValue)
        : Owner(RequireOwner(std::move(OwnerValue))), Fields(Owner->Arena()),
          Storage_(std::make_unique<ReservedStorage>())
    {
        Fields.reserve(HeaderLimits::MaxHeaderFields);
    }

    auto HeaderBlock::TryAppend(
        const std::string_view Name,
        const std::string_view Value) noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Storage_ || Fields.size() >= HeaderLimits::MaxHeaderFields ||
            Name.size() > HeaderLimits::MaxFieldBytes ||
            Value.size() > HeaderLimits::MaxFieldBytes)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::OversizedMsg});
        }
        if (Name.size() > HeaderLimits::MaxHeaderSectionBytes - Storage_->ByteCount ||
            Value.size() > HeaderLimits::MaxHeaderSectionBytes - Storage_->ByteCount - Name.size())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::OversizedMsg});
        }
        const auto Index = Storage_->FieldCount;
        const auto NameOffset = Storage_->ByteCount;
        if (!Name.empty())
        {
            std::memcpy(Storage_->Bytes.data() + NameOffset, Name.data(), Name.size());
        }
        const auto ValueOffset = NameOffset + Name.size();
        if (!Value.empty())
        {
            std::memcpy(Storage_->Bytes.data() + ValueOffset, Value.data(), Value.size());
        }
        try
        {
            Fields.push_back(Qpack::HeaderField{std::string(Name), std::string(Value)});
        }
        catch (const std::bad_alloc &)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (...)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        }
        Storage_->Fields[Index] = FieldRange{NameOffset, Name.size(), ValueOffset, Value.size()};
        Storage_->ByteCount += Name.size() + Value.size();
        ++Storage_->FieldCount;
        return {};
    }

    auto HeaderBlock::Clear() noexcept -> void
    {
        Fields.clear();
        if (Storage_)
        {
            Storage_->ByteCount = 0;
            Storage_->FieldCount = 0;
        }
    }

    auto HeaderBlock::ByteSize() const noexcept -> std::size_t
    {
        std::size_t Total = 0;
        for (const auto &Field : Fields)
        {
            if (Field.Name.size() > HeaderLimits::MaxHeaderSectionBytes - Total)
            {
                return HeaderLimits::MaxHeaderSectionBytes + 1;
            }
            Total += Field.Name.size();
            if (Field.value.size() > HeaderLimits::MaxHeaderSectionBytes - Total)
            {
                return HeaderLimits::MaxHeaderSectionBytes + 1;
            }
            Total += Field.value.size();
        }
        return Total;
    }

    auto HeaderBlock::WithinLimits() const noexcept -> bool
    {
        if (Fields.size() > HeaderLimits::MaxHeaderFields)
        {
            return false;
        }
        for (const auto &Field : Fields)
        {
            if (Field.Name.size() > HeaderLimits::MaxFieldBytes ||
                Field.value.size() > HeaderLimits::MaxFieldBytes)
            {
                return false;
            }
        }
        return ByteSize() <= HeaderLimits::MaxHeaderSectionBytes;
    }

    auto HeaderBlock::RequireOwner(
        std::shared_ptr<Prism::Memory::SessionResource<>> Value)
        -> std::shared_ptr<Prism::Memory::SessionResource<>>
    {
        if (!Value)
        {
            throw std::invalid_argument("HTTP/3 HeaderBlock requires an arena owner");
        }
        return Value;
    }

} // namespace Prism::Http3
