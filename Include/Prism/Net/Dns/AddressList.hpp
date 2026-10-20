/** @file AddressList.hpp @brief DNS 地址摘要的独占存储与只读范围接口。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>

#include <boost/asio/ip/address.hpp>

#include <array>
#include <cstddef>
#include <expected>
#include <iterator>
#include <span>

namespace Prism::Network::Dns
{
    /**
     * @brief 独占地址列表；八个地址内联，溢出按需预约真实池块。
     * @details 块和 allocator 状态由 OwnedBytes 保活；移动不分配，析构无分配归还。
     *          只允许串行访问；无 executor、取消、半关闭或网络关闭行为。
     */
    class AddressList final
    {
    public:
        AddressList() noexcept = default;
        AddressList(const AddressList &) = delete;
        auto operator=(const AddressList &) -> AddressList & = delete;
        AddressList(AddressList &&Other) noexcept;
        auto operator=(AddressList &&Other) noexcept -> AddressList &;

        [[nodiscard]] auto Size() const noexcept -> std::size_t;
        [[nodiscard]] auto Empty() const noexcept -> bool;
        [[nodiscard]] auto operator[](std::size_t Index) const noexcept
            -> boost::asio::ip::address;

        /** @brief 先预约溢出容量再写入地址；失败不修改列表事实。 */
        [[nodiscard]] auto TryAppend(const boost::asio::ip::address &Address,
            Memory::BytePool &Pool) noexcept -> std::expected<void, Fault::Failure>;

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
            Iterator(const AddressList *Owner, std::size_t Index) noexcept;
            [[nodiscard]] auto operator*() const noexcept -> value_type;
            auto operator++() noexcept -> Iterator &;
            auto operator++(int) noexcept -> Iterator;
            [[nodiscard]] auto operator==(const Iterator &) const noexcept -> bool = default;

        private:
            const AddressList *Owner_{nullptr};
            std::size_t Index_{0};
        };

        /** @brief 范围入口；迭代器只借用本列表，移动或析构后失效。 */
        [[nodiscard]] auto begin() const & noexcept -> Iterator;
        [[nodiscard]] auto end() const & noexcept -> Iterator;
        auto begin() const && -> Iterator = delete;
        auto end() const && -> Iterator = delete;

    private:
        static constexpr std::size_t RecordSize = 17;

        [[nodiscard]] static auto Decode(std::span<const std::byte> Bytes) noexcept
            -> boost::asio::ip::address;
        static auto Encode(const boost::asio::ip::address &Address,
            std::span<std::byte> Bytes) noexcept -> void;

        std::array<boost::asio::ip::address, 8> Inline_{};
        std::array<Memory::OwnedBytes, 2> Chunks_{};
        std::size_t Size_{0};
    };
} // namespace Prism::Network::Dns
