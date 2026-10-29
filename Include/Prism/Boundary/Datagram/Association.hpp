/**
 * @file Association.hpp
 * @brief 独立 UDP socket 的 endpoint/association/worker 关联边界。
 * @details 该表只管理关联身份与生命周期，不解析 SOCKS5、VLESS 或其他
 *          应用协议。owner 由表持有，取消回调只执行一次；等待关闭使用
 *          owner-held channel，不使用阻塞锁或轮询。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

namespace Prism::Boundary
{

    namespace Net = boost::asio;

    struct DatagramAssociationKey final
    {
        Net::ip::udp::endpoint Peer;
        std::uint64_t AssociationId{0};
        std::uint64_t WorkerId{0};

        [[nodiscard]] auto operator==(const DatagramAssociationKey& Other) const noexcept -> bool;

        [[nodiscard]] auto Valid() const noexcept -> bool;
    };

    struct DatagramAssociationKeyHash final
    {
        [[nodiscard]] auto operator()(const DatagramAssociationKey& Key) const noexcept -> std::size_t;

    private:
        [[nodiscard]] static auto Combine(const std::size_t Seed, const std::uint64_t Value) noexcept
            -> std::size_t;
    };

    struct DatagramAssociationOptions final
    {
        Net::any_io_executor Executor{};
        std::function<void()> Cancel;
    };

    class DatagramAssociation final
    {
    public:
        DatagramAssociation(DatagramAssociationKey KeyValue, DatagramAssociationOptions Options);

        ~DatagramAssociation() noexcept;

        DatagramAssociation(const DatagramAssociation&) = delete;
        auto operator=(const DatagramAssociation&) -> DatagramAssociation& = delete;

        [[nodiscard]] auto Key() const noexcept -> const DatagramAssociationKey&;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor;

        [[nodiscard]] auto IsClosed() const noexcept -> bool;

        /**
         * @brief 取消 owner 并唤醒所有关闭等待者。
         * @details 取消回调由 association owner 提供，表和 association
         *          都只允许它成功执行一次。
         */
        auto Close() noexcept -> void;

        [[nodiscard]] auto WaitClosed() -> Net::awaitable<bool>;

    private:
        struct State;

        std::shared_ptr<State> State_;
    };

    using SharedDatagramAssociation = std::shared_ptr<DatagramAssociation>;

    class DatagramAssociationTable final
    {
    public:
        using AssociationMap =
            std::unordered_map<DatagramAssociationKey, SharedDatagramAssociation, DatagramAssociationKeyHash>;

        DatagramAssociationTable() = default;

        ~DatagramAssociationTable() noexcept;

        DatagramAssociationTable(const DatagramAssociationTable&) = delete;
        auto operator=(const DatagramAssociationTable&) -> DatagramAssociationTable& = delete;

        [[nodiscard]] auto Register(const DatagramAssociationKey& Key, SharedDatagramAssociation Association)
            -> bool;

        [[nodiscard]] auto Find(const DatagramAssociationKey& Key) const noexcept
            -> SharedDatagramAssociation;

        [[nodiscard]] auto Remove(const DatagramAssociationKey& Key) noexcept -> bool;

        auto Drain() noexcept -> void;

        auto Close() noexcept -> void;

        [[nodiscard]] auto Size() const noexcept -> std::size_t;

        [[nodiscard]] auto IsDraining() const noexcept -> bool;

        [[nodiscard]] auto IsClosed() const noexcept -> bool;

    private:
        AssociationMap Associations_;
        bool Draining_{false};
        bool Closed_{false};
    };

} // namespace Prism::Boundary
