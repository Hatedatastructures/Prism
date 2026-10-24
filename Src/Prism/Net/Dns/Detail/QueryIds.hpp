/** @file QueryIds.hpp @brief DNS 在途 query ID 的有界预约接口。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>

namespace Prism::Network::Dns
{
    namespace Detail
    {
        struct QueryIdState;
    }

    /**
     * @brief 独占在途 ID；移动转交真实 query owner，析构无分配归还一次。
     * @details 不能在取消命令发出时退休，须等所有关联 read/write/worker 实际退栈。
     *          没有 executor 或 socket 权限；不同预约可跨线程移动，本对象只串行访问。
     */
    class QueryIdReservation final
    {
    public:
        QueryIdReservation() noexcept = default;
        ~QueryIdReservation() noexcept;
        QueryIdReservation(const QueryIdReservation &) = delete;
        auto operator=(const QueryIdReservation &) -> QueryIdReservation & = delete;
        QueryIdReservation(QueryIdReservation &&Other) noexcept;
        auto operator=(QueryIdReservation &&Other) noexcept -> QueryIdReservation &;

        [[nodiscard]] auto Id() const noexcept -> std::uint16_t;
        auto Release() noexcept -> void;

    private:
        friend class QueryIds;
        QueryIdReservation(std::shared_ptr<Detail::QueryIdState> State,
            std::uint16_t Id) noexcept;

        std::shared_ptr<Detail::QueryIdState> State_;
        std::uint16_t Id_{0};
    };

    /** @brief 单真实上游 owner 的 ID 名字空间；不按进程全局猜测关联。 */
    class QueryIds final
    {
    public:
        /** @brief 冷分配固定 bitmap；上限必须在 1 到 65536 之间。 */
        explicit QueryIds(std::size_t MaxActive = 4096);
        QueryIds(const QueryIds &) = delete;
        auto operator=(const QueryIds &) -> QueryIds & = delete;

        /** @brief 使用一次 CSPRNG 的十六个候选取得 ID，不扫描或等待无界历史。 */
        [[nodiscard]] auto TryAcquire()
            -> std::expected<QueryIdReservation, Fault::Failure>;

        [[nodiscard]] auto Active() const noexcept -> std::size_t;

    private:
        std::shared_ptr<Detail::QueryIdState> State_;
    };
} // namespace Prism::Network::Dns
