/**
 * @file Throttle.hpp
 * @brief 限速与封禁中间件（T5-4 O4）
 * @details - ThrottleMiddleware：令牌桶限速（取不到令牌 → blocked）
 *          - BanMiddleware：失败计数超阈值 → 动态封禁（窗口过期自动解封）
 * @note 对应生产 ThrottleMiddleware / BanMiddleware
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/strand.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>

namespace Prism::Rate
{
    class TokenBucket;
}

namespace Prism::Middleware::Builtin
{

    namespace Net = boost::asio;

    /**
     * @class ThrottleMiddleware
     * @brief 限速中间件
     * @details 每连接消耗 1 令牌；不足 → blocked（管线终止）。
     *          令牌桶由调用方持有（跨连接共享）。
     */
    class ThrottleMiddleware final : public Middleware
    {
    public:
        /**
         * @brief 构造
         * @param bucket 令牌桶（调用方持有）
         * @param NowFn 时钟函数（毫秒；nullptr = 用 steady_clock）
         */
        explicit ThrottleMiddleware(Prism::Rate::TokenBucket *bucket,
                                     std::uint64_t (*NowFn)() = nullptr)
            : Bucket_(bucket), NowFn_(NowFn)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "throttle";
        }

        /**
         * @brief 限速检查
         * @return 空 Failure 表示通过；拒绝和缺少 bucket 保留领域码。
         * @note 调用方持有 Bucket_ 至 awaitable 完成；在调用 executor 同步检查，不拥有传输、不执行关闭。
         */
        auto Handle(Prism::SharedTransmission & /*Inbound*/, Context & /*ctx*/)
            -> Net::awaitable<Prism::Fault::Failure> override;

    private:
        Prism::Rate::TokenBucket *Bucket_; ///< 令牌桶（非拥有）
        std::uint64_t (*NowFn_)();           ///< 时钟函数
    };

    /** @brief 封禁策略；记录上限与过期窗口由一次冷配置值共同定义。 */
    struct BanOptions final
    {
        std::size_t MaxFailures{}; ///< 达到该失败数后封禁。
        std::uint64_t WindowMs{}; ///< 失败窗口与封禁 TTL，单位毫秒。
    };

    /**
     * @class BanMiddleware
     * @brief 有界、按单 executor strand 管理的远端失败封禁 owner。
     * @details 固定 256 槽、每键最多 64 字节；每次检查/记录都清退过期槽。
     *          容量耗尽和超长键明确返回 ResourceUnavailable，不丢弃失败记录。
     */
    class BanMiddleware final : public Middleware
    {
    public:
        using OwnerStrand = Net::strand<Net::any_io_executor>;

        static constexpr std::size_t EntryCapacity = 256;
        static constexpr std::size_t MaximumKeyBytes = 64;

        /**
         * @brief 创建策略和状态共用的 executor owner。
         * @param Options 失败阈值与窗口/封禁 TTL。
         * @param Executor 状态表唯一执行域；调用者持有本中间件至所有操作完成。
         */
        explicit BanMiddleware(BanOptions Options, Net::any_io_executor Executor)
            : Options_(Options), Owner_(Net::make_strand(std::move(Executor)))
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "ban";
        }

        /** @brief 在 owner strand 上按来源地址检查封禁并完成 TTL 清退。 */
        auto Handle(Prism::SharedTransmission & /*Inbound*/, Context &ctx)
            -> Net::awaitable<Prism::Fault::Failure> override;

        /**
         * @brief 记录一个远端失败并在阈值到达时启动封禁 TTL。
         * @param Key 远端地址键；在首次挂起前复制到有界局部存储。
         * @return Success 或明确的参数/容量失败；不触碰传输，不执行关闭。
         * @note 状态只在 Owner_ strand 修改；调用者必须 co_await 到完成并保持本 owner 存活。
         */
        auto RecordFailure(std::string_view Key) -> Net::awaitable<Prism::Fault::Failure>;

    private:
        struct Entry final
        {
            std::array<char, MaximumKeyBytes> Key{};
            std::size_t KeyLength{};
            std::size_t FailureCount{};
            std::uint64_t WindowStartedAt{};
            std::uint64_t LastFailureAt{};
            std::uint64_t BannedAt{};
            bool Occupied{};
            bool Banned{};
        };

        [[nodiscard]] auto IsValidOptions() const noexcept -> bool;

        [[nodiscard]] static auto NowMilliseconds() noexcept -> std::uint64_t;

        [[nodiscard]] static auto Elapsed(const std::uint64_t Now, const std::uint64_t Since) noexcept
            -> std::uint64_t;

        auto PruneExpired(const std::uint64_t Now) noexcept -> void;

        [[nodiscard]] auto Find(const std::string_view Key) noexcept -> Entry *;

        [[nodiscard]] auto FindFree() noexcept -> Entry *;

        const BanOptions Options_;
        OwnerStrand Owner_;
        std::array<Entry, EntryCapacity> Entries_{};
    };

} // namespace Prism::Middleware::Builtin
