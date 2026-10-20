/** @file TrafficHistory.hpp @brief 控制 executor 记录的真实有界流量历史。 */
#pragma once
#include <Prism/Statistics/Types.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
namespace Prism::Statistics
{
    /** @brief Unix 毫秒与实际累计字节/终态；缺失采样不补零，也不合成活动数。 */
    struct TrafficSample final { std::uint64_t Timestamp{0}; TrafficValue Value{}; };
    /** @brief 单控制 executor 拥有固定 1024 槽；公开查询复制值，不保活业务。 */
    class TrafficHistory final
    {
    public:
        static constexpr std::size_t Capacity = 1024;
        /** @brief 仅在真实 flush 后追加；时钟倒退或相同毫秒更新当前样本，不伪造时间。 */
        auto Append(TrafficSample Sample) noexcept -> void;
        /** @brief 查询拥有型时间序列；输入/输出无资源生命周期副作用。 */
        [[nodiscard]] auto Snapshot() const -> std::vector<TrafficSample>;
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }
    private:
        std::array<TrafficSample, Capacity> Samples_{};
        std::size_t Head_{0}, Size_{0};
    };
}
