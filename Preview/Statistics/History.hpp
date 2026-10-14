/** @file History.hpp @brief 控制 executor 记录的真实有界流量历史。 */
#pragma once
#include <Preview/Statistics/Types.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
namespace Preview::Statistics
{
    /** @brief Unix 毫秒与实际累计字节/终态；缺失采样不补零，也不合成活动数。 */
    struct TrafficSample final { std::uint64_t Timestamp{0}; TrafficValue Value{}; };
    /** @brief 单控制 executor 拥有固定 1024 槽；公开查询复制值，不保活业务。 */
    class TrafficHistory final
    {
    public:
        static constexpr std::size_t Capacity = 1024;
        /** @brief 仅在真实 flush 后追加；时钟倒退或相同毫秒更新当前样本，不伪造时间。 */
        auto Append(TrafficSample Sample) noexcept -> void
        {
            if (Size_ != 0)
            {
                const auto Last = (Head_ + Size_ - 1) % Capacity;
                if (Sample.Timestamp < Samples_[Last].Timestamp) return;
                if (Sample.Timestamp == Samples_[Last].Timestamp)
                { Samples_[Last] = Sample; return; }
            }
            if (Size_ == Capacity) { Samples_[Head_] = Sample; Head_ = (Head_ + 1) % Capacity; return; }
            Samples_[(Head_ + Size_) % Capacity] = Sample;
            ++Size_;
        }
        /** @brief 查询拥有型时间序列；输入/输出无资源生命周期副作用。 */
        [[nodiscard]] auto Snapshot() const -> std::vector<TrafficSample>
        {
            std::vector<TrafficSample> Result;
            Result.reserve(Size_);
            for (std::size_t Index = 0; Index < Size_; ++Index) Result.push_back(Samples_[(Head_ + Index) % Capacity]);
            return Result;
        }
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }
    private:
        std::array<TrafficSample, Capacity> Samples_{};
        std::size_t Head_{0}, Size_{0};
    };
}
