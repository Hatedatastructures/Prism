/** @file TrafficHistory.cpp @brief 固定容量流量历史写入与快照实现。 */
#include <Prism/Statistics/TrafficHistory.hpp>

#include <cstddef>
#include <vector>

namespace Prism::Statistics
{
    auto TrafficHistory::Append(TrafficSample Sample) noexcept -> void
    {
        if (Size_ != 0)
        {
            const auto Last = (Head_ + Size_ - 1) % Capacity;
            if (Sample.Timestamp < Samples_[Last].Timestamp) return;
            if (Sample.Timestamp == Samples_[Last].Timestamp)
            {
                Samples_[Last] = Sample;
                return;
            }
        }
        if (Size_ == Capacity)
        {
            Samples_[Head_] = Sample;
            Head_ = (Head_ + 1) % Capacity;
            return;
        }
        Samples_[(Head_ + Size_) % Capacity] = Sample;
        ++Size_;
    }

    auto TrafficHistory::Snapshot() const -> std::vector<TrafficSample>
    {
        std::vector<TrafficSample> Result;
        Result.reserve(Size_);
        for (std::size_t Index = 0; Index < Size_; ++Index)
            Result.push_back(Samples_[(Head_ + Index) % Capacity]);
        return Result;
    }
}
