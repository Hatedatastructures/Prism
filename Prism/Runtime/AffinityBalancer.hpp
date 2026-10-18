/**
 * @file AffinityBalancer.hpp
 * @brief Runtime 远端标识到 worker 的稳定亲和性选择。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace Prism::Runtime
{

    /**
     * @class AffinityBalancer
     * @brief 亲和性分发器。
     * @details FNV-1a 哈希远端标识，同一标识稳定映射到同一 worker。
     */
    class AffinityBalancer
    {
    public:
        explicit AffinityBalancer(std::size_t WorkerCount) : WorkerCount_(WorkerCount)
        {
            if (WorkerCount_ < 1)
            {
                WorkerCount_ = 1;
            }
        }

        [[nodiscard]] auto Select(std::string_view Key) const noexcept -> std::size_t
        {
            std::uint64_t Hash = 14695981039346656037ULL;
            for (const char Character : Key)
            {
                Hash ^= static_cast<unsigned char>(Character);
                Hash *= 1099511628211ULL;
            }
            return static_cast<std::size_t>(Hash % WorkerCount_);
        }

        [[nodiscard]] auto WorkerCount() const noexcept -> std::size_t
        {
            return WorkerCount_;
        }

    private:
        std::size_t WorkerCount_{1};
    };

} // namespace Prism::Runtime

