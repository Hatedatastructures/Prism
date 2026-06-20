/**
 * @file pad.hpp
 * @brief Transport 层记录填充装饰器
 * @details 在 async_write_some 中根据填充策略注入随机填充字节,
 *          混淆 tunnel relay 的字节流大小特征。使用 BLAKE3 作为
 *          CSPRNG 生成随机填充大小和内容。
 *          前 stop_after 次 write 执行填充,之后透传零开销。
 */

#pragma once

#include <prism/core/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <blake3.h>

#include <array>
#include <cstdint>
#include <span>


namespace psm::transport
{

    namespace net = boost::asio;

    /**
     * @brief 填充目标描述
     */
    struct pad_target
    {
        std::uint16_t min_val{0};
        std::uint16_t max_val{0};
    };

    /**
     * @brief 填充配置
     */
    struct pad_config
    {
        memory::string pad_targets{"17,30-50,30-50,80-150"};
        std::uint8_t stop_after{12};
        std::uint16_t max_pad_bytes{256};

        [[nodiscard]] auto enabled() const noexcept -> bool
        {
            return !pad_targets.empty();
        }
    };

    /**
     * @class pad_transport
     * @brief Transport 层记录填充装饰器
     * @details 包装下层传输,在前 N 次 write 中注入随机填充。
     *          读操作直接透传。使用 BLAKE3 CTR 模式作为 CSPRNG。
     */
    class pad_transport final : public transmission
    {
    public:
        explicit pad_transport(shared_transmission inner,
                               const pad_config &cfg);

        ~pad_transport() noexcept override = default;

        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return inner_->transport_type();
        }

        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return inner_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return inner_.get();
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return inner_->executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;
        void cancel() override;

    private:
        shared_transmission inner_;
        pad_config cfg_;
        memory::vector<pad_target> targets_;
        memory::vector<std::byte> pad_buf_;
        std::uint8_t write_count_{0};

        /// BLAKE3 CSPRNG 状态
        std::array<std::uint8_t, 32> rng_key_{};
        std::uint64_t rng_counter_{0};
        std::array<std::uint8_t, 32> rng_cache_{};
        std::size_t rng_cache_pos_{32};

        /// @brief 计算当前 write 的填充字节数
        [[nodiscard]] auto compute_padding(std::size_t data_len) -> std::size_t;

        /// @brief 从 CSPRNG 生成 [min_val, max_val] 范围的随机数
        [[nodiscard]] auto rng_next_u16(std::uint16_t min_val, std::uint16_t max_val) -> std::uint16_t;

        /// @brief 刷新 CSPRNG 缓存
        auto rng_refill() -> void;

        /// @brief 从 CSPRNG 填充指定缓冲区
        auto rng_next_bytes(std::span<std::byte> out) -> void;

        /// @brief 解析 pad_targets 字符串为目标列表
        [[nodiscard]] static auto parse_targets(std::string_view spec, memory::resource_pointer mr)
            -> memory::vector<pad_target>;
    };

} // namespace psm::transport
