/**
 * @file pad.hpp
 * @brief Transport 层记录填充装饰器
 * @details 在 async_write_some 中根据填充策略注入随机填充字节,
 *          混淆 tunnel relay 的字节流大小特征。使用 BLAKE3 作为
 *          CSPRNG 生成随机填充大小和内容。
 *          前 stop_after 次 write 执行填充,之后透传零开销。
 */

#pragma once

#include <openssl/rand.h>

#include <common/core/memory/container.hpp>
#include <common/core/transmission.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <span>

#include <blake3.h>

namespace preview::transport {


    namespace net = boost::asio;

    /**
     * @struct pad_target
     * @brief 填充目标描述
     * @details 用 [min_val, max_val] 区间描述单条填充目标记录。
     */
    struct pad_target
    {
        std::uint16_t min_val{0}; // 填充长度下限
        std::uint16_t max_val{0}; // 填充长度上限
    };

    /**
     * @struct pad_config
     * @brief 填充配置
     */
    struct pad_config
    {
        memory::string pad_targets{"17,30-50,30-50,80-150"}; // 填充目标规格（逗号分隔，区间用 "-" 连接）
        std::uint8_t stop_after{12};                         // 前 N 次写入执行填充
        std::uint16_t max_pad_bytes{256};                    // 单次填充字节数上限

        /**
         * @brief 填充功能是否启用
         * @return pad_targets 非空返回 true
         */
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
        /**
         * @brief 构造填充装饰器
         * @param inner 被包装的内层传输
         * @param cfg 填充配置
         */
        explicit pad_transport(shared_transmission inner, const pad_config &cfg);

        ~pad_transport() noexcept override = default;

        /**
         * @brief 获取传输层类型
         * @return 内层传输的类型
         */
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return inner_->transport_type();
        }

        /**
         * @brief 获取内层传输
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return inner_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 被包装的内层传输指针
         */
        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return inner_.get();
        }

        /**
         * @brief 获取关联的执行器
         * @return 内层传输的执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override
        {
            return inner_->executor();
        }

        /**
         * @brief 异步读取数据
         * @details 读操作直接透传给内层传输，不做填充处理。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 在前 stop_after 次写入中按填充策略注入随机填充，
         * 之后透传零开销。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override;

    private:
        shared_transmission inner_;                    // 被包装的内层传输
        pad_config cfg_;                               // 填充配置
        memory::vector<pad_target> targets_;           // 解析后的填充目标列表
        memory::vector<std::byte> pad_buf_;            // 填充数据缓冲区
        std::uint8_t write_count_{0};                  // 已执行填充的写入次数

        /// BLAKE3 CSPRNG 状态
        std::array<std::uint8_t, 32> rng_key_{};       // CSPRNG 密钥
        std::uint64_t rng_counter_{0};                 // CSPRNG 计数器
        std::array<std::uint8_t, 32> rng_cache_{};     // CSPRNG 输出缓存
        std::size_t rng_cache_pos_{32};                // CSPRNG 缓存读取位置

        /**
         * @brief 计算当前 write 的填充字节数
         * @param data_len 待写入的数据长度
         * @return 本次写入的填充字节数
         */
        [[nodiscard]] auto compute_padding(std::size_t data_len) -> std::size_t;

        /**
         * @brief 从 CSPRNG 生成 [min_val, max_val] 范围的随机数
         * @param min_val 随机数下限
         * @param max_val 随机数上限
         * @return [min_val, max_val] 范围内的随机数
         */
        [[nodiscard]] auto rng_next_u16(std::uint16_t min_val, std::uint16_t max_val) -> std::uint16_t;

        /**
         * @brief 刷新 CSPRNG 缓存
         */
        auto rng_refill() -> void;

        /**
         * @brief 从 CSPRNG 填充指定缓冲区
         * @param out 目标缓冲区
         */
        auto rng_next_bytes(std::span<std::byte> out) -> void;

        /**
         * @brief 解析 pad_targets 字符串为目标列表
         * @param spec 填充目标规格字符串
         * @param mr 内存资源指针
         * @return 解析后的填充目标列表
         */
        [[nodiscard]] static auto parse_targets(std::string_view spec, memory::resource_pointer mr)
            -> memory::vector<pad_target>;
    };




    inline pad_transport::pad_transport(shared_transmission inner, const pad_config &cfg)
        : inner_(std::move(inner)), cfg_(cfg),
          targets_(parse_targets(cfg.pad_targets, memory::current_resource())),
          pad_buf_(16384 + 256, memory::current_resource())
    {
        /// 从 BoringSSL 获取 CSPRNG 种子
        RAND_bytes(rng_key_.data(), static_cast<int>(rng_key_.size()));
    }

    inline auto pad_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await inner_->async_read_some(buffer, ec);
    }

    inline auto pad_transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        /// 未启用或超过 stop_after 后直接透传,零开销
        if (!cfg_.enabled() || write_count_ >= cfg_.stop_after || buffer.empty())
        {
            co_return co_await inner_->async_write_some(buffer, ec);
        }

        const auto data_len = buffer.size();
        const auto pad_size = compute_padding(data_len);
        const auto total = data_len + pad_size;

        /// 如果 pad_buf_ 不够大,直接透传(极端情况)
        if (total > pad_buf_.size())
        {
            co_return co_await inner_->async_write_some(buffer, ec);
        }

        std::memcpy(pad_buf_.data(), buffer.data(), data_len);
        if (pad_size > 0)
        {
            rng_next_bytes(std::span<std::byte>(pad_buf_.data() + data_len, pad_size));
        }

        co_await inner_->async_write(std::span<const std::byte>(pad_buf_.data(), total), ec);

        ++write_count_;

        if (ec)
        {
            co_return 0;
        }
        co_return data_len;
    }

    inline void pad_transport::close()
    {
        inner_->close();
    }

    inline void pad_transport::cancel()
    {
        inner_->cancel();
    }

    inline auto pad_transport::compute_padding(std::size_t data_len) -> std::size_t
    {
        if (targets_.empty())
        {
            return rng_next_u16(0, cfg_.max_pad_bytes);
        }

        /// 选取当前 write_count 对应的 target(循环使用)
        const auto &target = targets_[write_count_ % targets_.size()];
        const auto target_len = rng_next_u16(target.min_val, target.max_val);

        if (data_len < target_len)
        {
            return target_len - data_len;
        }

        return rng_next_u16(0, cfg_.max_pad_bytes);
    }

    inline auto pad_transport::rng_next_u16(std::uint16_t min_val, std::uint16_t max_val) -> std::uint16_t
    {
        if (min_val >= max_val)
        {
            return min_val;
        }

        std::array<std::byte, 2> buf{};
        rng_next_bytes(buf);

        const auto raw =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[0])) << 8) |
                                       static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[1])));

        // 用 uint32 计算区间，避免 max_val=65535 时 uint16 溢出为 0
        // 导致取模除零
        const auto range = static_cast<std::uint32_t>(max_val) - min_val + 1;
        return static_cast<std::uint16_t>(min_val + (raw % range));
    }

    inline void pad_transport::rng_refill()
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, rng_key_.data());

        std::array<std::uint8_t, 8> counter_bytes{};
        auto ctr = rng_counter_;
        for (std::size_t i = 0; i < 8; ++i)
        {
            counter_bytes[i] = static_cast<std::uint8_t>(ctr & 0xFF);
            ctr >>= 8;
        }
        blake3_hasher_update(&hasher, counter_bytes.data(), 8);
        blake3_hasher_finalize(&hasher, rng_cache_.data(), 32);

        rng_cache_pos_ = 0;
        ++rng_counter_;
    }

    inline void pad_transport::rng_next_bytes(std::span<std::byte> out)
    {
        std::size_t offset = 0;
        while (offset < out.size())
        {
            if (rng_cache_pos_ >= 32)
            {
                rng_refill();
            }

            std::size_t chunk = 0;
            if (out.size() - offset < 32 - rng_cache_pos_)
            {
                chunk = out.size() - offset;
            }
            else
            {
                chunk = 32 - rng_cache_pos_;
            }
            std::memcpy(out.data() + offset, rng_cache_.data() + rng_cache_pos_, chunk);
            rng_cache_pos_ += chunk;
            offset += chunk;
        }
    }

    inline auto pad_transport::parse_targets(std::string_view spec, memory::resource_pointer mr)
        -> memory::vector<pad_target>
    {
        memory::vector<pad_target> targets(mr);

        std::size_t start = 0;
        while (start <= spec.size())
        {
            auto end = spec.find(',', start);
            if (end == std::string_view::npos)
            {
                end = spec.size();
            }

            const auto token = spec.substr(start, end - start);
            if (!token.empty())
            {
                pad_target t{};

                auto dash = token.find('-');
                if (dash != std::string_view::npos)
                {
                    auto min_str = token.substr(0, dash);
                    auto max_str = token.substr(dash + 1);
                    std::uint16_t mn = 0;
                    std::uint16_t mx = 0;
                    std::from_chars(min_str.data(), min_str.data() + min_str.size(), mn);
                    std::from_chars(max_str.data(), max_str.data() + max_str.size(), mx);
                    t.min_val = mn;
                    t.max_val = mx;
                }
                else
                {
                    std::uint16_t val = 0;
                    std::from_chars(token.data(), token.data() + token.size(), val);
                    t.min_val = val;
                    t.max_val = val;
                }

                targets.push_back(t);
            }

            start = end + 1;
        }

        return targets;
    }


} // namespace preview::transport
