/**
 * @file pad.cpp
 * @brief Transport 层记录填充装饰器实现
 */

#include <prism/net/transport/pad.hpp>

#include <openssl/rand.h>

#include <charconv>
#include <cstring>

namespace psm::transport
{

    pad_transport::pad_transport(shared_transmission inner, const pad_config &cfg)
        : inner_(std::move(inner))
        , cfg_(cfg)
        , targets_(parse_targets(cfg.pad_targets, memory::current_resource()))
        , pad_buf_(16384 + 256, memory::current_resource())
    {
        /// 从 BoringSSL 获取 CSPRNG 种子
        RAND_bytes(rng_key_.data(), static_cast<int>(rng_key_.size()));
    }


    auto pad_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await inner_->async_read_some(buffer, ec);
    }


    auto pad_transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        /// 超过 stop_after 后直接透传,零开销
        if (write_count_ >= cfg_.stop_after || buffer.empty())
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

        co_await async_write(*inner_,
            std::span<const std::byte>(pad_buf_.data(), total), ec);

        ++write_count_;

        if (ec)
            co_return 0;
        co_return data_len;
    }


    void pad_transport::close()
    {
        inner_->close();
    }


    void pad_transport::cancel()
    {
        inner_->cancel();
    }


    auto pad_transport::compute_padding(std::size_t data_len) -> std::size_t
    {
        if (targets_.empty())
            return rng_next_u16(0, cfg_.max_pad_bytes);

        /// 选取当前 write_count 对应的 target(循环使用)
        const auto &target = targets_[write_count_ % targets_.size()];
        const auto target_len = rng_next_u16(target.min_val, target.max_val);

        if (data_len < target_len)
            return target_len - data_len;

        return rng_next_u16(0, cfg_.max_pad_bytes);
    }


    auto pad_transport::rng_next_u16(std::uint16_t min_val, std::uint16_t max_val) -> std::uint16_t
    {
        if (min_val >= max_val)
            return min_val;

        std::array<std::byte, 2> buf{};
        rng_next_bytes(buf);

        const auto raw = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[0])) << 8) |
            static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[1])));

        const auto range = static_cast<std::uint16_t>(max_val - min_val + 1);
        return static_cast<std::uint16_t>(min_val + (raw % range));
    }


    void pad_transport::rng_refill()
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


    void pad_transport::rng_next_bytes(std::span<std::byte> out)
    {
        std::size_t offset = 0;
        while (offset < out.size())
        {
            if (rng_cache_pos_ >= 32)
                rng_refill();

            const auto chunk = (out.size() - offset < 32 - rng_cache_pos_)
                ? (out.size() - offset) : (32 - rng_cache_pos_);
            std::memcpy(out.data() + offset, rng_cache_.data() + rng_cache_pos_, chunk);
            rng_cache_pos_ += chunk;
            offset += chunk;
        }
    }


    auto pad_transport::parse_targets(std::string_view spec, memory::resource_pointer mr)
        -> memory::vector<pad_target>
    {
        memory::vector<pad_target> targets(mr);

        std::size_t start = 0;
        while (start <= spec.size())
        {
            auto end = spec.find(',', start);
            if (end == std::string_view::npos)
                end = spec.size();

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

} // namespace psm::transport
