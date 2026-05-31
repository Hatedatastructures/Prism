#include <prism/stealth/stack/anytls/padding.hpp>

#include <openssl/evp.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <random>

namespace psm::stealth::anytls
{

    namespace
    {
        // 解析 "min-max" 为密码学安全随机整数 [min, max]
        auto random_in_range(std::int32_t lo, std::int32_t hi)
            -> std::int32_t
        {
            if (lo >= hi)
            {
                return lo;
            }
            thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<std::int32_t> dist(lo, hi);
            return dist(gen);
        }

        // 解析 "min-max" 字符串
        auto parse_range(std::string_view seg)
            -> std::pair<std::int32_t, std::int32_t>
        {
            auto dash = seg.find('-');
            if (dash == std::string_view::npos)
            {
                std::int32_t val = 0;
                std::string tmp(seg);
                val = static_cast<std::int32_t>(std::atoi(tmp.c_str()));
                return {val, val};
            }
            std::string lo_str(seg.substr(0, dash));
            std::string hi_str(seg.substr(dash + 1));
            return {static_cast<std::int32_t>(std::atoi(lo_str.c_str())), static_cast<std::int32_t>(std::atoi(hi_str.c_str()))};
        }

        // 计算 MD5 摘要，返回十六进制字符串
        auto compute_md5_hex(std::string_view data)
            -> memory::string
        {
            std::array<std::uint8_t, 16> digest{};
            std::uint32_t digest_len = 0;

            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data.size());
            EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
            EVP_MD_CTX_free(ctx);

            constexpr const char hex[] = "0123456789abcdef";
            memory::string result;
            result.reserve(32);
            for (std::size_t i = 0; i < digest_len; ++i)
            {
                result.push_back(hex[digest[i] >> 4]);
                result.push_back(hex[digest[i] & 0x0F]);
            }
            return result;
        }
    } // namespace

    padding_factory::padding_factory(const std::string_view raw_scheme)
        : raw_scheme_(raw_scheme.data(), raw_scheme.size())
    {
        if (raw_scheme.empty())
        {
            return;
        }

        // 计算 MD5
        md5 = compute_md5_hex(raw_scheme);

        // 按行解析
        std::size_t line_start = 0;
        for (std::size_t i = 0; i <= raw_scheme.size(); ++i)
        {
            if (i == raw_scheme.size() || raw_scheme[i] == '\n')
            {
                auto line = raw_scheme.substr(line_start, i - line_start);

                // 去除 \r
                if (!line.empty() && line.back() == '\r')
                {
                    line.remove_suffix(1);
                }

                if (!line.empty())
                {
                    // 解析 "stop=N" 或 "pktNum=segments"
                    auto eq = line.find('=');
                    if (eq != std::string_view::npos)
                    {
                        auto key = line.substr(0, eq);
                        auto val = line.substr(eq + 1);

                        if (key == "stop")
                        {
                            stop = static_cast<std::uint32_t>(std::atoi(std::string(val).c_str()));
                        }
                        else
                        {
                            // key 是包序号
                            std::int32_t pkt_num = static_cast<std::int32_t>(std::atoi(std::string(key).c_str()));
                            scheme_[pkt_num] = memory::string(val.data(), val.size());
                        }
                    }
                }

                line_start = i + 1;
            }
        }
    }

    auto padding_factory::generate_sizes(const std::uint32_t pkt) const
        -> memory::vector<std::int32_t>
    {
        memory::vector<std::int32_t> sizes(memory::current_resource());

        if (pkt >= static_cast<std::int32_t>(stop))
        {
            // 超出 stop 范围，不 padding
            sizes.push_back(checkmark);
            return sizes;
        }

        auto it = scheme_.find(static_cast<std::int32_t>(pkt));
        if (it == scheme_.end())
        {
            sizes.push_back(checkmark);
            return sizes;
        }

        // 解析 segments：逗号分隔的 "min-max" 或 "c"
        const auto &segments = it->second;
        std::size_t seg_start = 0;

        for (std::size_t i = 0; i <= segments.size(); ++i)
        {
            if (i == segments.size() || segments[i] == ',')
            {
                auto seg = std::string_view(segments.data() + seg_start, i - seg_start);

                if (seg == "c")
                {
                    sizes.push_back(checkmark);
                }
                else
                {
                    auto [lo, hi] = parse_range(seg);
                    sizes.push_back(random_in_range(lo, hi));
                }

                seg_start = i + 1;
            }
        }

        return sizes;
    }
} // namespace psm::stealth::anytls
