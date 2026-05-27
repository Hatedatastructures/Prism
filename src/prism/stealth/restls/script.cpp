#include <prism/stealth/restls/script.hpp>

#include <prism/stealth/restls/crypto.hpp>

#include <cstdlib>
#include <random>

namespace psm::stealth::restls
{

    namespace
    {
        // 解析单条 script 规则为 script_line
        auto parse_line(std::string_view token)
            -> script_line
        {
            script_line line;

            std::size_t pos = 0;

            // 解析 target_base（数字前缀）
            std::int16_t base = 0;
            while (pos < token.size() && token[pos] >= '0' && token[pos] <= '9')
            {
                base = base * 10 + (token[pos] - '0');
                ++pos;
            }
            line.target_base = base;

            // 解析随机修饰符
            if (pos < token.size())
            {
                const char modifier = token[pos];
                if (modifier == '?' || modifier == '~')
                {
                    ++pos;
                    std::int16_t range = 0;
                    while (pos < token.size() && token[pos] >= '0' && token[pos] <= '9')
                    {
                        range = range * 10 + (token[pos] - '0');
                        ++pos;
                    }

                    if (modifier == '?')
                    {
                        // 一次性随机：解析时 resolve
                        if (range > 0)
                            line.target_base = base + std::rand() % range;
                        else
                            line.target_base = base;
                        line.target_random = 0;
                        line.random_is_fixed = true;
                    }
                    else
                    {
                        // 动态随机：每次调用时计算
                        line.target_base = base;
                        line.target_random = range;
                        line.random_is_fixed = false;
                    }
                }
            }

            // 解析 <responseCount
            if (pos < token.size() && token[pos] == '<')
            {
                ++pos;
                std::uint8_t count = 0;
                while (pos < token.size() && token[pos] >= '0' && token[pos] <= '9')
                {
                    count = count * 10 + (token[pos] - '0');
                    ++pos;
                }
                line.cmd = command_type::response;
                line.response_count = count;
                if (count == 0)
                    line.response_count = 1;
            }

            return line;
        }

        // 分割逗号分隔的 script 字符串
        auto split_script(std::string_view script)
            -> memory::vector<std::string_view>
        {
            memory::vector<std::string_view> tokens;
            std::size_t start = 0;
            for (std::size_t i = 0; i <= script.size(); ++i)
            {
                if (i == script.size() || script[i] == ',')
                {
                    if (i > start)
                    {
                        tokens.emplace_back(script.data() + start, i - start);
                    }
                    start = i + 1;
                }
            }
            return tokens;
        }

        constexpr std::string_view default_script = "250?100<1,350~100<1,600~100,300~200,300~100";
    } // namespace

    // ── script_line ──

    auto script_line::target_length() const
        -> std::int16_t
    {
        if (random_is_fixed || target_random == 0)
        {
            return target_base;
        }
        return target_base + static_cast<std::int16_t>(std::rand() % target_random);
    }

    // ── script_engine ──

    script_engine::script_engine(const std::string_view script)
    {
        std::string_view effective = default_script;
        if (!script.empty())
            effective = script;
        // NOLINTNEXTLINE: script 为空时使用默认值，无需 PMR
        const auto tokens = split_script(effective);
        lines_.reserve(tokens.size());
        for (const auto &token : tokens)
        {
            lines_.push_back(parse_line(token));
        }
    }

    auto script_engine::allocate(const std::uint64_t counter, const std::size_t data_available) const
        -> allocation
    {
        allocation alloc;

        // 确定目标长度
        std::int16_t target = 0;
        bool blocking = false;
        if (counter < lines_.size())
        {
            const auto &line = lines_[counter];
            target = line.target_length();
            alloc.cmd = line.cmd;
            alloc.response_count = line.response_count;
            blocking = (line.cmd == command_type::response);
        }

        // 计算 data_len 和 padding
        if (data_available == 0)
        {
            // 无用户数据时发送随机 padding
            alloc.data_len = 0;
            alloc.padding_len = static_cast<std::int16_t>(19 + std::rand() % 100);
        }
        else
        {
            // target 包含 auth_header (12 bytes)
            const auto effective_target = target - static_cast<std::int16_t>(auth_hdrlen);
            const bool valid_counter = counter < lines_.size();
            const bool data_fits = data_available >= static_cast<std::size_t>(effective_target);
            if (valid_counter && effective_target > 0 && data_fits)
            {
                alloc.data_len = effective_target;
                alloc.padding_len = 0;
            }
            else if (valid_counter && effective_target > 0 && !data_fits)
            {
                alloc.data_len = static_cast<std::int16_t>(data_available);
                alloc.padding_len = effective_target - alloc.data_len;
            }
            else
            {
                // counter 超出 script 范围，无 padding
                alloc.data_len = static_cast<std::int16_t>(
                    std::min(data_available, static_cast<std::size_t>(max_plaintext - auth_hdrlen)));
                alloc.padding_len = 0;
            }
        }

        alloc.payload_len = static_cast<std::int16_t>(auth_hdrlen) + alloc.data_len + alloc.padding_len;
        alloc.write_blocking = blocking;

        return alloc;
    }
} // namespace psm::stealth::restls
