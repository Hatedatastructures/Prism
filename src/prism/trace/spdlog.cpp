#include <prism/trace/spdlog.hpp>

#include <spdlog/async.h>
#include <spdlog/mdc.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <vector>


namespace psm::trace
{

    namespace
    {
        std::shared_mutex trace_mutex;
        config last_config{};
        std::shared_ptr<spdlog::logger> shared_system_logger;
        std::atomic<spdlog::logger *> atomic_logger_ptr{nullptr};

        [[nodiscard]] auto parse_spdlog_level(const std::string_view level_str) noexcept
            -> spdlog::level::level_enum
        {
            std::string normalized;
            normalized.reserve(level_str.size());
            for (const char ch : level_str)
            {
                normalized.push_back(static_cast<char>(std::tolower(static_cast<std::uint8_t>(ch))));
            }

            if (normalized == "trace")
            {
                return spdlog::level::trace;
            }
            if (normalized == "debug")
            {
                return spdlog::level::debug;
            }
            if (normalized == "info")
            {
                return spdlog::level::info;
            }
            if (normalized == "warn" || normalized == "warning")
            {
                return spdlog::level::warn;
            }
            if (normalized == "error" || normalized == "err")
            {
                return spdlog::level::err;
            }
            if (normalized == "critical" || normalized == "fatal")
            {
                return spdlog::level::critical;
            }
            if (normalized == "off")
            {
                return spdlog::level::off;
            }

            return spdlog::level::info;
        }

        [[nodiscard]] auto build_log_path(const config &cfg)
            -> std::filesystem::path
        {
            if (cfg.path_name.empty())
            {
                return std::filesystem::path(cfg.file_name.c_str());
            }
            return std::filesystem::path(cfg.path_name.c_str()) / cfg.file_name.c_str();
        }
    } // anonymous namespace

    void mdc_set(const std::string &key, const std::string &value)
    {
        spdlog::mdc::put(key, value);
    }

    void mdc_remove(const std::string &key)
    {
        spdlog::mdc::remove(key);
    }

    void mdc_clear()
    {
        spdlog::mdc::clear();
    }

    auto build_mdc_prefix() -> std::string
    {
        const auto &mdc_map = spdlog::mdc::get_context();
        if (mdc_map.empty())
        {
            return {};
        }
        std::string prefix;
        for (const auto &[key, value] : mdc_map)
        {
            prefix.push_back('[');
            prefix.append(key);
            prefix.push_back('=');
            prefix.append(value);
            prefix.push_back(']');
        }
        prefix.push_back(' ');
        return prefix;
    }

    auto recorder() noexcept
        -> std::shared_ptr<spdlog::logger>
    {
        // 使用 atomic load 替代 shared_mutex，减少热路径锁开销
        // logger 指针仅在 init/shutdown 时变更（极少操作）
        auto *ptr = atomic_logger_ptr.load(std::memory_order_acquire);
        if (!ptr)
        {
            return nullptr;
        }
        // 通过 spdlog::default_logger_raw 获取 managed shared_ptr
        return spdlog::default_logger();
    }

    void init(const config &cfg)
    {
        std::unique_lock lock(trace_mutex);

        last_config = cfg;

        if (cfg.enable_file && !cfg.path_name.empty())
        {
            std::error_code ec;
            std::filesystem::create_directories(std::filesystem::path(cfg.path_name.c_str()), ec);
        }

        if (!spdlog::thread_pool())
        {
            spdlog::init_thread_pool(cfg.queue_size, cfg.thread_count);
        }

        config effective_cfg = cfg;
        if (effective_cfg.enable_file && effective_cfg.file_name.empty())
        {
            if (effective_cfg.trace_name.empty())
            {
                effective_cfg.file_name = "forward_engine.log";
            }
            else
            {
                effective_cfg.file_name = effective_cfg.trace_name + ".log";
            }
        }

        const auto log_path = build_log_path(effective_cfg);

        std::vector<spdlog::sink_ptr> sinks;
        std::size_t sink_count = 0U;
        if (effective_cfg.enable_file)
        {
            sink_count += 1U;
        }
        if (effective_cfg.enable_console)
        {
            sink_count += 1U;
        }
        sinks.reserve(sink_count);

        if (effective_cfg.enable_file)
        {
            sinks.emplace_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_path.string(),
                static_cast<std::size_t>(effective_cfg.max_size),
                static_cast<std::size_t>(effective_cfg.max_files),
                true));
        }

        if (effective_cfg.enable_console)
        {
            sinks.emplace_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        }

        if (sinks.empty())
        {
            sinks.emplace_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        }

        // 创建异步 logger
        std::string logger_name;
        if (effective_cfg.trace_name.empty())
        {
            logger_name = "forward_engine";
        }
        else
        {
            logger_name = std::string(effective_cfg.trace_name.c_str());
        }
        auto logger = std::make_shared<spdlog::async_logger>(
            logger_name,
            sinks.begin(),
            sinks.end(),
            spdlog::thread_pool(),
            spdlog::async_overflow_policy::overrun_oldest);

        const auto log_level = parse_spdlog_level({effective_cfg.log_level.data(), effective_cfg.log_level.size()});
        logger->set_level(log_level);
        // 关键：异步 logger 必须显式 flush_on，否则 buffer 不会自动刷盘，
        // taskkill /F 或异常终止时会丢失所有日志
        logger->flush_on(spdlog::level::info);
        logger->set_pattern(std::string(effective_cfg.pattern.c_str()));

        spdlog::set_default_logger(logger);
        spdlog::set_level(log_level);
        shared_system_logger = std::move(logger);
        atomic_logger_ptr.store(shared_system_logger.get(), std::memory_order_release);
    }

    void shutdown()
    {
        std::shared_ptr<spdlog::logger> logger;
        memory::string trace_name;

        {
            std::unique_lock lock(trace_mutex);
            atomic_logger_ptr.store(nullptr, std::memory_order_release);
            logger = std::move(shared_system_logger);
            trace_name = last_config.trace_name;
            shared_system_logger.reset();
        }

        if (logger)
        {
            try
            {
                logger->flush();
            }
            catch (...)
            {
            }
        }

        try
        {
            if (!trace_name.empty())
            {
                spdlog::drop(std::string(trace_name.c_str()));
            }
        }
        catch (...)
        {
        }

        try
        {
            spdlog::shutdown();
        }
        catch (...)
        {
        }
    }
}
