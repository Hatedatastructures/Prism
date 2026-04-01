#include <algorithm>
#include <cctype>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include <prism/trace/spdlog.hpp>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>


namespace psm::trace
{
    namespace
    {
        std::shared_mutex trace_mutex;
        config last_config{};
        std::shared_ptr<spdlog::logger> shared_system_logger;

        [[nodiscard]] auto parse_spdlog_level(const std::string_view level_str) noexcept
            -> spdlog::level::level_enum
        {
            std::string normalized;
            normalized.reserve(level_str.size());
            for (const char ch : level_str)
            {
                normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
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
    }

    auto recorder() noexcept
        -> std::shared_ptr<spdlog::logger>
    {
        std::shared_lock lock(trace_mutex);
        return shared_system_logger;
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
            effective_cfg.file_name = effective_cfg.trace_name.empty() ? "forward_engine.log" : (effective_cfg.trace_name + ".log");
        }

        const auto log_path = build_log_path(effective_cfg);

        std::vector<spdlog::sink_ptr> sinks;
        sinks.reserve((effective_cfg.enable_file ? 1U : 0U) + (effective_cfg.enable_console ? 1U : 0U));

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
        const std::string logger_name = effective_cfg.trace_name.empty() ? "forward_engine" : std::string(effective_cfg.trace_name.c_str());
        auto logger = std::make_shared<spdlog::async_logger>(
            logger_name,
            sinks.begin(),
            sinks.end(),
            spdlog::thread_pool(),
            spdlog::async_overflow_policy::overrun_oldest);

        const auto log_level = parse_spdlog_level({effective_cfg.log_level.data(), effective_cfg.log_level.size()});
        logger->set_level(log_level);
        logger->set_pattern(std::string(effective_cfg.pattern.c_str()));

        spdlog::set_default_logger(logger);
        spdlog::set_level(log_level);
        shared_system_logger = std::move(logger);
    }

    void shutdown()
    {
        std::shared_ptr<spdlog::logger> logger;
        memory::string trace_name;

        {
            std::unique_lock lock(trace_mutex);
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
