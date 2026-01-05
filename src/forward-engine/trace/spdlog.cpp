#include <forward-engine/trace/spdlog.hpp>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>
#include <mutex>
#include <vector>

namespace ngx::trace
{
    namespace
    {
        std::mutex trace_mutex;
        trace_config last_config{};
        std::shared_ptr<spdlog::logger> logsys;

        /**
         * @brief 构建日志文件路径
         * @param cfg 配置
         * @return 日志文件路径
         */
        [[nodiscard]] std::filesystem::path build_log_path(const trace_config &cfg)
        {
            if (cfg.path_name.empty())
            {
                return std::filesystem::path(cfg.file_name);
            }
            return cfg.path_name / cfg.file_name;
        }
    }

    std::shared_ptr<spdlog::logger> recorder() noexcept
    {
        std::scoped_lock lock(trace_mutex);
        return logsys;
    }

    void init(const trace_config &cfg)
    {
        std::scoped_lock lock(trace_mutex);

        last_config = cfg;

        if (!cfg.path_name.empty())
        {
            std::error_code ec;
            std::filesystem::create_directories(cfg.path_name, ec);
        }

        if (!spdlog::thread_pool())
        {
            spdlog::init_thread_pool(cfg.queue_size, cfg.thread_count);
        }

        const auto log_path = build_log_path(cfg);

        std::vector<spdlog::sink_ptr> sinks;
        sinks.reserve(cfg.enable_console ? 2U : 1U);

        sinks.emplace_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_path.string(), cfg.max_size, cfg.max_files, true));

        if (cfg.enable_console)
        {
            sinks.emplace_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        }

        // 创建异步 logger
        auto logger = std::make_shared<spdlog::async_logger>(
            cfg.trace_name,
            sinks.begin(),
            sinks.end(),
            spdlog::thread_pool(),
            spdlog::async_overflow_policy::overrun_oldest);

        logger->set_level(cfg.log_level);
        logger->set_pattern(cfg.pattern);

        spdlog::set_default_logger(logger);
        spdlog::set_level(cfg.log_level);
        logsys = std::move(logger);
    }

    void shutdown()
    {
        std::shared_ptr<spdlog::logger> logger;
        std::string trace_name;

        {
            std::scoped_lock lock(trace_mutex);
            logger = std::move(logsys);
            trace_name = last_config.trace_name;
            logsys.reset();
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
                spdlog::drop(trace_name);
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
