/**
 * @file monitor.hpp
 * @brief 已弃用的协程日志系统
 * @details 基于 Boost.Asio 协程的日志实现，由于性能问题和资源开销较大，
 * 已被 spdlog 方案替代。保留作为协程 I/O 操作的参考实现。
 * @deprecated 已弃用，请使用 ngx::trace::spdlog 替代。
 * @warning 使用此模块可能导致性能下降和资源泄漏。
 */
#pragma once

#include <string>
#include <format>
#include <chrono>
#include <vector>
#include <memory>
#include <unordered_map>
#include <filesystem>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/stream_file.hpp>

/**
 * @namespace ngx::trace::deprecated
 * @brief 已弃用的日志监控命名空间
 * @details 包含 ForwardEngine 早期版本的日志监控实现，由于协程切换开销
 * 大于 I/O 阻塞开销，已被 spdlog 方案替代。
 * @deprecated 严禁在新代码中使用此命名空间。
 */
namespace ngx::trace::deprecated
{
    /**
     * @brief 容器类型概念约束
     * @details 要求容器类型支持 boost::asio::buffer 转换。
     */
    template <typename container_type>
    concept compatible = requires(const container_type &x) { boost::asio::buffer(x); };

    /**
     * @enum level
     * @brief 日志级别枚举
     * @details 定义日志记录的级别，从低到高依次为 debug、info、warn、error、fatal。
     * @note 日志级别按数值递增，数值越高级别越严重。
     */
    enum class level
    {
        debug, // 调试级别，用于开发调试
        info,  // 信息级别，记录正常运行状态
        warn,  // 警告级别，记录潜在问题
        error, // 错误级别，记录运行错误
        fatal, // 致命级别，记录不可恢复的错误
    };

    namespace asio = boost::asio;
    namespace fs = std::filesystem;

    /**
     * @class coroutine_log
     * @brief 协程日志类
     * @details 基于 Boost.Asio 协程的日志实现，支持文件输出和控制台输出。
     * 由于协程切换开销约 100-200ns 远高于日志格式化开销，已被 spdlog 替代。
     * @deprecated 已弃用，请使用 ngx::trace::spdlog 替代。
     * @warning 使用此类将导致性能下降和资源泄漏风险。
     */
    class coroutine_log
    {
        // 文件上下文结构，包含文件句柄和当前大小
        struct context
        {
            std::shared_ptr<asio::stream_file> handle;
            std::size_t current_size = 0;
        };

    public:
        coroutine_log() = default;

        /**
         * @brief 构造协程日志对象
         * @param executor I/O 执行器，用于协程调度和异步操作
         */
        explicit coroutine_log(const asio::any_io_executor &executor);

        /**
         * @brief 设置日志输出目录
         * @param directory_name 日志输出目录的路径
         * @return 协程等待对象
         */
        asio::awaitable<void> set_output_directory(const std::string &directory_name);

        /**
         * @brief 设置日志文件的最大大小
         * @param size 日志文件的最大大小，单位为字节
         * @return 协程等待对象
         * @details 超过该大小则创建新的日志文件，实现日志轮转。
         */
        asio::awaitable<void> set_max_file_size(std::size_t size);

        /**
         * @brief 设置时间偏移
         * @param offset 时间偏移量，默认为 0
         * @return 协程等待对象
         */
        asio::awaitable<void> set_time_offset(std::chrono::minutes offset);

        /**
         * @brief 设置输出到日志文件的级别阈值
         * @param threshold 日志级别阈值
         * @return 协程等待对象
         * @details 低于此阈值的日志将不会写入文件。
         */
        asio::awaitable<void> set_file_level_threshold(level threshold);

        /**
         * @brief 设置输出到控制台的级别阈值
         * @param threshold 日志级别阈值
         * @return 协程等待对象
         * @details 低于此阈值的日志将不会输出到控制台。
         */
        asio::awaitable<void> set_console_level_threshold(level threshold);

        /**
         * @brief 设置日志文件最大归档数量
         * @param count 最大归档数量
         * @return 协程等待对象
         * @details 超过该数量则删除最旧的日志文件，0 表示不限制。
         */
        asio::awaitable<void> set_max_archive_count(std::size_t count);

        /**
         * @brief 关闭指定文件句柄
         * @param path 文件路径
         * @return 协程等待对象
         */
        asio::awaitable<void> close_file(const std::string &path) const;

        /**
         * @brief 关闭所有已打开的文件句柄
         * @return 协程等待对象
         */
        asio::awaitable<void> shutdown() const;

        /**
         * @brief 将日志消息输出到文件
         * @tparam container 容器类型，需满足 compatible 概念
         * @param filename 日志文件名
         * @param data 日志消息数据
         * @return 写入的字节数
         * @details 如果文件不存在，会尝试创建目录并打开文件，支持自动文件轮转。
         */
        template <compatible container>
        auto file_write(const std::string &filename, const container &data) const
            -> asio::awaitable<std::size_t>
        {
            co_await asio::dispatch(serial_exec, asio::use_awaitable);

            fs::path target_path = root_directory / filename;
            if (fs::path(filename).is_absolute())
            {
                target_path = filename;
            }
            std::string key = target_path.string();

            auto it = file_map.find(key);
            if (it == file_map.end() || !it->second.handle || !it->second.handle->is_open())
            {
                if (!fs::exists(target_path.parent_path()))
                {
                    boost::system::error_code ec;
                    fs::create_directories(target_path.parent_path(), ec);
                }

                asio::stream_file fp(serial_exec, key,
                                     asio::file_base::write_only | asio::file_base::create | asio::file_base::append);

                if (!fp.is_open())
                {
                    if (boost::system::error_code ec; fs::exists(target_path, ec))
                    {
                        fs::remove(target_path, ec);
                        asio::stream_file fp_retry(serial_exec, key,
                                                   asio::file_base::write_only | asio::file_base::create | asio::file_base::append);
                        if (!fp_retry.is_open())
                            co_return 0;
                        fp = std::move(fp_retry);
                    }
                    else
                    {
                        co_return 0;
                    }
                }

                context ctx;
                ctx.handle = std::make_shared<asio::stream_file>(std::move(fp));
                boost::system::error_code ec;
                ctx.current_size = fs::file_size(target_path, ec);
                it = file_map.insert_or_assign(key, std::move(ctx)).first;
            }

            std::size_t write_size = asio::buffer_size(asio::buffer(data));
            if (it->second.current_size + write_size > max_file_size)
            {
                it->second.handle->close();

                auto now = std::chrono::system_clock::now();
                auto timestamp_str = std::format("{:%Y%m%d_%H%M%S}", now);
                fs::path parent = target_path.parent_path();
                std::string stem = target_path.stem().string();
                std::string ext = target_path.extension().string();
                fs::path archive_path = parent / (stem + "-" + timestamp_str + ext);

                boost::system::error_code ec;
                fs::rename(target_path, archive_path, ec);
                cleanup_old_archives(target_path);

                asio::stream_file new_fp(serial_exec, key,
                                         asio::file_base::write_only | asio::file_base::create | asio::file_base::truncate);

                if (!new_fp.is_open())
                {
                    file_map.erase(it);
                    co_return 0;
                }

                it->second.handle = std::make_shared<asio::stream_file>(std::move(new_fp));
                it->second.current_size = 0;
            }

            boost::system::error_code ec;
            std::size_t n = co_await asio::async_write(*it->second.handle, asio::buffer(data),
                                                       asio::redirect_error(asio::use_awaitable, ec));

            if (ec)
            {
                file_map.erase(it);
                co_return 0;
            }

            it->second.current_size += n;
            co_return n;
        }

        /**
         * @brief 将字符串向量写入文件
         * @param path 日志文件名
         * @param data 日志消息向量，每个元素为一条日志消息
         * @return 写入的总字节数
         * @details 会将所有消息合并为一个字符串后写入文件。
         */
        auto file_write(const std::string &path, const std::vector<std::string> &data) const
            -> asio::awaitable<std::size_t>;

        /**
         * @brief 将日志级别转换为字符串
         * @param log_level 日志级别枚举值
         * @return 日志级别的字符串表示
         */
        static std::string to_string(const level &log_level);

        /**
         * @brief 将日志消息输出到控制台
         * @param log_level 日志级别
         * @param data 日志消息
         * @return 写入的字节数
         * @details 如果日志级别低于 console_level_threshold，则不输出。
         */
        auto console_write(const level &log_level, const std::string &data) const
            -> asio::awaitable<std::size_t>;

        /**
         * @brief 将日志消息输出到控制台并添加换行符
         * @param log_level 日志级别
         * @param data 日志消息
         * @return 写入的字节数
         * @details 如果日志级别低于 console_level_threshold，则不输出。
         */
        auto console_write_line(const level &log_level, const std::string &data) const
            -> asio::awaitable<std::size_t>;

        /**
         * @brief 格式化写入日志消息到文件
         * @tparam Args 格式化参数类型
         * @param filename 日志文件名
         * @param log_level 日志级别
         * @param format 日志消息格式化字符串
         * @param args 格式化参数
         * @return 写入的字节数
         * @details 如果日志级别低于 file_level_threshold，则不输出。
         */
        template <typename... Args>
        auto file_write_fmt(const std::string &filename, level log_level, const std::string &format, Args &&...args) const
            -> asio::awaitable<std::size_t>
        {
            co_await asio::dispatch(serial_exec, asio::use_awaitable);
            if (static_cast<int>(log_level) < static_cast<int>(file_level_threshold))
            {
                co_return 0;
            }
            const std::string data = timestamp_string() + std::format("[{}] ", to_string(log_level)) + std::vformat(format, std::make_format_args(std::forward<Args>(args)...));
            co_return co_await file_write(filename, data);
        }

        /**
         * @brief 将日志消息写入文件并添加换行符
         * @param filename 日志文件名
         * @param data 日志消息
         * @return 写入的字节数
         * @details 会在日志消息前添加时间戳，末尾添加换行符。
         */
        asio::awaitable<std::size_t> file_write_line(const std::string &filename, const std::string &data) const;

        /**
         * @brief 格式化输出日志消息到控制台
         * @tparam Args 格式化参数类型
         * @param log_level 日志级别
         * @param format 日志消息格式化字符串
         * @param args 格式化参数
         * @return 写入的字节数
         * @details 如果日志级别低于 console_level_threshold，则不输出。
         */
        template <typename... Args>
        auto console_write_fmt(const level log_level, const std::string &format, Args &&...args) const
            -> asio::awaitable<std::size_t>
        {
            std::string data = std::vformat(format, std::make_format_args(args...));
            co_return co_await console_write(log_level, data);
        }

    private:
        asio::any_io_executor event_executor;
        asio::strand<asio::any_io_executor> serial_exec;
        mutable std::unordered_map<std::string, context> file_map;

        fs::path root_directory;
        std::chrono::minutes time_offset{0ULL};
        std::size_t max_archive_count = 0;
        level file_level_threshold = level::debug;
        level console_level_threshold = level::debug;
        std::size_t max_file_size = 10 * 1024 * 1024;

        /**
         * @brief 构建时间戳字符串
         * @return 时间戳字符串，格式为 "[YYYY-MM-DD HH:MM]"
         */
        std::string timestamp_string() const;

        /**
         * @brief 清理旧归档文件
         * @param target_path 目标文件路径
         * @details 根据 max_archive_count 配置删除超出数量的旧归档文件。
         */
        void cleanup_old_archives(const fs::path &target_path) const;
    };
}
