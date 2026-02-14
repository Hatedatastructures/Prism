/**
 * @file monitor.hpp
 * @brief 已弃用的协程日志系统
 * @details 包含一个基于 `Boost.Asio` 协程的日志实现，但由于性能问题和资源开销较大，现已弃用。
 *
 * 弃用原因：
 * - 性能不足：基于协程的同步 `I/O` 操作无法达到高性能日志记录需求；
 * - 资源开销：每个日志操作都涉及协程切换和上下文保存，开销较大；
 * - 复杂度高：协程日志实现复杂，维护成本高，且容易引入 `bug`；
 * - 功能有限：缺乏 `spdlog` 丰富的特性，如异步缓冲、多后端支持、格式定制等。
 *
 * 替代方案：
 * - 主要替代：`ngx::trace::spdlog` - 基于 `spdlog` 的高性能异步日志系统；
 * - 配置参考：`ngx::trace::config` - 日志系统配置结构；
 * - 迁移指南：参见 `ngx::trace::spdlog` 文档和示例。
 *
 * 历史背景：
 * 该模块是 `ForwardEngine` 早期版本中的日志实现，尝试利用协程实现"零阻塞"日志记录。
 * 然而在实际性能测试中发现，协程切换开销超过了 `I/O` 阻塞的开销，且实现复杂度高。
 * 最终决定采用业界标准的 `spdlog` 库作为日志解决方案。
 *
 * 保留目的：
 * - 参考实现：作为协程 `I/O` 操作的参考实现；
 * - 历史记录：保留项目演进的历史记录；
 * - 技术研究：供研究协程日志实现的技术人员参考。
 *
 * 警告：
 * @warning 该模块已弃用，不应在新代码中使用！
 * @warning 使用此模块可能导致性能下降和资源泄漏。
 * @warning 未来版本可能完全移除该模块。
 *
@see ngx::trace::config 日志配置
 *
 *
 * @deprecated 已弃用，请使用 `ngx::trace::spdlog` 替代。
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
 * @details 该命名空间包含 `ForwardEngine` 早期版本的日志监控实现，现已弃用。
 *
 * 包含组件：
 * - 协程日志：`coroutine_log` - 基于 `Boost.Asio` 协程的日志记录器；
 * - 日志级别：`level` - 日志级别枚举（`debug`、`info`、`warn`、`error`、`fatal`）；
 * - 概念约束：`compatible` - 容器类型概念，要求支持 `boost::asio::buffer` 转换。
 *
 * 设计缺陷：
 * - 性能问题：协程切换开销大于 `I/O` 阻塞开销，无法满足高性能需求；
 * - 资源管理：文件句柄管理复杂，容易导致资源泄漏；
 * - 线程模型：协程与线程模型耦合紧密，难以扩展；
 * - 功能缺失：缺乏异步缓冲、日志轮转、多后端等现代日志库特性。
 *
 * 迁移建议：
 * 1. 将所有对 `ngx::trace::deprecated` 的引用替换为 `ngx::trace::spdlog`；
 * 2. 将协程 `awaitable` 日志调用替换为同步日志接口；
 * 3. 使用 `ngx::trace::config` 配置新的日志系统；
 * 4. 删除对 `monitor.hpp` 的包含，改为包含 `spdlog.hpp`。
 *
 * 技术债务：
 * 该命名空间是项目演进过程中产生的技术债务，保留供参考和学习。
 * 新代码严禁使用该命名空间中的任何组件。
 *
 * @deprecated 已弃用，请使用 `ngx::trace::spdlog` 替代。
 * @warning 严禁在新代码中使用此命名空间！
 * ngx::trace::spdlog
 * ngx::trace::config
 */
namespace ngx::trace::deprecated
{
    template <typename container_type>
    concept compatible = requires(const container_type &x) { boost::asio::buffer(x); };

    /**
     * @brief 日志级别
     * @details 日志级别从低到高分别为 debug, info, warn, error, fatal。
     */
    enum class level
    {
        debug, // 调试
        info,  // 信息
        warn,  // 警告
        error, // 错误
        fatal, // 致命
    };

    namespace asio = boost::asio;
    namespace fs = std::filesystem;

    /**
     * @class coroutine_log
     * @brief 协程日志类（已弃用）
     * @details 基于 `Boost.Asio` 协程的日志实现，支持文件输出和控制台输出。
     * 该类是 `ForwardEngine` 早期日志系统的核心组件，由于性能问题和设计缺陷已被弃用。
     *
     * 设计原理：
     * - 协程 `I/O`：使用 `Boost.Asio` 协程实现异步文件 `I/O`，避免阻塞业务线程；
     * - 文件轮转：支持基于文件大小的自动轮转和归档管理；
     * - 级别过滤：支持文件和控住台输出的独立级别阈值；
     * - 线程安全：通过 `asio::strand` 保证线程安全，但引入了额外开销。
     *
     * 主要缺陷：
     * 1. 性能瓶颈：协程切换开销（约 `100-200ns`）远高于日志格式化开销；
     * 2. 内存开销：每个文件句柄使用 `shared_ptr` 管理，增加了内存和原子操作开销；
     * 3. 复杂度高：文件轮转、归档清理、错误处理逻辑复杂，容易出错；
     * 4. 扩展性差：难以添加新的日志后端（如网络、数据库、`syslog`）。
     *
     * 替代方案：
     * ```
     * // 弃用方式
     * ngx::trace::deprecated::coroutine_log logger(executor);
     * co_await logger.file_write_fmt("app.log", level::info, "User {} logged in", user_id);
     *
     * // 推荐方式（使用 spdlog）
     * #include <forward-engine/trace/spdlog.hpp>
     * ngx::trace::spdlog::info("User {} logged in", user_id);
     *
     *
     * 技术债务：
     * - 保留作为协程 `I/O` 操作的参考实现；
     * - 展示如何结合 `Boost.Asio` 协程与文件操作；
     * - 作为性能优化的反面教材。
     *
     * @deprecated 已弃用，请使用 `ngx::trace::spdlog` 替代。
     * @warning 使用此类将导致性能下降和资源泄漏风险。
     * @warning 未来版本可能完全移除此类，请勿依赖其接口稳定性。
     *
     */
    class coroutine_log
    {
        struct context
        {
            std::shared_ptr<asio::stream_file> handle;
            std::size_t current_size = 0;
        };

    public:
        coroutine_log() = default;
        explicit coroutine_log(const asio::any_io_executor &executor);

        /**
         * @brief 设置日志输出目录
         * @param directory_name 日志输出目录的路径
         */
        asio::awaitable<void> set_output_directory(const std::string &directory_name);

        /**
         * @brief 设置日志文件的最大大小
         * @details 超过该大小则创建新的日志文件。
         * @param size 日志文件的最大大小，单位为字节
         */
        asio::awaitable<void> set_max_file_size(std::size_t size);

        /**
         * @brief 设置时间偏移
         * @details 用于日志中的时间戳计算。
         * @param offset 时间偏移量，默认 +8 小时
         */
        asio::awaitable<void> set_time_offset(std::chrono::minutes offset);

        /**
         * @brief 设置输出到日志文件的级别阈值
         * @param threshold 日志级别阈值
         */
        asio::awaitable<void> set_file_level_threshold(level threshold);

        /**
         * @brief 设置输出到控制台日志的级别阈值
         * @param threshold 日志级别阈值
         */
        asio::awaitable<void> set_console_level_threshold(level threshold);

        /**
         * @brief 设置日志文件最大归档数量
         * @details 超过该数量则删除最旧的日志文件。
         * @param count 最大归档数量
         */
        asio::awaitable<void> set_max_archive_count(std::size_t count);

        asio::awaitable<void> close_file(const std::string &path) const;

        /**
         * @brief 关闭所有已打开的文件句柄
         */
        asio::awaitable<void> shutdown() const;

        /**
         * @brief 将日志消息输出到文件
         * @param filename 日志文件名
         * @param data 日志消息
         * @return std::size_t 写入的字节数
         * @note 如果文件不存在，会尝试创建目录并打开文件。
         */
        template <compatible container>
        auto file_write(const std::string &filename, const container &data) const
            -> asio::awaitable<std::size_t>
        {
            // Implementation...
            co_await asio::dispatch(serial_exec, asio::use_awaitable);

            // 1. 获取文件路径
            fs::path target_path = root_directory / filename;
            if (fs::path(filename).is_absolute())
            { // 如果路径是绝对路径，则直接使用，避免路径拼接错误
                target_path = filename;
            }
            std::string key = target_path.string();

            // 2. 获取或创建文件上下文
            auto it = file_map.find(key);
            if (it == file_map.end() || !it->second.handle || !it->second.handle->is_open())
            {
                if (!fs::exists(target_path.parent_path()))
                { // 如果目录不存在，尝试创建
                    boost::system::error_code ec;
                    fs::create_directories(target_path.parent_path(), ec);
                }

                asio::stream_file fp(serial_exec, key,
                                     asio::file_base::write_only | asio::file_base::create | asio::file_base::append);

                if (!fp.is_open())
                { // 尝试自愈：如果文件存在但无法打开，可能是损坏，尝试删除并重新创建
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

                context ctx; // 初始化上下文并获取当前文件大小
                ctx.handle = std::make_shared<asio::stream_file>(std::move(fp));
                boost::system::error_code ec;
                ctx.current_size = fs::file_size(target_path, ec);
                it = file_map.insert_or_assign(key, std::move(ctx)).first;
            }

            // 3. 滚动检查
            std::size_t write_size = asio::buffer_size(asio::buffer(data));
            if (it->second.current_size + write_size > max_file_size)
            {
                // 关闭当前句柄
                it->second.handle->close();

                // 生成归档文件名（保持扩展名在末尾）
                auto now = std::chrono::system_clock::now();
                auto timestamp_str = std::format("{:%Y%m%d_%H%M%S}", now);
                fs::path parent = target_path.parent_path();
                std::string stem = target_path.stem().string();
                std::string ext = target_path.extension().string();
                fs::path archive_path = parent / (stem + "-" + timestamp_str + ext);

                boost::system::error_code ec;
                fs::rename(target_path, archive_path, ec);
                // 归档保留策略清理
                cleanup_old_archives(target_path);

                // 重新创建新文件
                asio::stream_file new_fp(serial_exec, key,
                                         asio::file_base::write_only | asio::file_base::create | asio::file_base::truncate); // truncate 清空

                if (!new_fp.is_open())
                { // 滚动失败，移除映射
                    file_map.erase(it);
                    co_return 0;
                }

                it->second.handle = std::make_shared<asio::stream_file>(std::move(new_fp));
                it->second.current_size = 0;
            }

            // 4. 执行写入
            boost::system::error_code ec;
            std::size_t n = co_await asio::async_write(*it->second.handle, asio::buffer(data),
                                                       asio::redirect_error(asio::use_awaitable, ec));

            if (ec)
            {
                file_map.erase(it); // 写入失败，移除映射
                co_return 0;
            }

            it->second.current_size += n;
            co_return n;
        }

        /**
         * @brief 针对 vector<string> 的特化：先合并再调用通用 file_write (避免递归循环)
         * @param path 日志文件名
         * @param data 日志消息向量，每个元素为一条日志消息
         * @return std::size_t 写入的总字节数
         * @note 会将所有消息合并为一个字符串后写入文件。
         */
        auto file_write(const std::string &path, const std::vector<std::string> &data) const
            -> asio::awaitable<std::size_t>;

        static std::string to_string(const level &log_level);

        /**
         * @brief 将日志消息输出到控制台
         * @param log_level 日志级别
         * @param data 日志消息
         * @return std::size_t 写入的字节数
         * @note 如果日志级别低于 console_level_threshold，则不输出。
         */
        auto console_write(const level &log_level, const std::string &data) const
            -> asio::awaitable<std::size_t>;

        /**
         * @brief 将日志消息输出到控制台，并在末尾添加换行符
         * @param log_level 日志级别
         * @param data 日志消息
         * @return std::size_t 写入的字节数
         * @note 如果日志级别低于 console_level_threshold，则不输出。
         */
        auto console_write_line(const level &log_level, const std::string &data) const
            -> asio::awaitable<std::size_t>;

        /**
         * @brief 写入日志消息到文件
         * @param filename 日志文件名
         * @param log_level 日志级别
         * @param format 日志消息格式化字符串
         * @param args 日志消息参数
         * @return std::size_t 写入的字节数
         * @note 如果日志级别低于 file_level_threshold，则不输出。
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
         * @brief 写入日志消息到文件，并在末尾添加换行符
         * @param filename 日志文件名
         * @param data 日志消息
         * @return std::size_t 写入的字节数
         * @note 会在日志消息前添加时间戳。
         */
        asio::awaitable<std::size_t> file_write_line(const std::string &filename, const std::string &data) const;

        /**
         * @brief 将日志消息输出到控制台
         * @param log_level 日志级别
         * @param format 日志消息格式化字符串
         * @param args 日志消息参数
         * @return std::size_t 写入的字节数
         * @note 如果日志级别低于 console_level_threshold，则不输出。
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

        // 配置项
        fs::path root_directory;
        std::chrono::minutes time_offset{0ULL};
        std::size_t max_archive_count = 0; // 0 表示不限制归档个数
        level file_level_threshold = level::debug;
        level console_level_threshold = level::debug;
        std::size_t max_file_size = 10 * 1024 * 1024; // 10MB

        /**
         * @brief 构建时间戳字符串（使用实例级时间偏移）
         * @return std::string 时间戳字符串，格式为 "[YYYY-MM-DD HH:MM]"
         */
        std::string timestamp_string() const;

        /**
         * @brief 清理旧归档文件
         * @param target_path 目标文件路径
         */
        void cleanup_old_archives(const fs::path &target_path) const;
    };
}
