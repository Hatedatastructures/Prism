/**
 * @file SinkSet.hpp
 * @brief Preview Diagnose 的 spdlog sink 和 async logger owner。
 */
#pragma once

#include <spdlog/async.h>
#include <spdlog/details/log_msg.h>
#include <spdlog/details/thread_pool.h>
#include <spdlog/formatter.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/sink.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>

namespace Preview::Diagnose::Detail
{

    /**
     * @brief 在异步队列中提供写入顺序屏障的临时 sink。
     * @details barrier 到达时在 spdlog worker 上 flush 目标 sink，再通知控制线程；本 sink 不输出 barrier 文本。
     */
    class DrainBarrierSink final : public spdlog::sinks::sink
    {
    public:
        /**
         * @brief 绑定待 flush 的实际 sinks 和完成信号。
         * @param Targets barrier 到达时依次 flush 的 sinks。
         * @param Completion barrier flush 完成后写入结果的 promise。
         */
        DrainBarrierSink(std::vector<spdlog::sink_ptr> Targets,
                         std::shared_ptr<std::promise<bool>> Completion)
            : Targets_(std::move(Targets)), Completion_(std::move(Completion))
        {
        }

        /**
         * @brief 在 logger worker 处理到 barrier 时 flush 目标 sinks 并通知等待者。
         * @param Message barrier logger 投递的内部消息；正文不会写入实际日志文件。
         */
        auto log(const spdlog::details::log_msg &Message) -> void override
        {
            (void)Message;
            bool Succeeded = true;
            for (const auto &Target : Targets_)
            {
                try
                {
                    Target->flush();
                }
                catch (...)
                {
                    Succeeded = false;
                }
            }
            try
            {
                Completion_->set_value(Succeeded);
            }
            catch (...)
            {
            }
        }

        /** @brief barrier sink 不持有缓冲，因此无需额外 flush。 */
        auto flush() -> void override
        {
        }
        /** @brief barrier sink 不格式化输出，忽略 pattern 设置。 */
        auto set_pattern(const std::string &) -> void override
        {
        }
        /** @brief barrier sink 不格式化输出，忽略 formatter 设置。 */
        auto set_formatter(std::unique_ptr<spdlog::formatter>) -> void override
        {
        }

    private:
        std::vector<spdlog::sink_ptr> Targets_;          ///< barrier 到达时需要 flush 的实际输出 sinks。
        std::shared_ptr<std::promise<bool>> Completion_; ///< 将 flush 结果通知给控制线程等待者。
    };

    /**
     * @brief 创建并拥有 spdlog logger 使用的全部输出 sink。
     * @details 始终创建轮转文件 sink；配置启用控制台时再添加 stdout sink。logger 使用 BackendLifecycle 提供的独占 spdlog pool，
     *          队列满时采用 discard_new 策略。本类关闭 logger，pool 的 join 由 BackendLifecycle 执行。
     */
    class SinkSet final
    {
    public:
        /**
         * @brief 创建日志目录、处理旧格式文件并构造异步 logger。
         * @param Settings 已校验的 backend 设置。
         * @param Pool 由 BackendLifecycle 独占持有的 spdlog async pool。
         * @return 成功时返回 sink owner；失败时返回目录、thread pool、归档或文件打开错误。
         */
        [[nodiscard]] static auto Create(const BackendSettings &Settings,
                                         const std::shared_ptr<spdlog::details::thread_pool> &Pool)
            -> std::expected<std::shared_ptr<SinkSet>, BackendError>
        {
            std::error_code Error;
            std::filesystem::create_directories(Settings.Logging.Directory, Error);
            if (Error || !std::filesystem::is_directory(Settings.Logging.Directory, Error))
            {
                return std::unexpected(BackendError{BackendErrorCode::Directory,
                                                    Settings.Logging.Directory.string(),
                                                    "cannot create Diagnose log directory"});
            }
            if (!Pool)
            {
                return std::unexpected(BackendError{BackendErrorCode::WorkerStart,
                                                    Settings.Logging.Directory.string(),
                                                    "spdlog async thread pool is not available"});
            }

            const auto LogPath = Settings.Logging.Directory / Settings.Logging.FileName;
            auto Result = std::shared_ptr<SinkSet>(new SinkSet);
            if (!Result->ArchiveMismatchedFile(LogPath, Settings.Mode))
            {
                return std::unexpected(BackendError{BackendErrorCode::LegacyArchive, LogPath.string(),
                                                    "cannot archive a log file with another format"});
            }

            try
            {
                std::vector<spdlog::sink_ptr> Sinks;
                if (Settings.Logging.Console)
                {
                    Sinks.reserve(2U);
                }
                else
                {
                    Sinks.reserve(1U);
                }
                Sinks.emplace_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    LogPath.string(), Settings.Logging.RotateBytes, Settings.Logging.RotateFiles, false));
                if (Settings.Logging.Console)
                {
                    Sinks.emplace_back(std::make_shared<spdlog::sinks::stdout_sink_mt>());
                }
                Result->Sinks_ = Sinks;
                Result->Pool_ = Pool;
                Result->Logger_ =
                    std::make_shared<spdlog::async_logger>("PrismPreviewDiagnose", Sinks.begin(), Sinks.end(),
                                                           Pool, spdlog::async_overflow_policy::discard_new);
                Result->Logger_->set_level(spdlog::level::trace);
                Result->Logger_->flush_on(spdlog::level::warn);
                if (Settings.Mode == RenderMode::Structured)
                {
                    Result->Logger_->set_pattern("%v");
                }
                else
                {
                    Result->Logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%5t] [%l] %v");
                }
                Result->Logger_->set_error_handler(
                    [Raw = Result.get()](const std::string &)
                    { Raw->ErrorCount_.fetch_add(1U, std::memory_order_relaxed); });
            }
            catch (const std::exception &ErrorValue)
            {
                return std::unexpected(
                    BackendError{BackendErrorCode::FileOpen, LogPath.string(), ErrorValue.what()});
            }
            return Result;
        }

        /**
         * @brief 获取由本对象拥有的异步 logger。
         * @return 指向 shared_ptr 成员的只读引用；引用有效期不超过 SinkSet 对象。
         */
        [[nodiscard]] auto Logger() const noexcept -> const std::shared_ptr<spdlog::async_logger> &
        {
            return Logger_;
        }

        /**
         * @brief 返回 spdlog 错误回调记录的错误数。
         * @return 自创建 logger 以来捕获的 backend 错误次数。
         */
        [[nodiscard]] auto ErrorCount() const noexcept -> std::uint64_t
        {
            return ErrorCount_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 向异步 logger 提交 flush 请求。
         * @details 请求由 spdlog async pool 处理；本函数只提交请求，不等待 sink 完成 flush。
         */
        auto Flush() noexcept -> void
        {
            if (Logger_)
            {
                Logger_->flush();
            }
        }

        /**
         * @brief 在 spdlog worker 上排入 flush barrier，并在非 Asio 控制线程等待确认。
         * @param Deadline 最晚允许等待到的 steady_clock 时间点。
         * @param SubmissionGate 与普通日志入队共享的非阻塞门闩。
         * @return sink flush 成功返回 true；门闩忙或等待超时返回空值；sink flush 失败返回 false。
         * @note barrier 入队使用 spdlog block policy；该同步方法只能从非 Asio 控制线程调用，Timeout 仅限制入队后的确认等待。
         */
        [[nodiscard]] auto DrainOnControlThread(const std::chrono::steady_clock::time_point Deadline,
                                                std::atomic_flag &SubmissionGate) const noexcept
            -> std::optional<bool>
        {
            if (!Logger_ || !Pool_)
            {
                return true;
            }
            try
            {
                auto Completion = std::make_shared<std::promise<bool>>();
                auto Result = Completion->get_future();
                auto BarrierSinkValue = std::make_shared<DrainBarrierSink>(Sinks_, Completion);
                auto BarrierLogger =
                    std::make_shared<spdlog::async_logger>("PrismPreviewDiagnoseDrain", BarrierSinkValue,
                                                           Pool_, spdlog::async_overflow_policy::block);
                BarrierLogger->set_level(spdlog::level::trace);
                if (SubmissionGate.test_and_set(std::memory_order_acquire))
                {
                    return {};
                }
                struct GateRelease final
                {
                    std::atomic_flag &Gate;
                    bool Active{true};
                    auto Release() noexcept -> void
                    {
                        if (Active)
                        {
                            Gate.clear(std::memory_order_release);
                            Active = false;
                        }
                    }
                    ~GateRelease()
                    {
                        Release();
                    }
                } Release{SubmissionGate};
                BarrierLogger->info("drain barrier");
                Release.Release();
                if (Result.wait_until(Deadline) != std::future_status::ready)
                {
                    return {};
                }
                return Result.get();
            }
            catch (...)
            {
                return false;
            }
        }

        /**
         * @brief 提交 flush 请求并从 spdlog registry 移除 logger。
         * @details 此操作释放本对象持有的 logger 和 pool 引用；BackendLifecycle 保留 pool owner 到最终 join。
         */
        auto Shutdown() noexcept -> void
        {
            Flush();
            if (Logger_)
            {
                Logger_.reset();
            }
            Pool_.reset();
        }

        /**
         * @brief 在线程池 join 后同步 flush 实际输出 sinks。
         * @return 所有 sink flush 成功时返回 true；任一 sink 抛出异常时返回 false。
         * @note 只能在 spdlog worker 已停止后由控制线程调用，不能从协程或 I/O worker 调用。
         */
        [[nodiscard]] auto FlushSinksOnControlThread() noexcept -> bool
        {
            bool Succeeded = true;
            for (const auto &Sink : Sinks_)
            {
                try
                {
                    Sink->flush();
                }
                catch (...)
                {
                    ErrorCount_.fetch_add(1U, std::memory_order_relaxed);
                    Succeeded = false;
                }
            }
            return Succeeded;
        }

    private:
        /**
         * @brief 判断现有日志文件格式是否与当前输出模式兼容。
         * @param Path 当前日志文件路径。
         * @param Mode 当前渲染模式。
         * @return 文件不存在、为空或首个有效字符与模式匹配时返回 true；不匹配时尝试归档并返回结果。
         * @details 仅检查首个非空白字符，不解析整个文件；Human 模式预期以 '[' 开始，Structured 模式预期以 '{' 开始。
         * @note 若文件存在但无法读取首个有效字符，当前实现会保留原文件并继续创建 sink。
         */
        [[nodiscard]] auto ArchiveMismatchedFile(const std::filesystem::path &Path,
                                                 const RenderMode Mode) const -> bool
        {
            std::error_code Error;
            if (!std::filesystem::exists(Path, Error))
            {
                return !Error;
            }
            const auto Size = std::filesystem::file_size(Path, Error);
            if (Error || Size == 0U)
            {
                return !Error;
            }
            // 只按首个有效字符判断 human/JSON 格式；不解析旧日志全文，避免启动阶段无界 IO。
            std::ifstream Input(Path, std::ios::binary);
            char First = '\0';
            while (Input.get(First) && (First == '\r' || First == '\n' || First == ' ' || First == '\t'))
            {
            }
            char Expected = '[';
            if (Mode == RenderMode::Structured)
            {
                Expected = '{';
            }
            if (!Input || First == Expected)
            {
                return true;
            }
            Input.close();
            return Archive(Path);
        }

        /**
         * @brief 将格式不兼容的旧日志改名为带 .legacy 后缀的文件。
         * @param Path 要归档的日志文件路径。
         * @return 改名成功时返回 true；目标冲突检查或文件改名失败时返回 false。
         * @details 若目标名已存在，会依次尝试追加数字后缀，不覆盖已有文件。
         */
        [[nodiscard]] auto Archive(const std::filesystem::path &Path) const -> bool
        {
            std::error_code Error;
            const auto Base = std::filesystem::path(Path.string() + ".legacy");
            auto Destination = Base;
            for (std::uint32_t Index = 1U; std::filesystem::exists(Destination, Error); ++Index)
            {
                if (Error)
                {
                    return false;
                }
                Destination = std::filesystem::path(Base.string() + "." + std::to_string(Index));
                Error.clear();
            }
            std::filesystem::rename(Path, Destination, Error);
            return !Error;
        }

        std::shared_ptr<spdlog::async_logger> Logger_{};       ///< logger。
        std::shared_ptr<spdlog::details::thread_pool> Pool_{}; ///< spdlog pool。
        std::vector<spdlog::sink_ptr> Sinks_{};                ///< 按 logger 写入顺序保存实际输出 sink
        std::atomic<std::uint64_t> ErrorCount_{0U};            ///< spdlog 错误回调观察到的错误数。
    };

} // namespace Preview::Diagnose::Detail
