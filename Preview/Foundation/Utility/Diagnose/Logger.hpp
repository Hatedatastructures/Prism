/**
 * @file Logger.hpp
 * @brief Preview owner-held、非阻塞日志提交器。
 * @details 数据面只向有界队列投递值记录；文件、控制台、轮转和 flush 均由 owner 线程执行。
 */

#pragma once

#include <Preview/Statistics/Redaction.hpp>
#include <Preview/Statistics/Trace.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstdint>
#include <deque>
#include <expected>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <ctime>
#include <unordered_set>
#include <utility>

namespace Preview::Diagnose
{

    /** @brief 日志严重级别，值顺序用于阈值比较。 */
    enum class LogLevel : std::uint8_t
    {
        Trace,
        Debug,
        Info,
        Access,
        Warn,
        Error,
        Critical,
        Off,
    };

    [[nodiscard]] inline auto ParseLogLevel(const std::string_view Value) noexcept
        -> std::optional<LogLevel>
    {
        if (Value == "Trace") return LogLevel::Trace;
        if (Value == "Debug") return LogLevel::Debug;
        if (Value == "Info") return LogLevel::Info;
        if (Value == "Access") return LogLevel::Access;
        if (Value == "Warn") return LogLevel::Warn;
        if (Value == "Error") return LogLevel::Error;
        if (Value == "Critical") return LogLevel::Critical;
        if (Value == "Off") return LogLevel::Off;
        return std::nullopt;
    }

    [[nodiscard]] inline auto LogLevelName(const LogLevel Value) noexcept -> std::string_view
    {
        switch (Value)
        {
        case LogLevel::Trace: return "Trace";
        case LogLevel::Debug: return "Debug";
        case LogLevel::Info: return "Info";
        case LogLevel::Access: return "Access";
        case LogLevel::Warn: return "Warn";
        case LogLevel::Error: return "Error";
        case LogLevel::Critical: return "Critical";
        case LogLevel::Off: return "Off";
        }
        return "Off";
    }

    /** @brief logger 创建失败分类。 */
    enum class LoggerErrorCode : std::uint8_t
    {
        InvalidOptions,
        Directory,
        FileOpen,
        LegacyArchive,
    };

    struct LoggerError final
    {
        LoggerErrorCode Code{LoggerErrorCode::InvalidOptions};
        std::filesystem::path Path;
        std::string Message;
    };

    /** @brief 非阻塞日志投递结果。 */
    enum class EnqueueStatus : std::uint8_t
    {
        Accepted,
        Filtered,
        Dropped,
        Stopped,
    };

    /** @brief logger 启动参数；字段与 Preview Logging 契约保持值语义一致。 */
    struct LoggerOptions final
    {
        LogLevel Level{LogLevel::Info};
        std::filesystem::path Directory{"logs"};
        std::string FileName{"preview.log"};
        bool Console{false};
        std::uint64_t RotateBytes{64ULL * 1024ULL * 1024ULL};
        std::uint32_t RotateFiles{8};
        std::uint32_t FlushIntervalMs{250};
        std::size_t QueueCapacity{4096};
    };

    /**
     * @class Logger
     * @brief 由应用 owner 持有的异步日志记录器。
     * @details TryWrite 不等待生产者锁；竞争、满队列和分配失败均丢弃并计数。
     */
    class Logger final
    {
    public:
        using Owner = std::shared_ptr<Logger>;

        [[nodiscard]] static auto Create(LoggerOptions Options)
            -> std::expected<Owner, LoggerError>
        {
            if (!IsKnownLevel(Options.Level) || Options.Directory.empty() ||
                !IsSafeFileName(Options.FileName) || Options.RotateBytes < MinRotateBytes ||
                Options.RotateBytes > MaxRotateBytes || Options.RotateFiles == 0U ||
                Options.RotateFiles > MaxRotateFiles || Options.FlushIntervalMs == 0U ||
                Options.FlushIntervalMs > MaxFlushIntervalMs || Options.QueueCapacity == 0U)
            {
                return std::unexpected(LoggerError{LoggerErrorCode::InvalidOptions,
                                                   Options.Directory,
                                                   "invalid Preview logger options"});
            }

            std::error_code Error;
            std::filesystem::create_directories(Options.Directory, Error);
            if (Error || !std::filesystem::is_directory(Options.Directory, Error))
            {
                return std::unexpected(LoggerError{LoggerErrorCode::Directory,
                                                   Options.Directory,
                                                   "cannot create Preview log directory"});
            }

            const auto Path = Options.Directory / Options.FileName;
            std::error_code FileError;
            if (std::filesystem::exists(Path, FileError) && !FileError)
            {
                const auto ExistingSize = std::filesystem::file_size(Path, FileError);
                if (!FileError && ExistingSize != 0U && !HasCurrentHeader(Path))
                {
                    if (!ArchiveLegacy(Path))
                    {
                        return std::unexpected(LoggerError{LoggerErrorCode::LegacyArchive,
                                                           Path,
                                                           "cannot archive legacy Preview log file"});
                    }
                }
            }

            std::ofstream File(Path, std::ios::binary | std::ios::app);
            if (!File.is_open())
            {
                return std::unexpected(LoggerError{LoggerErrorCode::FileOpen,
                                                   Path,
                                                   "cannot open Preview log file"});
            }

            std::uint64_t ExistingBytes = 0;
            Error.clear();
            if (const auto Size = std::filesystem::file_size(Path, Error); !Error)
            {
                ExistingBytes = Size;
            }
            if (ExistingBytes == 0U)
            {
                const auto Header = FormatHeader();
                File.write(Header.data(), static_cast<std::streamsize>(Header.size()));
                if (!File)
                {
                    return std::unexpected(LoggerError{LoggerErrorCode::FileOpen,
                                                       Path,
                                                       "cannot initialize Preview log file"});
                }
                ExistingBytes = static_cast<std::uint64_t>(Header.size());
            }
            return Owner(new Logger(std::move(Options), std::move(File), ExistingBytes));
        }

        ~Logger() noexcept
        {
            Stop();
        }

        Logger(const Logger &) = delete;
        auto operator=(const Logger &) -> Logger & = delete;
        Logger(Logger &&) = delete;
        auto operator=(Logger &&) -> Logger & = delete;

        /**
         * @brief 尝试提交一条值记录。
         * @details 不执行文件 I/O，不等待互斥量；返回 Dropped 时调用方继续数据面流程。
         */
        [[nodiscard]] auto TryWrite(
            const LogLevel Level,
            const std::string_view Message,
            Preview::Statistics::TraceSnapshot Snapshot = {}) noexcept -> EnqueueStatus
        {
            if (!ShouldWrite(Level))
            {
                return EnqueueStatus::Filtered;
            }

            try
            {
                Record Entry;
                Entry.Level = Level;
                Entry.Timestamp = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());
                Entry.Trace = std::move(Snapshot);
                Entry.Event = ExtractEvent(Message);
                Entry.Message = Preview::Statistics::RedactSensitiveText(Message);

                std::unique_lock Lock(Mutex_, std::try_to_lock);
                if (!Lock.owns_lock())
                {
                    return Drop();
                }
                if (Stopping_)
                {
                    return EnqueueStatus::Stopped;
                }
                if (Queue_.size() >= Options_.QueueCapacity)
                {
                    return Drop();
                }
                const bool AccessClose = Level == LogLevel::Access &&
                                         Entry.Event == "session_closed" &&
                                         (Entry.Trace.Session.has_value() ||
                                          Entry.Trace.Correlation.has_value());
                const auto AccessCloseKeyValue = AccessClose
                                                     ? std::optional<AccessCloseKey>{
                                                           MakeAccessCloseKey(Entry.Trace)}
                                                     : std::nullopt;
                if (AccessClose && AccessCloseKeys_.contains(*AccessCloseKeyValue))
                {
                    return EnqueueStatus::Filtered;
                }
                if (AccessClose)
                {
                    AccessCloseKeys_.insert(*AccessCloseKeyValue);
                }
                try
                {
                    Queue_.push_back(std::move(Entry));
                }
                catch (...)
                {
                    if (AccessClose)
                    {
                        AccessCloseKeys_.erase(*AccessCloseKeyValue);
                    }
                    throw;
                }
            }
            catch (...)
            {
                return Drop();
            }

            Wake_.notify_one();
            return EnqueueStatus::Accepted;
        }

        /** @brief 请求 owner 关闭并排空后台队列；只应在生命周期边界调用。 */
        auto Stop() noexcept -> void
        {
            {
                std::lock_guard Lock(Mutex_);
                if (Stopping_)
                {
                    return;
                }
                Stopping_ = true;
            }
            Wake_.notify_one();
            if (Worker_.joinable())
            {
                Worker_.join();
            }
            if (File_.is_open())
            {
                File_.flush();
                File_.close();
            }
            Accepting_.store(false, std::memory_order_release);
        }

        [[nodiscard]] auto IsRunning() const noexcept -> bool
        {
            return Accepting_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Dropped() const noexcept -> std::uint64_t
        {
            return Dropped_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] auto Options() const noexcept -> const LoggerOptions &
        {
            return Options_;
        }

    private:
        struct AccessCloseKey final
        {
            bool SessionScoped{false};
            std::uint64_t Identity{0};

            friend constexpr auto operator==(const AccessCloseKey &, const AccessCloseKey &)
                noexcept -> bool = default;
        };

        struct AccessCloseKeyHash final
        {
            [[nodiscard]] auto operator()(const AccessCloseKey &Value) const noexcept
                -> std::size_t
            {
                std::size_t Hash = std::hash<bool>{}(Value.SessionScoped);
                Hash ^= std::hash<std::uint64_t>{}(Value.Identity) +
                        static_cast<std::size_t>(0x9e3779b9U) + (Hash << 6U) + (Hash >> 2U);
                return Hash;
            }
        };

        [[nodiscard]] static auto MakeAccessCloseKey(
            const Preview::Statistics::TraceSnapshot &Trace) noexcept -> AccessCloseKey
        {
            if (Trace.Session)
            {
                return AccessCloseKey{true, Trace.Session->Value()};
            }
            return AccessCloseKey{false, Trace.Correlation ? Trace.Correlation->Value() : 0U};
        }

        struct Record final
        {
            LogLevel Level{LogLevel::Info};
            std::uint64_t Timestamp{0};
            Preview::Statistics::TraceSnapshot Trace{};
            std::string Event;
            std::string Message;
        };

        static constexpr std::string_view FormatHeaderValue =
            "# PrismPreview log format=v2\n";

        static constexpr std::uint64_t MinRotateBytes = 4096ULL;
        static constexpr std::uint64_t MaxRotateBytes = 1024ULL * 1024ULL * 1024ULL;
        static constexpr std::uint32_t MaxRotateFiles = 64U;
        static constexpr std::uint32_t MaxFlushIntervalMs = 600000U;

        Logger(LoggerOptions OptionsValue, std::ofstream FileValue, const std::uint64_t ExistingBytes)
            : Options_(std::move(OptionsValue)),
              File_(std::move(FileValue)),
              BytesWritten_(ExistingBytes)
        {
            Worker_ = std::thread(&Logger::Run, this);
        }

        [[nodiscard]] static auto IsKnownLevel(const LogLevel Value) noexcept -> bool
        {
            return static_cast<std::uint8_t>(Value) <= static_cast<std::uint8_t>(LogLevel::Off);
        }

        [[nodiscard]] static auto IsSafeFileName(const std::string_view Value) noexcept -> bool
        {
            return !Value.empty() && Value != "." && Value != ".." &&
                   Value.find_first_of("/\\:") == std::string_view::npos;
        }

        [[nodiscard]] static auto FormatHeader() noexcept -> std::string_view
        {
            return FormatHeaderValue;
        }

        [[nodiscard]] static auto HasCurrentHeader(const std::filesystem::path &Path) -> bool
        {
            std::ifstream Input(Path, std::ios::binary);
            if (!Input.is_open())
            {
                return false;
            }
            std::string Header;
            std::getline(Input, Header);
            return Header == "# PrismPreview log format=v2";
        }

        [[nodiscard]] static auto ArchiveLegacy(const std::filesystem::path &Path) -> bool
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

        [[nodiscard]] static auto IsEventCharacter(const char Value) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Value);
            return (Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
                   (Byte >= '0' && Byte <= '9') || Value == '_' || Value == '-' || Value == '.';
        }

        [[nodiscard]] static auto ExtractEvent(const std::string_view Message) -> std::string
        {
            std::size_t Search = 0;
            while (Search < Message.size())
            {
                const auto Position = Message.find("event=", Search);
                if (Position == std::string_view::npos)
                {
                    break;
                }
                const bool Boundary = Position == 0U ||
                                      !IsEventCharacter(Message[Position - 1U]);
                const auto ValueStart = Position + 6U;
                if (Boundary && ValueStart < Message.size() && IsEventCharacter(Message[ValueStart]))
                {
                    auto ValueEnd = ValueStart;
                    while (ValueEnd < Message.size() && IsEventCharacter(Message[ValueEnd]))
                    {
                        ++ValueEnd;
                    }
                    return std::string(Message.substr(ValueStart, ValueEnd - ValueStart));
                }
                Search = ValueStart;
            }
            return {};
        }

        [[nodiscard]] auto ShouldWrite(const LogLevel Value) const noexcept -> bool
        {
            return Value != LogLevel::Off && Options_.Level != LogLevel::Off &&
                   static_cast<std::uint8_t>(Value) >= static_cast<std::uint8_t>(Options_.Level);
        }

        auto Drop() noexcept -> EnqueueStatus
        {
            Dropped_.fetch_add(1, std::memory_order_relaxed);
            return EnqueueStatus::Dropped;
        }

        [[nodiscard]] auto LogPath() const -> std::filesystem::path
        {
            return Options_.Directory / Options_.FileName;
        }

        [[nodiscard]] auto RotatedPath(const std::uint32_t Index) const -> std::filesystem::path
        {
            return std::filesystem::path(LogPath().string() + "." + std::to_string(Index));
        }

        [[nodiscard]] static auto FormatRecord(const Record &Entry) -> std::string
        {
            std::ostringstream Output;
            const auto Seconds = static_cast<std::time_t>(Entry.Timestamp / 1000U);
            const auto Milliseconds = Entry.Timestamp % 1000U;
            std::tm LocalTime{};
#if defined(_WIN32)
            localtime_s(&LocalTime, &Seconds);
#else
            localtime_r(&Seconds, &LocalTime);
#endif
            Output << '[' << std::put_time(&LocalTime, "%Y-%m-%d %H:%M:%S") << '.'
                   << std::setfill('0') << std::setw(3) << Milliseconds << std::setfill('0')
                   << "] [" << LogLevelName(Entry.Level) << ']';
            if (!Entry.Event.empty())
            {
                Output << " [Event=" << Entry.Event << ']';
            }
            if (Entry.Trace.Correlation)
            {
                Output << " [Correlation=" << Entry.Trace.Correlation->Value() << ']';
            }
            if (Entry.Trace.Worker)
            {
                Output << " [Worker=" << Entry.Trace.Worker->Value() << ']';
            }
            if (Entry.Trace.Session)
            {
                Output << " [Session=" << Entry.Trace.Session->Value() << ']';
            }
            if (Entry.Trace.Stream)
            {
                Output << " [Stream=" << Entry.Trace.Stream->Value() << ']';
            }
            if (Entry.Trace.Task)
            {
                Output << " [Task=" << Entry.Trace.Task->Value() << ']';
            }
            if (Entry.Trace.Generation)
            {
                Output << " [Generation=" << Entry.Trace.Generation->Value() << ']';
            }
            AppendStructuredField(Output, "Carrier", Entry.Trace.Carrier);
            AppendStructuredField(Output, "Protocol", Entry.Trace.Protocol);
            AppendStructuredField(Output, "Sni", Entry.Trace.Sni);
            AppendStructuredField(Output, "Alpn", Entry.Trace.Alpn);
            AppendStructuredField(Output, "TlsVersion", Entry.Trace.TlsVersion);
            AppendStructuredField(Output, "Stage", Entry.Trace.Stage);
            AppendStructuredField(Output, "Status", Entry.Trace.Status);
            AppendStructuredField(Output, "FaultCode", Entry.Trace.FaultCode);
            AppendStructuredField(Output, "NativeError", Entry.Trace.NativeError);
            if (Entry.Trace.ElapsedMs)
            {
                Output << " [ElapsedMs=" << *Entry.Trace.ElapsedMs << ']';
            }
            Output << ' ';
            if (Entry.Level == LogLevel::Access && Entry.Event == "session_closed")
            {
                Output << "stage=close ";
            }
            Output << Entry.Message << '\n';
            return Output.str();
        }

        static auto AppendStructuredField(
            std::ostringstream &Output,
            const std::string_view Name,
            const std::string &Value) -> void
        {
            if (!Value.empty())
            {
                Output << " [" << Name << '=' << Preview::Statistics::RedactSensitiveText(Value)
                       << ']';
            }
        }

        auto Rotate() noexcept -> void
        {
            File_.flush();
            File_.close();
            std::error_code Error;
            for (std::uint32_t Index = Options_.RotateFiles; Index > 1U; --Index)
            {
                const auto Source = RotatedPath(Index - 1U);
                const auto Destination = RotatedPath(Index);
                std::filesystem::remove(Destination, Error);
                Error.clear();
                std::filesystem::rename(Source, Destination, Error);
                Error.clear();
            }
            const auto First = RotatedPath(1U);
            std::filesystem::remove(First, Error);
            Error.clear();
            std::filesystem::rename(LogPath(), First, Error);
            Error.clear();
            File_.open(LogPath(), std::ios::binary | std::ios::app);
            BytesWritten_ = 0;
            if (File_.is_open())
            {
                const auto Header = FormatHeader();
                File_.write(Header.data(), static_cast<std::streamsize>(Header.size()));
                if (File_)
                {
                    BytesWritten_ = static_cast<std::uint64_t>(Header.size());
                }
            }
        }

        auto WriteRecord(const Record &Entry) -> void
        {
            const auto Line = FormatRecord(Entry);
            if (File_.is_open())
            {
                if (BytesWritten_ != 0U &&
                    BytesWritten_ + static_cast<std::uint64_t>(Line.size()) > Options_.RotateBytes)
                {
                    Rotate();
                }
                if (File_.is_open())
                {
                    File_.write(Line.data(), static_cast<std::streamsize>(Line.size()));
                    if (File_)
                    {
                        BytesWritten_ += static_cast<std::uint64_t>(Line.size());
                    }
                }
            }
            if (Options_.Console)
            {
                std::clog.write(Line.data(), static_cast<std::streamsize>(Line.size()));
            }
        }

        auto Run() noexcept -> void
        {
            const auto Interval = std::chrono::milliseconds(Options_.FlushIntervalMs);
            auto NextFlush = std::chrono::steady_clock::now() + Interval;
            for (;;)
            {
                std::deque<Record> Batch;
                bool ShouldExit = false;
                {
                    std::unique_lock Lock(Mutex_);
                    Wake_.wait_until(Lock, NextFlush,
                                     [this]() { return Stopping_ || !Queue_.empty(); });
                    Batch.swap(Queue_);
                    ShouldExit = Stopping_ && Queue_.empty();
                }

                for (const auto &Entry : Batch)
                {
                    try
                    {
                        WriteRecord(Entry);
                    }
                    catch (...)
                    {
                        Dropped_.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                const auto Now = std::chrono::steady_clock::now();
                if (ShouldExit || Now >= NextFlush)
                {
                    File_.flush();
                    if (Options_.Console)
                    {
                        std::clog.flush();
                    }
                    NextFlush = Now + Interval;
                }
                if (ShouldExit)
                {
                    return;
                }
            }
        }

        LoggerOptions Options_;
        std::ofstream File_;
        std::uint64_t BytesWritten_{0};
        mutable std::mutex Mutex_;
        std::condition_variable Wake_;
        std::deque<Record> Queue_;
        std::unordered_set<AccessCloseKey, AccessCloseKeyHash> AccessCloseKeys_;
        std::thread Worker_;
        std::atomic<bool> Accepting_{true};
        std::atomic<std::uint64_t> Dropped_{0};
        bool Stopping_{false};
    };

} // namespace Preview::Diagnose
