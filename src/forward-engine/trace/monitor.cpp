#include <forward-engine/trace/monitor.hpp>
#include <iostream>

namespace ngx::trace::deprecated
{
    coroutine_log::coroutine_log(const asio::any_io_executor& executor)
        : event_executor(executor),
          serial_exec(asio::make_strand(executor))
    {
        file_map.reserve(4);
        root_directory = fs::current_path() / "logs";
        time_offset = std::chrono::hours(8ULL);
    }

    auto coroutine_log::set_output_directory(const std::string& directory_name)
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        fs::path candidate(directory_name);
        candidate = candidate.lexically_normal();
        if (candidate.empty())
        {
            co_return;
        }
        for (const auto& part : candidate)
        {
            if (part == "..")
            {
                co_return;
            }
        }
        root_directory = std::move(candidate);
        if (!fs::exists(root_directory))
        {
            boost::system::error_code ec;
            fs::create_directories(root_directory, ec);
        }
    }

    auto coroutine_log::set_max_file_size(const std::size_t size)
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        max_file_size = size;
    }

    auto coroutine_log::set_time_offset(const std::chrono::minutes offset)
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        time_offset = offset;
    }

    auto coroutine_log::set_file_level_threshold(const level threshold)
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        file_level_threshold = threshold;
    }

    auto coroutine_log::set_console_level_threshold(const level threshold)
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        console_level_threshold = threshold;
    }

    auto coroutine_log::set_max_archive_count(const std::size_t count)
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        max_archive_count = count;
    }

    auto coroutine_log::close_file(const std::string& path) const
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        if (const auto it = file_map.find(path); it != file_map.end())
        {
            if (it->second.handle)
            {
                it->second.handle->close();
            }
            file_map.erase(it);
        }
    }

    auto coroutine_log::shutdown() const
        -> asio::awaitable<void>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        for (auto it = file_map.begin(); it != file_map.end();)
        {
            if (it->second.handle)
            {
                it->second.handle->close();
            }
            it = file_map.erase(it);
        }
    }

    auto coroutine_log::file_write(
        const std::string& path,
        const std::vector<std::string>& data) const
        -> asio::awaitable<std::size_t>
    {
        std::size_t total = 0;
        for (const auto& s : data)
        {
            total += s.size();
        }
        std::string joined;
        joined.reserve(total);
        for (const auto& s : data)
        {
            joined.append(s);
        }

        co_return co_await file_write(path, joined);
    }

    auto coroutine_log::to_string(const level& log_level)
        -> std::string
    {
        switch (log_level)
        {
            case level::debug:
                return "DEBUG";
            case level::info:
                return "INFO";
            case level::warn:
                return "WARN";
            case level::error:
                return "ERROR";
            case level::fatal:
                return "FATAL";
            default:
                return "";
        }
    }

    auto coroutine_log::console_write(
        const level& log_level,
        const std::string& data) const
        -> asio::awaitable<std::size_t>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        if (static_cast<int>(log_level) < static_cast<int>(console_level_threshold))
        {
            co_return 0;
        }
        const std::string log_str = timestamp_string() + std::format("[{}] ", to_string(log_level)) + data;
        std::cout.write(log_str.data(), static_cast<std::streamsize>(log_str.size()));
        std::cout.flush();
        std::size_t n = log_str.size();
        co_return n;
    }

    auto coroutine_log::console_write_line(
        const level& log_level,
        const std::string& data) const
        -> asio::awaitable<std::size_t>
    {
        co_await asio::dispatch(serial_exec, asio::use_awaitable);
        if (static_cast<int>(log_level) < static_cast<int>(console_level_threshold))
        {
            co_return 0;
        }
        std::string log_str = timestamp_string() + std::format("[{}] ", to_string(log_level)) + data + "\n";
        std::cout.write(log_str.data(), static_cast<std::streamsize>(log_str.size()));
        std::cout.flush();
        std::size_t n = log_str.size();
        co_return n;
    }

    auto coroutine_log::file_write_line(
        const std::string& filename,
        const std::string& data) const
        -> asio::awaitable<std::size_t>
    {
        std::string s = timestamp_string() + data + "\n";
        co_return co_await file_write(filename, s);
    }

    auto coroutine_log::timestamp_string() const
        -> std::string
    {
        auto now = std::chrono::system_clock::now() + time_offset;
        auto ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
        auto secs = std::chrono::time_point_cast<std::chrono::seconds>(ms);
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(ms - secs).count();

        return std::format("[{:%Y-%m-%d %H:%M:%S}.{:03d}]", secs, millis);
    }

    void coroutine_log::cleanup_old_archives(const fs::path& target_path) const
    {
        if (max_archive_count == 0)
        {
            return;
        }
        boost::system::error_code ec;
        const fs::path parent = target_path.parent_path();
        if (!fs::exists(parent, ec))
        {
            return;
        }
        const std::string stem = target_path.stem().string();
        const std::string ext = target_path.extension().string();
        const std::string prefix = stem + "-";
        std::vector<fs::directory_entry> archives;
        for (fs::directory_iterator it(parent, ec), end; it != end && !ec; ++it)
        {
            const auto& entry = *it;
            if (!entry.is_regular_file(ec))
            {
                continue;
            }
            if (std::string name = entry.path().filename().string();
                name.size() >= prefix.size() + ext.size() &&
                name.starts_with(prefix) && name.ends_with(ext))
            {
                archives.push_back(entry);
            }
        }
        if (archives.size() <= max_archive_count)
        {
            return;
        }
        auto archives_sorted = [](const fs::directory_entry& a, const fs::directory_entry& b)
        {
            return a.path().filename().string() < b.path().filename().string();
        };
        std::ranges::sort(archives, archives_sorted);
        const std::size_t remove_count = archives.size() - max_archive_count;
        for (std::size_t i = 0; i < remove_count; ++i)
        {
            fs::remove(archives[i], ec);
        }
    }

} // namespace ngx::trace::deprecated
