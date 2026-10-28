/** @file Lifecycle.hpp @brief Application 账户持久化 owner 的启动、预热和最终关闭。 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Storage/Sqlite/Detail/Usage.hpp>
#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <Prism/Application/Startup/Detail/Errors.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <exception>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace Prism::Application::StorageLifecycle
{
    namespace Detail
    {
        template <class Result>
        [[nodiscard]] auto RunBlocking(boost::asio::awaitable<Result> Operation) -> Result
        {
            boost::asio::io_context Context;
            std::optional<Result> Value;
            std::exception_ptr Error;
            boost::asio::co_spawn(Context, std::move(Operation),
                [&Value, &Error](std::exception_ptr Failure, Result ResultValue)
                {
                    Error = std::move(Failure);
                    Value.emplace(std::move(ResultValue));
                });
            Context.run();
            if (Error) std::rethrow_exception(Error);
            if (!Value) throw std::runtime_error("storage operation did not complete");
            return std::move(*Value);
        }

        /** @brief 启动失败时关闭并等待本地存储 owner，失败原因仍由调用者主错误表达。 */
        [[nodiscard]] inline auto ShutdownAndJoin(
            std::shared_ptr<Storage::StorageRuntime> Owner) noexcept -> bool
        {
            if (!Owner) return true;
            bool Succeeded = false;
            try
            {
                Succeeded = RunBlocking(Owner->Shutdown()).has_value();
            }
            catch (...)
            {
            }
            try
            {
                Owner->Join();
            }
            catch (...)
            {
                Succeeded = false;
            }
            return Succeeded;
        }
    }

    /** @brief 空值使用配置旁 data/配置名；显式相对路径相对配置文件解析。 */
    [[nodiscard]] inline auto ResolveDirectory(
        const Configuration::StorageConfiguration &Configured,
        const std::filesystem::path &ConfigurationPath) -> std::filesystem::path
    {
        if (!Configured.Directory.empty())
        {
            const std::filesystem::path Path(Configured.Directory);
            if (Path.is_absolute() || ConfigurationPath.parent_path().empty()) return Path;
            return ConfigurationPath.parent_path() / Path;
        }
        auto Parent = ConfigurationPath.parent_path();
        if (Parent.empty()) Parent = std::filesystem::current_path();
        return Parent / "data" / ConfigurationPath.stem();
    }

    /** @brief 在初始账户快照发布前打开真实存储并挂接唯一异步持久端口。 */
    [[nodiscard]] inline auto Open(
        const std::shared_ptr<Application::RuntimeState> &Runtime,
        const std::filesystem::path &ConfigurationPath)
        -> std::expected<void, StartupError>
    {
        if (!Runtime || !Runtime->Generation || !Runtime->Accounts.Identities)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Storage", "storage requires an account identity owner"));
        }
        const auto &Configured = Runtime->Generation->Configuration().Storage;
        auto Opened = Detail::RunBlocking(Storage::StorageRuntime::Open(
            Storage::StorageOptions{ResolveDirectory(Configured, ConfigurationPath), {},
                Configured.HistoryMaxBytes}));
        if (!Opened)
        {
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Storage", "storage runtime could not be opened"));
        }
        auto Owner = std::move(*Opened);
        const auto Attached = Runtime->Accounts.Identities->RuntimeRegistry()->AttachUsagePersistence(
            std::make_shared<Storage::SqliteUsagePersistence>(Owner),
            Owner->Incarnation());
        if (!Attached)
        {
            if (!Detail::ShutdownAndJoin(std::move(Owner)))
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::Runtime, "Storage",
                    "account usage persistence failed to attach and storage cleanup failed"));
            }
            return std::unexpected(Startup::MakeStartupError(
                StartupErrorCode::Runtime, "Accounts",
                "account usage persistence could not be attached"));
        }
        Runtime->StorageOwner = std::move(Owner);
        return {};
    }

    /** @brief 初始 generation 发布后、监听器启动前为有限额度读取持久余额。 */
    [[nodiscard]] inline auto WarmUsage(
        const std::shared_ptr<Application::RuntimeState> &Runtime)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Runtime || !Runtime->Accounts.Identities || !Runtime->StorageOwner)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        return Detail::RunBlocking(Runtime->Accounts.Identities->RuntimeRegistry()->FlushUsage(false));
    }

    /** @brief 数据面全部退休后最终结算并封止存储执行域。 */
    [[nodiscard]] inline auto Finalize(
        const std::shared_ptr<Application::RuntimeState> &Runtime)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Runtime || !Runtime->StorageOwner)
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (!Runtime->Accounts.Identities)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        const auto Flushed = co_await Runtime->Accounts.Identities->RuntimeRegistry()->FlushUsage(true);
        if (!Flushed) co_return std::unexpected(Flushed.error());
        const auto Closed = co_await Runtime->StorageOwner->Shutdown();
        if (!Closed) co_return std::unexpected(Closed.error());
        Runtime->StorageShutdownSucceeded.store(true, std::memory_order_release);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    /** @brief 仅同步最终化路径等待存储线程；必须先完成 Finalize。 */
    inline auto Join(const std::shared_ptr<Application::RuntimeState> &Runtime) -> void
    {
        if (!Runtime || !Runtime->StorageOwner) return;
        if (!Runtime->StorageShutdownSucceeded.load(std::memory_order_acquire))
            throw std::runtime_error("storage shutdown was not completed");
        Runtime->StorageOwner->Join();
    }
}
