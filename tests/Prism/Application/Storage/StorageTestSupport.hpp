/** @file StorageTestSupport.hpp @brief 存储用例共享真实临时目录与完整协程驱动，不运行网络服务。 */
#pragma once
#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <chrono>
#include <exception>
#include <optional>
#include <random>
#include <gtest/gtest.h>

namespace Prism::StorageTests
{
    class StorageFixture : public ::testing::Test
    {
    public:
        StorageFixture()
        {
            std::random_device Random;
            const auto Root = std::filesystem::temp_directory_path();
            do { Directory = Root / ("PrismStorageTest-" + std::to_string(Random()) + "-" + std::to_string(Random())); }
            while (!std::filesystem::create_directory(Directory));
        }
        ~StorageFixture() override
        {
            if (Owner) { (void)Run(Owner->Shutdown()); Owner->Join(); Owner.reset(); }
            std::error_code Error;
            std::filesystem::remove_all(Directory, Error);
        }
        template<class Result>
        auto Run(boost::asio::awaitable<Result> Work) -> Result
        {
            Context.restart();
            std::optional<Result> Value;
            std::exception_ptr Error;
            boost::asio::co_spawn(Context, std::move(Work), [&](std::exception_ptr Failure, Result Output)
                { Error = Failure; Value.emplace(std::move(Output)); });
            Context.run();
            if (Error) std::rethrow_exception(Error);
            if (!Value) throw std::runtime_error("storage operation did not complete");
            return std::move(*Value);
        }
        auto Open(std::string Incarnation = "test-first") -> void
        {
            auto Value = Run(Application::Storage::StorageRuntime::Open({Directory, std::move(Incarnation)}));
            if (!Value) throw std::system_error(Fault::ToNative(Value.error()));
            Owner = std::move(*Value);
        }
        auto Close() -> void
        {
            auto Result = Run(Owner->Shutdown());
            if (!Result) throw std::system_error(Fault::ToNative(Result.error()));
            Owner->Join(); Owner.reset();
        }
        boost::asio::io_context Context;
        std::filesystem::path Directory;
        std::shared_ptr<Application::Storage::StorageRuntime> Owner;
    };
}
