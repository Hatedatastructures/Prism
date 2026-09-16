/**
 * @file PreviewProductionBridgeTest.cpp
 * @brief Preview/production worker bridge 类型契约测试
 * @details Contract target 有意同时拥有 production 与 Preview 闭包，
 *          验证 bridge 的真实 production owner 类型可被构造。
 */

#include <gtest/gtest.h>

#include <memory>
#include <type_traits>
#include <utility>

#include <prism/preview/WorkerBridge.hpp>
#include <prism/preview/ProductionWorkerServices.hpp>
#include <prism/resource/worker.hpp>
#include <prism/runtime/worker/worker.hpp>

namespace
{

    TEST(PreviewProductionBridgeContract, TypedProductionAccessUsesPublicWorkerTypes)
    {
        using ResourceWorker = psm::resource::worker;
        using ProductionLauncher = psm::runtime::worker::worker;
        static_assert(std::is_same_v<decltype(psm::preview::WorkerBridge::ProductionAccess::ResourceWorker),
                                     std::shared_ptr<ResourceWorker>>);
        static_assert(std::is_same_v<decltype(psm::preview::WorkerBridge::ProductionAccess::Launcher),
                                     std::shared_ptr<ProductionLauncher>>);

        psm::preview::WorkerBridge::ProductionAccess Access;
        Access.Alive = [] { return true; };
        Access.Stop = [] {};
        Access.Metrics = [] { return psm::preview::WorkerMetricsSnapshot{.Alive = true}; };
        const auto Bridge = psm::preview::WorkerBridge::FromProduction(std::move(Access));

        EXPECT_TRUE(Bridge.IsAlive());
        EXPECT_TRUE(Bridge.Metrics().Alive);
    }

    TEST(PreviewProductionBridgeContract, Socks5PreviewLauncherIsExplicitlyRegistered)
    {
        const auto Launcher = psm::preview::ProductionWorkerServices::Socks5PreviewConnectionLauncher();
        EXPECT_TRUE(static_cast<bool>(Launcher));
        EXPECT_EQ(psm::preview::ProductionWorkerServices::Socks5ModeDescription(),
                  "socks5=preview;other_protocols=production_fallback");
    }

    TEST(PreviewProductionBridgeContract, HttpPreviewLauncherIsExplicitlyRegistered)
    {
        const auto Launcher = psm::preview::ProductionWorkerServices::HttpPreviewConnectionLauncher();
        EXPECT_TRUE(static_cast<bool>(Launcher));
        EXPECT_EQ(psm::preview::ProductionWorkerServices::HttpModeDescription(),
                  "http=preview;other_protocols=production_fallback");
    }

} // namespace
