/**
 * @file QuicServices.hpp
 * @brief 将已绑定 QUIC 工厂接入 Boundary CID 表的启动接线。
 * @details 本文件只在冷路径读取类型化 binding，不选择协议或实现协议业务。
 */
#pragma once

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <memory>
#include <utility>

namespace Preview::Application::Startup::QuicServices
{
    inline auto WriteRegistryEvent(const std::weak_ptr<Application::RuntimeState> &WeakRuntime,
        const Preview::Boundary::QuicConnectionRegistryEvent Event) -> void
    {
        const auto Owner = WeakRuntime.lock();
        if (!Owner)
        {
            return;
        }
        (void)Preview::Diagnose::Trace(
            Owner->CurrentProcessContext(), "QuicRegistryStage Stage={} Accepted={} Connections={}",
            Preview::Boundary::QuicConnectionRegistryStageName(Event.Stage),
            Event.Accepted, Event.ActiveConnections);
    }

    /**
     * @brief 构造进程级 QUIC CID/peer registry；factory 随每包 generation selection 提供。
     * @param Runtime 已装配代次的运行时状态。
     * @note Registry 只负责既有 CID/peer 路由与连接租约；未知 CID 的工厂来自当前包 selection。
     *       协议 binding 负责连接 Close/Drain，Boundary 保持 CID 与 UDP socket 所有权。
     */
    inline auto Build(const std::shared_ptr<Application::RuntimeState>& Runtime) -> void
    {
        if (!Runtime->DatagramListener)
        {
            return;
        }

        const auto WeakRuntime = std::weak_ptr<Application::RuntimeState>(Runtime);
        auto Events = [WeakRuntime](Preview::Boundary::QuicConnectionRegistryEvent Event)
        { WriteRegistryEvent(WeakRuntime, Event); };

        Runtime->QuicConnectionRegistry =
            std::make_shared<Preview::Boundary::QuicConnectionRegistry>(
                Preview::Boundary::QuicConnectionRegistry::Options{
                    std::move(Events),
                    Runtime->QuicPacketGateway->AdmissionBudget()});
    }
}
