/**
 * @file WriteLoop.hpp
 * @brief 多路复用会话的底层写入细节
 * @details 将会话帧的 uint8_t 视图适配到 Prism Transmission 的
 *          byte 视图，保留会话层统一的协议错误映射。每次部分写沿唯一
 *          typed 前门 Raw->WriteSome 启动，已完成字节先消费再判定终态。
 */

#pragma once

#include <cstdint>
#include <span>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Mux::Detail
{

    /** @brief 一个帧写入的协议结果与原始传输终态。 */
    struct FrameWriteResult final
    {
        ProtocolEc ErrorCode{};
        Prism::Fault::Failure Terminal{};
    };

    /**
     * @brief 写入一个帧缓冲并保留底层终态。
     * @param Raw 底层传输（借用；调用方保活到协程返回）
     * @param Buffer 待写入帧（借用至协程返回）
     * @return 原协议错误码与原始失败；成功时两项均成功
     * @details 单次部分写消费 IoResult 的 Bytes 与 Failure；零字节或 over-report
     *          按 BrokenPipe 报告，不复制缓冲区。
     */
    [[nodiscard]] auto WriteFrame(
        SharedTransmission Raw,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<FrameWriteResult>;

} // namespace Prism::Mux::Detail
