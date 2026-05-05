/**
 * @file result.hpp
 * @brief 识别模块分析结果结构定义
 * @details 定义 ClientHello 分析结果结构，由各 scheme 的 detect() 返回。
 * 该结果不包含网络 I/O 相关数据，仅描述特征分析的结论。
 */

#pragma once

#include <prism/memory/container.hpp>
#include <prism/recognition/confidence.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/fault/code.hpp>

namespace psm::recognition
{
    /**
     * @struct analysis_result
     * @brief ClientHello 特征分析结果
     * @details 由 registry::analyze() 返回，包含按置信度排序的候选方案列表。
     * 调用方应根据 candidates 的顺序依次尝试方案执行。
     * confidence 字段反映最高置信度方案的级别，为 none 时表示无任何匹配。
     */
    struct analysis_result
    {
        /** @brief 候选方案名称列表（按置信度排序，high 在前，none 不加入） */
        memory::vector<memory::string> candidates;

        /** @brief 整体置信度，取最高候选的置信度值，无候选时为 none */
        confidence confidence{confidence::none};

        /** @brief 提取的 ClientHello 原始特征，供调用方参考 */
        protocol::tls::client_hello_features features;

        /** @brief 解析错误码，成功时为 fault::code::success */
        fault::code error{fault::code::success};
    };
} // namespace psm::recognition