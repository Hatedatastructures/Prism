/**
 * @file result.hpp
 * @brief 识别模块结果结构定义
 * @details 定义 ClientHello 分析结果和方案执行结果结构。
 */

#pragma once

#include <prism/memory/container.hpp>
#include <prism/recognition/confidence.hpp>
#include <prism/recognition/feature.hpp>
#include <prism/fault/code.hpp>
#include <prism/stealth/scheme.hpp>

namespace psm::recognition
{
    /**
     * @struct analysis_result
     * @brief ClientHello 特征分析结果
     * @details 包含候选方案列表、整体置信度和提取的特征。
     */
    struct analysis_result
    {
        /** @brief 候选方案名称列表（按置信度排序，高置信度在前） */
        memory::vector<memory::string> candidates;

        /** @brief 整体置信度（最高置信度方案的置信度） */
        confidence confidence{confidence::none};

        /** @brief 提取的 ClientHello 特征 */
        clienthello_features features;

        /** @brief 解析错误码 */
        fault::code error{fault::code::success};
    };

    /**
     * @struct execution_result
     * @brief 方案执行结果
     * @details 包含方案返回结果、成功执行的方案名称和状态。
     */
    struct execution_result
    {
        /** @brief 方案返回结果（传输层、检测协议、预读数据） */
        psm::stealth::scheme_result scheme_result;

        /** @brief 成功执行的方案名称 */
        memory::string executed_scheme;

        /** @brief 是否成功识别并建立传输层 */
        bool success{false};
    };
} // namespace psm::recognition