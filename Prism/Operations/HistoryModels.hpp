/** @file HistoryModels.hpp @brief 历史查询管理边界输入。 */
#pragma once
#include <Prism/Statistics/Analysis/HistoryModels.hpp>
namespace Prism::Operations
{
    struct HistoryRead final { Prism::Statistics::HistoryQuery Request; };
}
