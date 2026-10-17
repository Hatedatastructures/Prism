/** @file HistoryModels.hpp @brief 历史查询管理边界输入。 */
#pragma once
#include <Preview/Statistics/Analysis/HistoryModels.hpp>
namespace Preview::Operations
{
    struct HistoryRead final { Preview::Statistics::HistoryQuery Request; };
}
