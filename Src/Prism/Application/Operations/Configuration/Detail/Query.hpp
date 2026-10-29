/**
 * @file Query.hpp
 * @brief Application 内部管理配置查询入口。
 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Operations/Models.hpp>

#include <memory>

namespace Prism::Application::OperationsConfiguration
{

    [[nodiscard]] auto MakeQuery(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &State,
        const Prism::Operations::ConfigurationQuery &Query)
        -> Prism::Operations::QueryResult;

} // namespace Prism::Application::OperationsConfiguration
