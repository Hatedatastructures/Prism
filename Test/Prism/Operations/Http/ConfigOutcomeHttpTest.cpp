/** @file ConfigOutcomeHttpTest.cpp @brief 配置冲突与首因经真实HTTP编码保留。 */
#include <Prism/Application/Configuration/Command/Detail/Outcome.hpp>
#include <Prism/Operations/Routes/HttpJson.hpp>
#include <gtest/gtest.h>
#include <string>

TEST(ConfigurationOutcomeHttp, ExpiredBaseReturnsConflictAndExactCurrentGeneration)
{
    const auto Result = Prism::Operations::CommandResult::Conflict(
        Prism::RequestId{9}, Prism::GenerationId{18446744073709551615ULL});
    EXPECT_EQ(Prism::Operations::HttpDetail::StatusFor(Result.Status), 409);
    const auto Body = Prism::Operations::HttpDetail::SerializeCommand(Result);
    ASSERT_TRUE(Body);
    EXPECT_NE(Body->find("\"status\":\"conflict\""), std::string::npos);
    EXPECT_NE(Body->find("\"generation\":\"18446744073709551615\""), std::string::npos);
    EXPECT_NE(Body->find("\"configuration_issues\":[]"), std::string::npos);
}

TEST(ConfigurationOutcomeHttp, RestartStatusAndActualChangedFieldSurviveEncoding)
{
    auto Result = Prism::Operations::CommandResult::RestartRequired(
        Prism::RequestId{10}, Prism::GenerationId{42});
    Result.RestartRequiredFields.push_back("Runtime.WorkerCount");
    EXPECT_EQ(Prism::Operations::HttpDetail::StatusFor(Result.Status), 409);
    const auto Body = Prism::Operations::HttpDetail::SerializeCommand(Result);
    ASSERT_TRUE(Body);
    EXPECT_NE(Body->find("\"status\":\"restart_required\""), std::string::npos);
    EXPECT_NE(Body->find("\"restart_required_fields\":[\"Runtime.WorkerCount\"]"), std::string::npos);
}

TEST(ConfigurationOutcomeHttp, ValidationKeepsFieldCodeAndNeverEchoesInputValue)
{
    const Prism::Application::Configuration::ConfigurationError Error{
        Prism::Application::Configuration::ConfigurationErrorCode::UnresolvedSecret,
        "Accounts[0].SecretRef", "confidential-input-value"};
    const auto Result = Prism::Application::ConfigurationCommandOutcome::Invalid(Prism::RequestId{11}, Error);
    EXPECT_EQ(Prism::Operations::HttpDetail::StatusFor(Result.Status), 400);
    const auto Body = Prism::Operations::HttpDetail::SerializeCommand(Result);
    ASSERT_TRUE(Body);
    EXPECT_NE(Body->find("\"code\":\"unresolved_secret\""), std::string::npos);
    EXPECT_NE(Body->find("\"path\":\"Accounts[0].SecretRef\""), std::string::npos);
    EXPECT_EQ(Body->find("confidential-input-value"), std::string::npos);
}
