/**
 * @file HttpForwardTestSupport.hpp
 * @brief HTTP 正向代理入口测试的共享 alias 与解析辅助。
 */
#pragma once
/**
 * @file HttpForwardTestSupport.hpp
 * @brief HTTP 正向代理真实 Application 入口验收。
 */

#include <gtest/gtest.h>

#include "HttpForwardApplicationFixture.hpp"
#include "HttpForwardOriginFixture.hpp"
#include "HttpForwardProtocolFixture.hpp"

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    namespace Fixture = Prism::Testing::HttpForward;

    using Fixture::CloseSocket;
    using Fixture::Connect;
    using Fixture::FindFreePort;
    using Fixture::IoTimeout;
    using Fixture::LoopbackOrigin;
    using Fixture::MakeOriginHost;
    using Fixture::OriginCloseMode;
    using Fixture::OperationsDrainObservation;
    using Fixture::ProxyAuthorization;
    using Fixture::ReadUntilClose;
    using Fixture::RunningApplication;
    using Fixture::TemporaryConfiguration;
    using Fixture::TemporaryConfigurationOptions;
    using Fixture::WaitForResourcesEmpty;
    using Fixture::WriteAll;
    using Fixture::DialFailureTimeout;

} // namespace

