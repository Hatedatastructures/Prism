/**
 * @file XhttpNgxFactoryE2E.cpp
 * @brief XHTTP factory and split-mode end-to-end tests.
 */
#include "../Core/XhttpNgxE2ESupport.hpp"

TEST(XhttpNgxE2E, ClientFactoryProvidesStreamOneTransport)
{
    auto IoContext = std::make_shared<Net::io_context>();
    auto ServerContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
    LoadSelfSigned(*ServerContext);
    auto ClientContext = std::make_shared<SSL::context>(SSL::context::tlsv13_client);
    ClientContext->set_verify_mode(SSL::verify_none);

    auto [A, B] = Prism::MakeMemoryPair(IoContext->get_executor());
    auto ClientRaw = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto ServerRaw = std::make_shared<Prism::MemoryStream>(std::move(B));
    const std::weak_ptr<Prism::Transmission> ClientWeak = ClientRaw;
    const std::weak_ptr<Prism::Transmission> ServerWeak = ServerRaw;
    Xhttp::Config Config;
    const std::string Payload = "xhttp-client-factory-echo";
    auto ClientSucceeded = std::make_shared<bool>(false);
    auto ServerSucceeded = std::make_shared<bool>(false);
    auto TimedOut = std::make_shared<bool>(false);
    FactoryScenarioRequest Request{
        IoContext->get_executor(),
        std::move(ClientRaw),
        std::move(ServerRaw),
        ClientContext,
        ServerContext,
        Config,
        Payload,
        ClientSucceeded,
        ServerSucceeded,
        TimedOut};

    RunCoroutine(IoContext, RunFactoryScenario(std::move(Request)));
    EXPECT_FALSE(*TimedOut);
    EXPECT_TRUE(*ServerSucceeded);
    EXPECT_TRUE(*ClientSucceeded);
    EXPECT_TRUE(ClientWeak.expired());
    EXPECT_TRUE(ServerWeak.expired());
}

TEST(XhttpNgxE2E, SplitModesEcho)
{
    for (const auto Mode : {"StreamUp", "PacketUp"})
    {
        auto IoContext = std::make_shared<Net::io_context>();
        auto ServerContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
        LoadSelfSigned(*ServerContext);
        auto ClientContext = std::make_shared<SSL::context>(SSL::context::tlsv13_client);
        ClientContext->set_verify_mode(SSL::verify_none);

        auto [A, B] = Prism::MakeMemoryPair(IoContext->get_executor());
        auto ClientRaw = std::make_shared<Prism::MemoryStream>(std::move(A));
        auto ServerRaw = std::make_shared<Prism::MemoryStream>(std::move(B));
        const std::weak_ptr<Prism::Transmission> ClientWeak = ClientRaw;
        const std::weak_ptr<Prism::Transmission> ServerWeak = ServerRaw;
        Xhttp::Config Config;
        Config.Path = "/xhttp";
        Config.Mode = Mode;
        const std::string Payload = std::string("xhttp-") + Mode + "-echo";
        auto ClientSucceeded = std::make_shared<bool>(false);
        auto ServerSucceeded = std::make_shared<bool>(false);
        auto TimedOut = std::make_shared<bool>(false);
        auto Trace = std::make_shared<FactoryScenarioRequest::SplitTrace>();
        FactoryScenarioRequest Request{
            IoContext->get_executor(),
            ClientRaw,
            ServerRaw,
            ClientContext,
            ServerContext,
            Config,
            Payload,
            ClientSucceeded,
            ServerSucceeded,
            TimedOut,
            Trace};

        RunCoroutine(IoContext, RunSplitScenario(std::move(Request)));
        EXPECT_FALSE(*TimedOut) << Mode;
        EXPECT_TRUE(*ServerSucceeded) << Mode;
        EXPECT_TRUE(*ClientSucceeded) << Mode;
        if (!*ServerSucceeded || !*ClientSucceeded)
        {
            ADD_FAILURE() << Mode << " clientStage=" << Trace->ClientStage
                          << " serverStage=" << Trace->ServerStage
                          << " clientBytes=" << Trace->ClientBytes
                          << " serverBytes=" << Trace->ServerBytes
                          << " clientError=" << Trace->ClientError
                          << " serverError=" << Trace->ServerError
                          << " clientHash=" << Trace->ClientHash
                          << " serverHash=" << Trace->ServerHash
                          << " exception=" << Trace->Exception;
        }
        ClientRaw.reset();
        ServerRaw.reset();
        EXPECT_TRUE(ClientWeak.expired()) << Mode;
        EXPECT_TRUE(ServerWeak.expired()) << Mode;
    }
}

