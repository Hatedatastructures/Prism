/**
 * @file Grpc.hpp
 * @brief Gun 标准 gRPC/HTTP2 endpoint 聚合入口。
 * @details 配置、stream accept 工厂、metadata、framing 和连接 owner
 *          分别位于职责头文件中。
 */
#pragma once

#include <Preview/Protocols/Gun/GrpcFraming.hpp>
#include <Preview/Protocols/Gun/GrpcMetadata.hpp>
#include <Preview/Protocols/Gun/GrpcStream.hpp>
#include <Preview/Protocols/Gun/GrpcTypes.hpp>
