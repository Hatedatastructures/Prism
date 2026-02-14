/**
 * @file constants.hpp
 * @brief HTTP 协议常量定义
 * @details 定义了 HTTP/1.1 和 HTTP/2 协议的核心常量，包括：
 * - 状态码 (`status` 枚举)：完整的 HTTP 状态码定义，从 100 到 511
 * - 请求方法 (`verb` 枚举)：所有标准 HTTP 方法及扩展方法
 * - 头部字段 (`field` 枚举)：超过 500 个标准及扩展 HTTP 头部字段
 *
 * @note 设计原则：
 * - 零开销枚举：所有枚举使用底层整型，支持高效的 switch 匹配和序列化
 * - 标准兼容：严格遵循 RFC 7230-7235、RFC 7540 及 IANA 注册表
 * - 扩展友好：预留 `unknown` 值处理未识别常量，支持自定义扩展
 * - 内存高效：使用最小化存储类型（`unsigned` 用于状态码，`unsigned short` 用于头部字段）
 *
 * @warning 性能注意：在热路径中避免对 `field` 枚举进行线性查找，应使用预构建的哈希映射
 * @warning 线程安全：所有枚举值均为编译时常量，可安全用于多线程环境
 *
 * ```
 * // 使用示例：解析 HTTP 响应状态码
 * #include <forward-engine/protocol/http/constants.hpp>
 *
 * using namespace ngx::protocol::http;
 *
 * void handle_response(status code)
 * {
 *     switch (code)
 *     {
 *         case status::ok:
 *             std::cout << "请求成功" << std::endl;
 *             break;
 *         case status::not_found:
 *             std::cout << "资源未找到" << std::endl;
 *             break;
 *         case status::internal_server_error:
 *             std::cout << "服务器内部错误" << std::endl;
 *             break;
 *         default:
 *             // 处理未知状态码
 *             break;
 *     }
 * }
 *
 * // 头部字段快速查找示例
 * field header = field::content_type;
 * if (header == field::content_type)
 * {
 *     // 处理 Content-Type 头部
 * }
 * ```
 */
#pragma once

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供：
 * - 请求/响应的序列化与反序列化
 * - 协议状态机管理
 * - 流控与优先级处理（HTTP/2）
 * - 头部压缩（HPACK）
 *
 * @note 该模块设计为无状态，仅负责数据报文的处理，不管理连接生命周期
 * @warning 内存管理：协议处理器使用 `PMR` 内存池，确保零堆分配热路径
 * @see ngx::protocol::http::request HTTP 请求类
 * @see ngx::protocol::http::response HTTP 响应类
 */
namespace ngx::protocol::http
{
    /**
     * @enum status
     * @brief HTTP 状态码枚举
     * @details 完整的 HTTP 状态码定义，覆盖 RFC 7231、RFC 6585、RFC 4918、RFC 5842、RFC 2774、RFC 7540 等标准。
     * 状态码分类遵循 IETF 标准：
     * - **1xx**：信息响应 - 请求已接收，继续处理
     * - **2xx**：成功 - 请求已成功处理
     * - **3xx**：重定向 - 需要进一步操作以完成请求
     * - **4xx**：客户端错误 - 请求包含语法错误或无法完成
     * - **5xx**：服务器错误 - 服务器在处理请求时发生错误
     *
     * @note **设计考虑**：
     * - 使用 `unsigned` 底层类型确保与标准 HTTP 状态码范围（0-999）兼容
     * - 为 `unknown` (0) 预留值处理未识别或自定义状态码
     * - 支持通过 `static_cast<unsigned>` 直接转换为整型用于网络传输
     * - 所有标准状态码均包含官方 RFC 描述
     *
     * @warning **性能提示**：在热路径中使用 `switch` 语句进行状态码匹配，避免线性查找
     * @warning **兼容性注意**：部分扩展状态码（如 103 Early Hints）需要客户端支持
     *
     * @code{.cpp}
     * // 状态码分类判断示例
     * using namespace ngx::protocol::http;
     *
     * bool is_success(status code) {
     *     auto value = static_cast<unsigned>(code);
     *     return value >= 200 && value < 300;
     * }
     *
     * bool is_client_error(status code) {
     *     auto value = static_cast<unsigned>(code);
     *     return value >= 400 && value < 500;
     * }
     *
     * // 状态码到描述映射示例
     * std::string_view get_status_description(status code) {
     *     switch (code) {
     *         case status::ok: return "OK";
     *         case status::not_found: return "Not Found";
     *         case status::internal_server_error: return "Internal Server Error";
     *         default: return "Unknown Status";
     *     }
     * }
     * @endcode
     */
    enum class status : unsigned
    {
        /**
         * @brief unknown
         * @note 这个状态码表示服务器不能识别客户端的请求
         */
        unknown = 0,

        /**
         * @brief continue
         * @note 这个临时响应表明，迄今为止的所有内容都是可行的，客户端应该继续请求，如果已经完成，则忽略它
         */
        continue_ = 100,

        /**
         * @brief switching_protocols
         * @note 这个状态码表示服务器已经理解了客户端的请求，并且同意切换到新的协议
         */
        switching_protocols = 101,

        /**
         * @brief processing
         * @note 这个状态码表示服务器已经理解了客户端的请求，并且正在处理它，但是没有响应体
         */
        processing = 102,

        /**
         * @brief early_hints
         * @note 这个状态码表示服务器已经理解了客户端的请求，并且正在处理它，但是没有响应体
         */
        early_hints = 103,

        /**
         * @brief ok
         * @note 这个状态码表示请求已经成功，响应体包含了请求的结果
         */
        ok = 200,

        /**
         * @brief created
         * @note 这个状态码表示请求已经成功，响应体包含了新创建的资源的信息
         */
        created = 201,

        /**
         * @brief accepted
         * @note 这个状态码表示请求已经被接受，但是服务器还没有开始处理它
         */
        accepted = 202,

        /**
         * @brief non_authoritative_information
         * @note 这个状态码表示服务器已经理解了客户端的请求，但是响应体包含了非授权的信息
         */
        non_authoritative_information = 203,

        /**
         * @brief no_content
         * @note 这个状态码表示请求已经成功，但是响应体是空的
         */
        no_content = 204,

        /**
         * @brief reset_content
         * @note 这个状态码表示请求已经成功，但是响应体是空的
         */
        reset_content = 205,

        /**
         * @brief partial_content
         * @note 这个状态码表示请求已经成功，但是响应体只包含了资源的部分内容
         */
        partial_content = 206,

        /**
         * @brief multi_status
         * @note 这个状态码表示请求已经成功，但是响应体包含了多个状态码
         */
        multi_status = 207,

        /**
         * @brief already_reported
         * @note 这个状态码表示请求已经成功，但是响应体包含了已经存在的资源的信息
         */
        already_reported = 208,

        /**
         * @brief im_used
         * @note 这个状态码表示服务器已经理解了客户端的请求，但是响应体只包含了资源的部分内容
         */
        im_used = 226,

        /**
         * @brief multiple_choices
         * @note 这个状态码表示请求有多个选择，客户端可以根据自己的需求选择其中一个
         */
        multiple_choices = 300,

        /**
         * @brief moved_permanently
         * @note 这个状态码表示请求的资源已经被永久移动到了新的位置
         */
        moved_permanently = 301,

        /**
         * @brief found
         * @note 这个状态码表示请求的资源已经被临时移动到了新的位置
         */
        found = 302,

        /**
         * @brief see_other
         * @note 这个状态码表示请求的资源已经被临时移动到了新的位置
         */
        see_other = 303,

        /**
         * @brief not_modified
         * @note 这个状态码表示请求的资源没有被修改，客户端可以使用缓存的版本
         */
        not_modified = 304,

        /**
         * @brief use_proxy
         * @note 这个状态码表示请求的资源只能通过代理服务器访问
         */
        use_proxy = 305,

        /**
         * @brief switch_proxy
         */
        temporary_redirect = 307,

        /**
         * @brief permanent_redirect
         * @note 这个状态码表示请求的资源已经被永久移动到了新的位置
         */
        permanent_redirect = 308,

        /**
         * @brief bad_request
         * @note 这个状态码表示请求的语法错误，服务器无法理解
         */
        bad_request = 400,

        /**
         * @brief unauthorized
         * @note 这个状态码表示请求需要进行身份验证，客户端需要提供有效的凭证
         */
        unauthorized = 401,

        /**
         * @brief payment_required
         * @note 这个状态码表示请求需要支付才能继续，客户端需要提供有效的支付凭证
         */
        payment_required = 402,

        /**
         * @brief forbidden
         * @note 这个状态码表示请求被服务器拒绝，客户端没有权限访问该资源
         */
        forbidden = 403,

        /**
         * @brief not_found
         * @note 这个状态码表示请求的资源不存在
         */
        not_found = 404,

        /**
         * @brief method_not_allowed
         * @note 这个状态码表示请求的方法不被服务器支持，客户端需要使用其他方法
         */
        method_not_allowed = 405,

        /**
         * @brief not_acceptable
         * @note 这个状态码表示服务器无法根据客户端的请求生成响应
         */
        not_acceptable = 406,

        /**
         * @brief proxy_authentication_required
         * @note 这个状态码表示请求需要通过代理服务器进行身份验证，客户端需要提供有效的凭证
         */
        proxy_authentication_required = 407,

        /**
         * @brief request_timeout
         * @note 这个状态码表示服务器在等待客户端发送请求时超时
         */
        request_timeout = 408,

        /**
         * @brief conflict
         * @note 这个状态码表示请求与服务器当前的状态冲突
         */
        conflict = 409,

        /**
         * @brief gone
         * @note 这个状态码表示请求的资源已经不存在，服务器不再保留该资源
         */
        gone = 410,

        /**
         * @brief length_required
         * @note 这个状态码表示请求的实体主体长度缺失，服务器无法处理该请求
         */
        length_required = 411,

        /**
         * @brief precondition_failed
         * @note 这个状态码表示请求的预条件失败，服务器无法满足该请求
         */
        precondition_failed = 412,

        /**
         * @brief payload_too_large
         * @note 这个状态码表示请求的实体主体长度超过了服务器允许的最大值
         */
        payload_too_large = 413,

        /**
         * @brief uri_too_long
         * @note 这个状态码表示请求的URI长度超过了服务器允许的最大值
         */
        uri_too_long = 414,

        /**
         * @brief unsupported_media_type
         * @note 这个状态码表示请求的实体主体媒体类型不被服务器支持
         */
        unsupported_media_type = 415,

        /**
         * @brief range_not_satisfiable
         * @note 这个状态码表示请求的Range头字段指定的范围无法满足，服务器只能返回整个实体主体
         */
        range_not_satisfiable = 416,

        /**
         * @brief expectation_failed
         * @note 这个状态码表示服务器无法满足请求的Expect头字段指定的条件
         */
        expectation_failed = 417,

        /**
         * @brief i_am_a_teapot
         * @note 这个状态码表示服务端拒绝用茶壶煮咖啡。笑话，典故来源茶壶冲泡咖啡，而不是一个真正的HTTP服务器
         */
        i_am_a_teapot = 418,

        /**
         * @brief misdirected_request
         * @note 这个状态码表示请求被错误的路由到了错误的服务器
         */
        misdirected_request = 421,

        /**
         * @brief unprocessable_entity
         * @note 这个状态码表示请求的实体主体无法被服务器处理，服务器拒绝执行该请求
         */
        unprocessable_entity = 422,

        /**
         * @brief locked
         * @note 这个状态码表示请求的资源被锁定，服务器拒绝执行该请求
         */
        locked = 423,

        /**
         * @brief failed_dependency
         * @note 这个状态码表示请求的依赖关系失败，服务器无法执行该请求
         */
        failed_dependency = 424,

        /**
         * @brief too_early
         * @note 这个状态码表示服务器拒绝执行该请求，因为请求的实体主体还没有准备好
         */
        too_early = 425,

        /**
         * @brief upgrade_required
         * @note 这个状态码表示服务器拒绝执行该请求，因为客户端需要升级到支持的协议版本
         */
        upgrade_required = 426,

        /**
         * @brief precondition_required
         * @note 这个状态码表示服务器拒绝执行该请求，因为请求的预条件失败
         */
        precondition_required = 428,

        /**
         * @brief too_many_requests
         * @note 这个状态码表示服务器拒绝执行该请求，因为客户端发送的请求数量超过了服务器的处理能力
         */
        too_many_requests = 429,

        /**
         * @brief request_header_fields_too_large
         * @note 这个状态码表示请求的头字段长度超过了服务器允许的最大值
         */
        request_header_fields_too_large = 431,

        /**
         * @brief unavailable_for_legal_reasons
         * @note 这个状态码表示请求的资源在法律上是不可用的，服务器拒绝执行该请求
         */
        unavailable_for_legal_reasons = 451,

        /**
         * @brief internal_server_error
         * @note 这个状态码表示服务器内部错误，无法完成请求
         */
        internal_server_error = 500,

        /**
         * @brief not_implemented
         * @note 这个状态码表示服务器不支持请求的功能
         */
        not_implemented = 501,

        /**
         * @brief bad_gateway
         * @note 这个状态码表示服务器作为网关或代理，从上游服务器收到了无效的响应
         */
        bad_gateway = 502,

        /**
         * @brief service_unavailable
         * @note 这个状态码表示服务器暂时无法处理请求，通常是因为服务器过载或维护
         */
        service_unavailable = 503,

        /**
         * @brief gateway_timeout
         * @note 这个状态码表示服务器作为网关或代理，在等待上游服务器响应时超时
         */
        gateway_timeout = 504,

        /**
         * @brief http_version_not_supported
         * @note 这个状态码表示服务器不支持请求的HTTP协议版本
         */
        http_version_not_supported = 505,

        /**
         * @brief variant_also_negotiates
         * @note 这个状态码表示服务器无法根据请求头字段协商响应的变体
         */
        variant_also_negotiates = 506,

        /**
         * @brief insufficient_storage
         * @note 这个状态码表示服务器无法满足请求的存储需求，服务器拒绝执行该请求
         */
        insufficient_storage = 507,

        /**
         * @brief loop_detected
         * @note 这个状态码表示服务器检测到请求的循环，服务器拒绝执行该请求
         */
        loop_detected = 508,

        /**
         * @brief not_extended
         * @note 这个状态码表示服务器拒绝执行该请求，因为请求的功能已被扩展，而服务器不支持该扩展
         */
        not_extended = 510,

        /**
         * @brief network_authentication_required
         * @note 这个状态码表示请求需要网络身份验证，服务器拒绝执行该请求
         */
        network_authentication_required = 511
    }; // enum class status

    /**
     * @enum verb
     * @brief HTTP 请求方法（动词）枚举
     * @details 完整的 HTTP 请求方法定义，覆盖 RFC 7231、RFC 5789、RFC 4918、RFC 5842 等标准。
     * 包含所有标准方法及常见扩展方法，用于标识请求对资源执行的操作类型。
     *
     * **核心方法分类**：
     * - **安全方法**（`safe`）：`GET`、`HEAD`、`OPTIONS`、`TRACE` - 不应修改服务器状态
     * - **幂等方法**（`idempotent`）：`GET`、`HEAD`、`PUT`、`DELETE`、`OPTIONS`、`TRACE` - 重复执行效果相同
     * - **缓存方法**：`GET`、`HEAD`、`POST` - 可被缓存代理处理
     *
     * @note **设计考虑**：
     * - 枚举值顺序遵循标准定义频率，优化 `switch` 语句性能
     * - 为 `unknown` (0) 预留值处理自定义或非标准方法
     * - 支持方法字符串到枚举值的双向转换（`to_string()` / `from_string()`）
     * - 包含 WebDAV (`PROPFIND`、`PROPPATCH` 等) 和扩展方法
     *
     * @warning **安全性注意**：正确处理 `TRACE` 和 `TRACK` 方法防止跨站跟踪攻击
     * @warning **幂等性**：正确实现幂等方法对重试机制和错误恢复至关重要
     *
     * @code{.cpp}
     * // 方法分类判断示例
     * using namespace ngx::protocol::http;
     *
     * bool is_safe_method(verb method) {
     *     switch (method) {
     *         case verb::get:
     *         case verb::head:
     *         case verb::options:
     *         case verb::trace:
     *             return true;
     *         default:
     *             return false;
     *     }
     * }
     *
     * bool is_idempotent(verb method) {
     *     switch (method) {
     *         case verb::get:
     *         case verb::head:
     *         case verb::put:
     *         case verb::delete_:
     *         case verb::options:
     *         case verb::trace:
     *             return true;
     *         case verb::post:
     *         case verb::patch:
     *         case verb::connect:
     *             return false;
     *         default:
     *             return false; // 自定义方法默认非幂等
     *     }
     * }
     *
     * // 方法字符串转换示例
     * std::string method_str = "GET";
     * verb method = verb_from_string(method_str); // 返回 verb::get
     * std::string result = to_string(verb::post); // 返回 "POST"
     * @endcode
     */
    enum class verb
    {
        /**
         * @brief unknown
         * @note 未知方法，表示请求方法字符串不属于已识别动词
         */
        unknown = 0,

        /**
         * @brief delete_
         * @note DELETE 方法：删除指定资源
         */
        delete_,

        /**
         * @brief get
         * @note GET 方法：请求指定资源的表示，只应获取数据，不产生其他副作用
         */
        get,

        /**
         * @brief head
         * @note HEAD 方法：与 GET 相同，但只返回响应头，不返回响应体，用于获取元信息
         */
        head,

        /**
         * @brief post
         * @note POST 方法：将请求中包含的实体作为指定 URI 的新子资源，可用于提交表单、注释等
         */
        post,

        /**
         * @brief put
         * @note PUT 方法：将包含的实体存储在提供的 URI 下；存在则修改，不存在可创建
         */
        put,

        /**
         * @brief connect
         * @note CONNECT 方法：将请求连接转换为透明 TCP/IP 隧道，常用于 HTTPS 代理
         */
        connect,

        /**
         * @brief options
         * @note OPTIONS 方法：返回服务器对指定 URL 所支持的 HTTP 方法，可用 '*' 检测功能
         */
        options,

        /**
         * @brief trace
         * @note TRACE 方法：回显收到的请求，使客户端可查看中间服务器所做的更改
         */
        trace,

        // WebDAV
        /**
         * @brief copy
         * @note COPY 方法：复制资源
         */
        copy,
        /**
         * @brief lock
         * @note LOCK 方法：锁定资源
         */
        lock,
        /**
         * @brief mkcol
         * @note MKCOL 方法：创建集合
         */
        mkcol,
        /**
         * @brief move
         * @note MOVE 方法：移动资源
         */
        move,
        /**
         * @brief propfind
         * @note PROPFIND 方法：查找属性
         */
        propfind,
        /**
         * @brief proppatch
         * @note PROPPATCH 方法：修补属性
         */
        proppatch,
        /**
         * @brief search
         * @note SEARCH 方法：搜索资源
         */
        search,
        /**
         * @brief unlock
         * @note UNLOCK 方法：解锁资源
         */
        unlock,
        /**
         * @brief bind
         * @note BIND 方法：绑定资源
         */
        bind,
        /**
         * @brief rebind
         * @note REBIND 方法：重新绑定资源
         */
        rebind,
        /**
         * @brief unbind
         * @note UNBIND 方法：解除绑定资源
         */
        unbind,
        /**
         * @brief acl
         * @note ACL 方法：访问控制列表
         */
        acl,

        // Subversion
        /**
         * @brief report
         * @note REPORT 方法：报告
         */
        report,
        /**
         * @brief mkactivity
         * @note MKACTIVITY 方法：创建活动
         */
        mkactivity,
        /**
         * @brief checkout
         * @note CHECKOUT 方法：检出资源
         */
        checkout,
        /**
         * @brief merge
         * @note MERGE 方法：合并资源
         */
        merge,

        // UPnP
        /**
         * @brief msearch
         * @note M-SEARCH 方法：多播搜索
         */
        msearch,
        /**
         * @brief notify
         * @note NOTIFY 方法：通知
         */
        notify,
        /**
         * @brief subscribe
         * @note SUBSCRIBE 方法：订阅
         */
        subscribe,
        /**
         * @brief unsubscribe
         * @note UNSUBSCRIBE 方法：取消订阅
         */
        unsubscribe,

        /**
         * @brief patch
         * @note PATCH 方法：对资源进行部分修改
         */
        patch,
        /**
         * @brief purge
         * @note PURGE 方法：清除缓存（Squid 等代理扩展）
         */
        purge,

        /**
         * @brief mkcalendar
         * @note MKCALENDAR 方法：创建日历
         */
        mkcalendar,

        /**
         * @brief link
         * @note LINK 方法：建立资源链接
         */
        link,
        /**
         * @brief unlink
         * @note UNLINK 方法：移除资源链接
         */
        unlink
    };

    /**
     * @enum field
     * @brief HTTP 头部字段枚举
     * @details 完整的 HTTP 头部字段定义，包含超过 500 个标准及扩展头部字段。
     * 基于 IANA 注册表、RFC 标准及实际部署中的常见扩展，覆盖：
     * - **标准请求/响应头部**：`Content-Type`、`Authorization`、`Cache-Control` 等
     * - **安全相关头部**：`Strict-Transport-Security`、`Content-Security-Policy` 等
     * - **性能优化头部**：`Accept-Encoding`、`Content-Encoding`、`ETag` 等
     * - **WebSocket 头部**：`Sec-WebSocket-Key`、`Sec-WebSocket-Accept` 等
     * - **自定义及扩展头部**：`X-Forwarded-For`、`X-Real-IP` 等常见代理头部
     *
     * **头部字段分类**：
     * - **端到端头部**（`end-to-end`）：必须转发给最终接收者，如 `Content-Type`
     * - **逐跳头部**（`hop-by-hop`：仅对单次传输有效，如 `Connection`、`Upgrade`
     * - **请求限定头部**：仅出现在请求中，如 `Host`、`User-Agent`
     * - **响应限定头部**：仅出现在响应中，如 `Server`、`Age`
     *
     * @note **设计考虑**：
     * - 使用 `unsigned short` 底层类型优化内存布局，支持高效数组索引
     * - 字段顺序遵循字母排序，便于二分查找和前缀匹配优化
     * - 为 `unknown` (0) 预留值处理未注册或自定义头部字段
     * - 支持头部字段名到枚举值的双向转换（`to_string()` / `from_string()`）
     * - 包含完整的 RFC 引用，便于标准合规性验证
     *
     * @warning **性能关键**：头部字段查找应使用预构建的 `std::unordered_map` 或完美哈希，避免线性扫描
     * @warning **安全性注意**：正确处理 `Host`、`Origin`、`Referer` 等安全敏感头部
     * @warning **大小写敏感**：HTTP 头部字段名大小写不敏感，但枚举映射使用规范大小写格式
     *
     * @code{.cpp}
     * // 头部字段分类判断示例
     * using namespace ngx::protocol::http;
     *
     * bool is_end_to_end_header(field header) {
     *     // 端到端头部示例
     *     switch (header) {
     *         case field::content_type:
     *         case field::content_length:
     *         case field::cache_control:
     *         case field::etag:
     *             return true;
     *         case field::connection:
     *         case field::upgrade:
     *         case field::proxy_authenticate:
     *             return false; // 逐跳头部
     *         default:
     *             // 默认视为端到端头部
     *             return true;
     *     }
     * }
     *
     * bool is_security_header(field header) {
     *     switch (header) {
     *         case field::strict_transport_security:
     *         case field::content_security_policy:
     *         case field::x_frame_options:
     *         case field::x_content_type_options:
     *             return true;
     *         default:
     *             return false;
     *     }
     * }
     *
     * // 头部字段名转换示例
     * std::string header_name = "Content-Type";
     * field header = field_from_string(header_name); // 返回 field::content_type
     * std::string result = to_string(field::authorization); // 返回 "Authorization"
     *
     * // 批量头部处理优化示例
     * std::vector<field> headers = parse_header_fields(buffer);
     * std::sort(headers.begin(), headers.end()); // 枚举值排序优化后续处理
     * @endcode
     *
     * @see https://www.iana.org/assignments/message-headers/message-headers.xhtml IANA 头部字段注册表
     * @see RFC 7230-7235 HTTP/1.1 标准
     * @see RFC 7540 HTTP/2 标准
     */
    enum class field : unsigned short
    {
        /**
         * @brief unknown
         * @note 未知或未识别的头部字段
         */
        unknown = 0,

        /**
         * @brief a_im
         * @note A-IM 头，用于指示可接受的实例操作（RFC 4229）
         */
        a_im,

        /**
         * @brief accept
         * @note Accept 头，客户端可接受的媒体类型
         */
        accept,

        /**
         * @brief accept_additions
         * @note Accept-Additions 头，扩展 Accept（RFC 4229）
         */
        accept_additions,

        /**
         * @brief accept_charset
         * @note Accept-Charset 头，客户端可接受的字符集
         */
        accept_charset,

        /**
         * @brief accept_datetime
         * @note Accept-Datetime 头，用于内容协商的时间戳（RFC 7089）
         */
        accept_datetime,

        /**
         * @brief accept_encoding
         * @note Accept-Encoding 头，客户端可接受的内容编码
         */
        accept_encoding,

        /**
         * @brief accept_features
         * @note Accept-Features 头，用于特征协商（RFC 4229）
         */
        accept_features,

        /**
         * @brief accept_language
         * @note Accept-Language 头，客户端可接受的语言
         */
        accept_language,

        /**
         * @brief accept_patch
         * @note Accept-Patch 头，服务器接受的补丁格式（RFC 5789）
         */
        accept_patch,

        /**
         * @brief accept_post
         * @note Accept-Post 头，服务器接受的 POST 内容类型（RFC 5992）
         */
        accept_post,

        /**
         * @brief accept_ranges
         * @note Accept-Ranges 头，服务器支持的范围请求单位
         */
        accept_ranges,

        /**
         * @brief access_control
         * @note Access-Control 头，WebDAV 访问控制扩展
         */
        access_control,

        /**
         * @brief access_control_allow_credentials
         * @note Access-Control-Allow-Credentials 头，CORS 是否允许携带凭据
         */
        access_control_allow_credentials,

        /**
         * @brief access_control_allow_headers
         * @note Access-Control-Allow-Headers 头，CORS 允许的请求头
         */
        access_control_allow_headers,

        /**
         * @brief access_control_allow_methods
         * @note Access-Control-Allow-Methods 头，CORS 允许的请求方法
         */
        access_control_allow_methods,

        /**
         * @brief access_control_allow_origin
         * @note Access-Control-Allow-Origin 头，CORS 允许的来源
         */
        access_control_allow_origin,

        /**
         * @brief access_control_expose_headers
         * @note Access-Control-Expose-Headers 头，CORS 允许前端读取的响应头
         */
        access_control_expose_headers,

        /**
         * @brief access_control_max_age
         * @note Access-Control-Max-Age 头，CORS 预检结果缓存时长
         */
        access_control_max_age,

        /**
         * @brief access_control_request_headers
         * @note Access-Control-Request-Headers 头，预检请求中实际发送的头列表
         */
        access_control_request_headers,

        /**
         * @brief access_control_request_method
         * @note Access-Control-Request-Method 头，预检请求中实际发送的方法
         */
        access_control_request_method,

        /**
         * @brief age
         * @note Age 头，响应在缓存中停留的秒数
         */
        age,

        /**
         * @brief allow
         * @note Allow 头，资源允许的 HTTP 方法集合
         */
        allow,

        /**
         * @brief alpn
         * @note ALPN 头，应用层协议协商（TLS 扩展）
         */
        alpn,

        /**
         * @brief also_control
         * @note Also-Control 头，邮件/消息控制扩展
         */
        also_control,

        /**
         * @brief alt_svc
         * @note Alt-Svc 头，服务器声明备用服务（RFC 7838）
         */
        alt_svc,

        /**
         * @brief alt_used
         * @note Alt-Used 头，客户端声明实际使用的备用服务（RFC 7838）
         */
        alt_used,

        /**
         * @brief alternate_recipient
         * @note Alternate-Recipient 头，邮件传输备用接收者
         */
        alternate_recipient,

        /**
         * @brief alternates
         * @note Alternates 头，内容协商可选列表（RFC 4229）
         */
        alternates,

        /**
         * @brief apparently_to
         * @note Apparently-To 头，遗留邮件头
         */
        apparently_to,

        /**
         * @brief apply_to_redirect_ref
         * @note Apply-To-Redirect-Ref 头，WebDAV 重定向引用
         */
        apply_to_redirect_ref,

        /**
         * @brief approved
         * @note Approved 头，新闻组 邮件审批标记
         */
        approved,

        /**
         * @brief archive
         * @note Archive 头，档案标识
         */
        archive,

        /**
         * @brief archived_at
         * @note Archived-At 头，消息归档 URL（RFC 5064）
         */
        archived_at,

        /**
         * @brief article_names
         * @note Article-Names 头，新闻组文章名称
         */
        article_names,

        /**
         * @brief article_updates
         * @note Article-Updates 头，新闻组文章更新标记
         */
        article_updates,

        /**
         * @brief authentication_control
         * @note Authentication-Control 头，认证控制指令
         */
        authentication_control,

        /**
         * @brief authentication_info
         * @note Authentication-Info 头，认证结果信息（RFC 7615）
         */
        authentication_info,

        /**
         * @brief authentication_results
         * @note Authentication-Results 头，邮件认证结果（RFC 8601）
         */
        authentication_results,

        /**
         * @brief authorization
         * @note Authorization 头，客户端身份凭证
         */
        authorization,

        /**
         * @brief auto_submitted
         * @note Auto-Submitted 头，自动提交标识（RFC 3834）
         */
        auto_submitted,

        /**
         * @brief autoforwarded
         * @note Autoforwarded 头，自动转发标记
         */
        autoforwarded,

        /**
         * @brief autosubmitted
         * @note Autosubmitted 头，同 Auto-Submitted（兼容）
         */
        autosubmitted,

        /**
         * @brief base
         * @note Base 头，基准 URI（遗留）
         */
        base,

        /**
         * @brief bcc
         * @note Bcc 头，密送地址
         */
        bcc,

        /**
         * @brief body
         * @note Body 头，消息体标识（遗留）
         */
        body,

        /**
         * @brief c_ext
         * @note C-Ext 头，缓存控制扩展
         */
        c_ext,

        /**
         * @brief c_man
         * @note C-Man 头，缓存管理指令
         */
        c_man,

        /**
         * @brief c_opt
         * @note C-Opt 头，缓存选项
         */
        c_opt,

        /**
         * @brief c_pep
         * @note C-PEP 头，PEP 缓存扩展
         */
        c_pep,

        /**
         * @brief c_pep_info
         * @note C-PEP-Info 头，PEP 缓存信息
         */
        c_pep_info,

        /**
         * @brief cache_control
         * @note Cache-Control 头，缓存指令（RFC 7234）
         */
        cache_control,

        /**
         * @brief caldav_timezones
         * @note CalDAV-Timezones 头，CalDAV 时区数据
         */
        caldav_timezones,

        /**
         * @brief cancel_key
         * @note Cancel-Key 头，新闻组取消密钥
         */
        cancel_key,

        /**
         * @brief cancel_lock
         * @note Cancel-Lock 头，新闻组取消锁
         */
        cancel_lock,

        /**
         * @brief cc
         * @note Cc 头，抄送地址
         */
        cc,

        /**
         * @brief close
         * @note Close 头，连接关闭标记（遗留）
         */
        close,

        /**
         * @brief comments
         * @note Comments 头，附加说明
         */
        comments,

        /**
         * @brief compliance
         * @note Compliance 头，合规性声明
         */
        compliance,

        /**
         * @brief connection
         * @note Connection 头，连接管理（keep-alive / close）
         */
        connection,

        /**
         * @brief content_alternative
         * @note Content-Alternative 头，备选内容
         */
        content_alternative,

        /**
         * @brief content_base
         * @note Content-Base 头，内容基准 URI（遗留）
         */
        content_base,

        /**
         * @brief content_description
         * @note Content-Description 头，内容描述
         */
        content_description,

        /**
         * @brief content_disposition
         * @note Content-Disposition 头，内容展示方式（RFC 6266）
         */
        content_disposition,

        /**
         * @brief content_duration
         * @note Content-Duration 头，内容持续时间
         */
        content_duration,

        /**
         * @brief content_encoding
         * @note Content-Encoding 头，内容编码（gzip 等）
         */
        content_encoding,

        /**
         * @brief content_features
         * @note Content-Features 头，内容特征标记
         */
        content_features,

        /**
         * @brief content_id
         * @note Content-ID 头，内容标识（MIME）
         */
        content_id,

        /**
         * @brief content_identifier
         * @note Content-Identifier 头，内容标识符
         */
        content_identifier,

        /**
         * @brief content_language
         * @note Content-Language 头，内容语言
         */
        content_language,

        /**
         * @brief content_length
         * @note Content-Length 头，内容长度（字节）
         */
        content_length,

        /**
         * @brief content_location
         * @note Content-Location 头，内容实际位置
         */
        content_location,

        /**
         * @brief content_md5
         * @note Content-MD5 头，内容 MD5 摘要（已废弃）
         */
        content_md5,

        /**
         * @brief content_range
         * @note Content-Range 头，内容范围（分块传输）
         */
        content_range,

        /**
         * @brief content_return
         * @note Content-Return 头，内容返回选项
         */
        content_return,

        /**
         * @brief content_script_type
         * @note Content-Script-Type 头，默认脚本类型
         */
        content_script_type,

        /**
         * @brief content_style_type
         * @note Content-Style-Type 头，默认样式类型
         */
        content_style_type,

        /**
         * @brief content_transfer_encoding
         * @note Content-Transfer-Encoding 头，MIME 传输编码
         */
        content_transfer_encoding,

        /**
         * @brief content_type
         * @note Content-Type 头，内容媒体类型
         */
        content_type,

        /**
         * @brief content_version
         * @note Content-Version 头，内容版本
         */
        content_version,

        /**
         * @brief control
         * @note Control 头，控制指令（遗留）
         */
        control,

        /**
         * @brief conversion
         * @note Conversion 头，转换标记
         */
        conversion,

        /**
         * @brief conversion_with_loss
         * @note Conversion-With-Loss 头，有损转换标记
         */
        conversion_with_loss,

        /**
         * @brief cookie
         * @note Cookie 头，客户端携带的 Cookie
         */
        cookie,

        /**
         * @brief cookie2
         * @note Cookie2 头，Cookie 协议版本 2（已废弃）
         */
        cookie2,

        /**
         * @brief cost
         * @note Cost 头，传输成本（试验）
         */
        cost,

        /**
         * @brief dasl
         * @note DASL 头，DAV 搜索能力（RFC 5323）
         */
        dasl,

        /**
         * @brief date
         * @note Date 头，消息生成时间
         */
        date,

        /**
         * @brief date_received
         * @note Date-Received 头，接收时间（遗留）
         */
        date_received,

        /**
         * @brief dav
         * @note DAV 头，DAV 版本
         */
        dav,

        /**
         * @brief default_style
         * @note Default-Style 头，默认样式
         */
        default_style,

        /**
         * @brief deferred_delivery
         * @note Deferred-Delivery 头，延迟投递时间
         */
        deferred_delivery,

        /**
         * @brief delivery_date
         * @note Delivery-Date 头，实际投递时间
         */
        delivery_date,

        /**
         * @brief delta_base
         * @note Delta-Base 头，增量编码基准（RFC 3229）
         */
        delta_base,

        /**
         * @brief depth
         * @note Depth 头，WebDAV 深度标记
         */
        depth,

        /**
         * @brief derived_from
         * @note Derived-From 头，派生资源标识
         */
        derived_from,

        /**
         * @brief destination
         * @note Destination 头，WebDAV 目标 URI
         */
        destination,

        /**
         * @brief differential_id
         * @note Differential-ID 头，差分 ID
         */
        differential_id,

        /**
         * @brief digest
         * @note Digest 头，内容摘要（RFC 3230）
         */
        digest,

        /**
         * @brief discarded_x400_ipms_extensions
         * @note Discarded-X400-IPMS-Extensions 头，丢弃的 X400 IPMS 扩展
         */
        discarded_x400_ipms_extensions,

        /**
         * @brief discarded_x400_mts_extensions
         * @note Discarded-X400-MTS-Extensions 头，丢弃的 X400 MTS 扩展
         */
        discarded_x400_mts_extensions,

        /**
         * @brief disclose_recipients
         * @note Disclose-Recipients 头，是否公开收件人
         */
        disclose_recipients,

        /**
         * @brief disposition_notification_options
         * @note Disposition-Notification-Options 头，投递通知选项
         */
        disposition_notification_options,

        /**
         * @brief disposition_notification_to
         * @note Disposition-Notification-To 头，投递通知地址
         */
        disposition_notification_to,

        /**
         * @brief distribution
         * @note Distribution 头，分发范围（新闻组）
         */
        distribution,

        /**
         * @brief dkim_signature
         * @note DKIM-Signature 头，邮件 DKIM 签名
         */
        dkim_signature,

        /**
         * @brief dl_expansion_history
         * @note DL-Expansion-History 头，分发列表扩展历史
         */
        dl_expansion_history,

        /**
         * @brief downgraded_bcc
         * @note Downgraded-Bcc 头，降级密送信息
         */
        downgraded_bcc,

        /**
         * @brief downgraded_cc
         * @note Downgraded-Cc 头，降级抄送信息
         */
        downgraded_cc,

        /**
         * @brief downgraded_disposition_notification_to
         * @note Downgraded-Disposition-Notification-To 头，降级投递通知地址
         */
        downgraded_disposition_notification_to,

        /**
         * @brief downgraded_final_recipient
         * @note Downgraded-Final-Recipient 头，降级最终收件人
         */
        downgraded_final_recipient,

        /**
         * @brief downgraded_from
         * @note Downgraded-From 头，降级发件人信息
         */
        downgraded_from,

        /**
         * @brief downgraded_in_reply_to
         * @note Downgraded-In-Reply-To 头，降级回复标识
         */
        downgraded_in_reply_to,

        /**
         * @brief downgraded_mail_from
         * @note Downgraded-Mail-From 头，降级邮件来源
         */
        downgraded_mail_from,

        /**
         * @brief downgraded_message_id
         * @note Downgraded-Message-ID 头，降级消息 ID
         */
        downgraded_message_id,

        /**
         * @brief downgraded_original_recipient
         * @note Downgraded-Original-Recipient 头，降级原始收件人
         */
        downgraded_original_recipient,

        /**
         * @brief downgraded_rcpt_to
         * @note Downgraded-Rcpt-To 头，降级接收地址
         */
        downgraded_rcpt_to,

        /**
         * @brief downgraded_references
         * @note Downgraded-References 头，降级引用信息
         */
        downgraded_references,

        /**
         * @brief downgraded_reply_to
         * @note Downgraded-Reply-To 头，降级回复地址
         */
        downgraded_reply_to,

        /**
         * @brief downgraded_resent_bcc
         * @note Downgraded-Resent-Bcc 头，降级重发密送
         */
        downgraded_resent_bcc,

        /**
         * @brief downgraded_resent_cc
         * @note Downgraded-Resent-Cc 头，降级重发抄送
         */
        downgraded_resent_cc,

        /**
         * @brief downgraded_resent_from
         * @note Downgraded-Resent-From 头，降级重发来源
         */
        downgraded_resent_from,

        /**
         * @brief downgraded_resent_reply_to
         * @note Downgraded-Resent-Reply-To 头，降级重发回复地址
         */
        downgraded_resent_reply_to,

        /**
         * @brief downgraded_resent_sender
         * @note Downgraded-Resent-Sender 头，降级重发发送者
         */
        downgraded_resent_sender,

        /**
         * @brief downgraded_resent_to
         * @note Downgraded-Resent-To 头，降级重发收件人
         */
        downgraded_resent_to,

        /**
         * @brief downgraded_return_path
         * @note Downgraded-Return-Path 头，降级返回路径
         */
        downgraded_return_path,

        /**
         * @brief downgraded_sender
         * @note Downgraded-Sender 头，降级发送者
         */
        downgraded_sender,

        /**
         * @brief downgraded_to
         * @note Downgraded-To 头，降级收件人
         */
        downgraded_to,

        /**
         * @brief ediint_features
         * @note EDIINT-Features 头，电子数据交换特征
         */
        ediint_features,

        /**
         * @brief eesst_version
         * @note EESST-Version 头，扩展安全服务版本
         */
        eesst_version,

        /**
         * @brief encoding
         * @note Encoding 头，编码标记（遗留）
         */
        encoding,

        /**
         * @brief encrypted
         * @note Encrypted 头，加密标记（遗留）
         */
        encrypted,

        /**
         * @brief errors_to
         * @note Errors-To 头，错误报告地址
         */
        errors_to,

        /**
         * @brief etag
         * @note ETag 头，实体标签（缓存与条件请求）
         */
        etag,

        /**
         * @brief expect
         * @note Expect 头，期望行为（如 100-continue）
         */
        expect,

        /**
         * @brief expires
         * @note Expires 头，过期时间（HTTP/1.0 缓存）
         */
        expires,

        /**
         * @brief expiry_date
         * @note Expiry-Date 头，显式过期日期
         */
        expiry_date,

        /**
         * @brief ext
         * @note Ext 头，扩展标记（遗留）
         */
        ext,

        /**
         * @brief followup_to
         * @note Followup-To 头，后续回复新闻组
         */
        followup_to,

        /**
         * @brief forwarded
         * @note Forwarded 头，代理链路信息（RFC 7239）
         */
        forwarded,

        /**
         * @brief from
         * @note From 头，请求发起者邮箱或标识
         */
        from,

        /**
         * @brief generate_delivery_report
         * @note Generate-Delivery-Report 头，生成投递报告
         */
        generate_delivery_report,

        /**
         * @brief getprofile
         * @note GetProfile 头，获取配置文件
         */
        getprofile,

        /**
         * @brief hobareg
         * @note Hobareg 头，HOBA 注册扩展
         */
        hobareg,

        /**
         * @brief host
         * @note Host 头，请求目标主机与端口
         */
        host,

        /**
         * @brief http2_settings
         * @note HTTP2-Settings 头，HTTP/2 设置帧（升级流程）
         */
        http2_settings,

        /**
         * @brief if_
         * @note If 头，WebDAV 条件判断
         */
        if_,

        /**
         * @brief if_match
         * @note If-Match 头，条件请求：ETag 需匹配
         */
        if_match,

        /**
         * @brief if_modified_since
         * @note If-Modified-Since 头，条件请求：修改时间需晚于该时间
         */
        if_modified_since,

        /**
         * @brief if_none_match
         * @note If-None-Match 头，条件请求：ETag 需不匹配
         */
        if_none_match,

        /**
         * @brief if_range
         * @note If-Range 头，范围请求条件：ETag/日期需匹配
         */
        if_range,

        /**
         * @brief if_schedule_tag_match
         * @note If-Schedule-Tag-Match 头，CalDAV 计划标签条件
         */
        if_schedule_tag_match,

        /**
         * @brief if_unmodified_since
         * @note If-Unmodified-Since 头，条件请求：修改时间需早于该时间
         */
        if_unmodified_since,

        /**
         * @brief im
         * @note IM 头，实例操作（RFC 3229）
         */
        im,

        /**
         * @brief importance
         * @note Importance 头，重要性级别
         */
        importance,

        /**
         * @brief in_reply_to
         * @note In-Reply-To 头，回复消息标识
         */
        in_reply_to,

        /**
         * @brief incomplete_copy
         * @note Incomplete-Copy 头，未完成复制标记
         */
        incomplete_copy,

        /**
         * @brief injection_date
         * @note Injection-Date 头，注入时间
         */
        injection_date,

        /**
         * @brief injection_info
         * @note Injection-Info 头，注入信息
         */
        injection_info,

        /**
         * @brief jabber_id
         * @note Jabber-ID 头，XMPP 标识（RFC 7395）
         */
        jabber_id,

        /**
         * @brief keep_alive
         * @note Keep-Alive 头，HTTP/1.0 长连接参数
         */
        keep_alive,

        /**
         * @brief keywords
         * @note Keywords 头，关键词列表
         */
        keywords,

        /**
         * @brief label
         * @note Label 头，内容标签（遗留）
         */
        label,

        /**
         * @brief language
         * @note Language 头，语言标识（遗留）
         */
        language,

        /**
         * @brief last_modified
         * @note Last-Modified 头，资源最后修改时间
         */
        last_modified,

        /**
         * @brief latest_delivery_time
         * @note Latest-Delivery-Time 头，最迟投递时间
         */
        latest_delivery_time,

        /**
         * @brief lines
         * @note Lines 头，行数统计
         */
        lines,

        /**
         * @brief link
         * @note Link 头，资源关联关系（RFC 5988）
         */
        link,

        /**
         * @brief list_archive
         * @note List-Archive 头，邮件列表归档地址
         */
        list_archive,

        /**
         * @brief list_help
         * @note List-Help 头，邮件列表帮助地址
         */
        list_help,

        /**
         * @brief list_id
         * @note List-ID 头，邮件列表标识
         */
        list_id,

        /**
         * @brief list_owner
         * @note List-Owner 头，邮件列表所有者地址
         */
        list_owner,

        /**
         * @brief list_post
         * @note List-Post 头，邮件列表 posting 地址
         */
        list_post,

        /**
         * @brief list_subscribe
         * @note List-Subscribe 头，邮件列表订阅地址
         */
        list_subscribe,

        /**
         * @brief list_unsubscribe
         * @note List-Unsubscribe 头，邮件列表退订地址
         */
        list_unsubscribe,

        /**
         * @brief list_unsubscribe_post
         * @note List-Unsubscribe-Post 头，退订 POST 表单（RFC 8058）
         */
        list_unsubscribe_post,

        /**
         * @brief location
         * @note Location 头，重定向或新资源地址
         */
        location,

        /**
         * @brief lock_token
         * @note Lock-Token 头，WebDAV 锁定令牌
         */
        lock_token,

        /**
         * @brief man
         * @note Man 头，缓存管理指令（遗留）
         */
        man,

        /**
         * @brief max_forwards
         * @note Max-Forwards 头，最大转发次数（TRACE/OPTIONS）
         */
        max_forwards,

        /**
         * @brief memento_datetime
         * @note Memento-Datetime 头，Memento 归档时间（RFC 7089）
         */
        memento_datetime,

        /**
         * @brief message_context
         * @note Message-Context 头，消息上下文
         */
        message_context,

        /**
         * @brief message_id
         * @note Message-ID 头，消息唯一标识
         */
        message_id,

        /**
         * @brief message_type
         * @note Message-Type 头，消息类型
         */
        message_type,

        /**
         * @brief meter
         * @note Meter 头，计量信息
         */
        meter,

        /**
         * @brief method_check
         * @note Method-Check 头，方法检查（遗留）
         */
        method_check,

        /**
         * @brief method_check_expires
         * @note Method-Check-Expires 头，方法检查过期时间
         */
        method_check_expires,

        /**
         * @brief mime_version
         * @note MIME-Version 头，MIME 版本
         */
        mime_version,

        /**
         * @brief mmhs_acp127_message_identifier
         * @note MMHS-ACP127-Message-Identifier 头，军用消息标识
         */
        mmhs_acp127_message_identifier,

        /**
         * @brief mmhs_authorizing_users
         * @note MMHS-Authorizing-Users 头，授权用户列表
         */
        mmhs_authorizing_users,

        /**
         * @brief mmhs_codress_message_indicator
         * @note MMHS-Codress-Message-Indicator 头，Codress 消息指示
         */
        mmhs_codress_message_indicator,

        /**
         * @brief mmhs_copy_precedence
         * @note MMHS-Copy-Precedence 头，副本优先级
         */
        mmhs_copy_precedence,

        /**
         * @brief mmhs_exempted_address
         * @note MMHS-Exempted-Address 头，豁免地址
         */
        mmhs_exempted_address,

        /**
         * @brief mmhs_extended_authorisation_info
         * @note MMHS-Extended-Authorisation-Info 头，扩展授权信息
         */
        mmhs_extended_authorisation_info,

        /**
         * @brief mmhs_handling_instructions
         * @note MMHS-Handling-Instructions 头，处理指令
         */
        mmhs_handling_instructions,

        /**
         * @brief mmhs_message_instructions
         * @note MMHS-Message-Instructions 头，消息处理指令
         */
        mmhs_message_instructions,

        /**
         * @brief mmhs_message_type
         * @note MMHS-Message-Type 头，军用消息类型
         */
        mmhs_message_type,

        /**
         * @brief mmhs_originator_plad
         * @note MMHS-Originator-PLAD 头，发起者 PLAD
         */
        mmhs_originator_plad,

        /**
         * @brief mmhs_originator_reference
         * @note MMHS-Originator-Reference 头，发起者引用
         */
        mmhs_originator_reference,

        /**
         * @brief mmhs_other_recipients_indicator_cc
         * @note MMHS-Other-Recipients-Indicator-Cc 头，其他抄送指示
         */
        mmhs_other_recipients_indicator_cc,

        /**
         * @brief mmhs_other_recipients_indicator_to
         * @note MMHS-Other-Recipients-Indicator-To 头，其他收件人指示
         */
        mmhs_other_recipients_indicator_to,

        /**
         * @brief mmhs_primary_precedence
         * @note MMHS-Primary-Precedence 头，主优先级
         */
        mmhs_primary_precedence,

        /**
         * @brief mmhs_subject_indicator_codes
         * @note MMHS-Subject-Indicator-Codes 头，主题指示码
         */
        mmhs_subject_indicator_codes,

        /**
         * @brief mt_priority
         * @note MT-Priority 头，消息传输优先级（RFC 6758）
         */
        mt_priority,

        /**
         * @brief negotiate
         * @note Negotiate 头，内容协商（遗留）
         */
        negotiate,

        /**
         * @brief newsgroups
         * @note Newsgroups 头，新闻组列表
         */
        newsgroups,

        /**
         * @brief nntp_posting_date
         * @note NNTP-Posting-Date 头，NNTP 发布时间
         */
        nntp_posting_date,

        /**
         * @brief nntp_posting_host
         * @note NNTP-Posting-Host 头，NNTP 发布主机
         */
        nntp_posting_host,

        /**
         * @brief non_compliance
         * @note Non-Compliance 头，不合规标记
         */
        non_compliance,

        /**
         * @brief obsoletes
         * @note Obsoletes 头，废弃标识
         */
        obsoletes,

        /**
         * @brief opt
         * @note Opt 头，选项（遗留）
         */
        opt,

        /**
         * @brief optional
         * @note Optional 头，可选标记
         */
        optional,

        /**
         * @brief optional_www_authenticate
         * @note Optional-WWW-Authenticate 头，可选认证方式
         */
        optional_www_authenticate,

        /**
         * @brief ordering_type
         * @note Ordering-Type 头，排序类型
         */
        ordering_type,

        /**
         * @brief organization
         * @note Organization 头，组织名称
         */
        organization,

        /**
         * @brief origin
         * @note Origin 头，跨域请求来源（CORS）
         */
        origin,

        /**
         * @brief original_encoded_information_types
         * @note Original-Encoded-Information-Types 头，原始编码信息类型
         */
        original_encoded_information_types,

        /**
         * @brief original_from
         * @note Original-From 头，原始发件人
         */
        original_from,

        /**
         * @brief original_message_id
         * @note Original-Message-ID 头，原始消息 ID
         */
        original_message_id,

        /**
         * @brief original_recipient
         * @note Original-Recipient 头，原始收件人
         */
        original_recipient,

        /**
         * @brief original_sender
         * @note Original-Sender 头，原始发送者
         */
        original_sender,

        /**
         * @brief original_subject
         * @note Original-Subject 头，原始主题
         */
        original_subject,

        /**
         * @brief originator_return_address
         * @note Originator-Return-Address 头，发起者返回地址
         */
        originator_return_address,

        /**
         * @brief overwrite
         * @note Overwrite 头，WebDAV 覆盖标记
         */
        overwrite,

        /**
         * @brief p3p
         * @note P3P 头，隐私策略（W3C）
         */
        p3p,

        /**
         * @brief path
         * @note Path 头，路由路径（电子邮件）
         */
        path,

        /**
         * @brief pep
         * @note PEP 头，策略扩展协议
         */
        pep,

        /**
         * @brief pep_info
         * @note PEP-Info 头，PEP 信息
         */
        pep_info,

        /**
         * @brief pics_label
         * @note PICS-Label 头，内容标签（已废弃）
         */
        pics_label,

        /**
         * @brief position
         * @note Position 头，位置信息
         */
        position,

        /**
         * @brief posting_version
         * @note Posting-Version 头，发布版本
         */
        posting_version,

        /**
         * @brief pragma
         * @note Pragma 头，实现相关指令（HTTP/1.0）
         */
        pragma,

        /**
         * @brief prefer
         * @note Prefer 头，客户端偏好（RFC 7240）
         */
        prefer,

        /**
         * @brief preference_applied
         * @note Preference-Applied 头，已应用的偏好
         */
        preference_applied,

        /**
         * @brief prevent_nondelivery_report
         * @note Prevent-NonDelivery-Report 头，阻止未投递报告
         */
        prevent_nondelivery_report,

        /**
         * @brief priority
         * @note Priority 头，优先级（邮件/HTTP）
         */
        priority,

        /**
         * @brief privicon
         * @note Privicon 头，隐私图标（试验）
         */
        privicon,

        /**
         * @brief profileobject
         * @note ProfileObject 头，配置文件对象
         */
        profileobject,

        /**
         * @brief protocol
         * @note Protocol 头，协议信息
         */
        protocol,

        /**
         * @brief protocol_info
         * @note Protocol-Info 头，协议信息（遗留）
         */
        protocol_info,

        /**
         * @brief protocol_query
         * @note Protocol-Query 头，协议查询
         */
        protocol_query,

        /**
         * @brief protocol_request
         * @note Protocol-Request 头，协议请求
         */
        protocol_request,

        /**
         * @brief proxy_authenticate
         * @note Proxy-Authenticate 头，代理认证要求
         */
        proxy_authenticate,

        /**
         * @brief proxy_authentication_info
         * @note Proxy-Authentication-Info 头，代理认证信息
         */
        proxy_authentication_info,

        /**
         * @brief proxy_authorization
         * @note Proxy-Authorization 头，代理认证凭证
         */
        proxy_authorization,

        /**
         * @brief proxy_connection
         * @note Proxy-Connection 头，代理连接（遗留）
         */
        proxy_connection,

        /**
         * @brief proxy_features
         * @note Proxy-Features 头，代理特性
         */
        proxy_features,

        /**
         * @brief proxy_instruction
         * @note Proxy-Instruction 头，代理指令
         */
        proxy_instruction,

        /**
         * @brief public_
         * @note Public 头，公开方法列表（遗留）
         */
        public_,

        /**
         * @brief public_key_pins
         * @note Public-Key-Pins 头，公钥固定（RFC 7469）
         */
        public_key_pins,

        /**
         * @brief public_key_pins_report_only
         * @note Public-Key-Pins-Report-Only 头，公钥固定仅报告
         */
        public_key_pins_report_only,

        /**
         * @brief range
         * @note Range 头，请求字节范围
         */
        range,

        /**
         * @brief received
         * @note Received 头，邮件传输路径信息
         */
        received,

        /**
         * @brief received_spf
         * @note Received-SPF 头，SPF 接收结果
         */
        received_spf,

        /**
         * @brief redirect_ref
         * @note Redirect-Ref 头，WebDAV 重定向引用
         */
        redirect_ref,

        /**
         * @brief references
         * @note References 头，引用消息列表
         */
        references,

        /**
         * @brief referer
         * @note Referer 头，请求来源页面地址
         */
        referer,

        /**
         * @brief referer_root
         * @note Referer-Root 头，来源根路径（试验）
         */
        referer_root,

        /**
         * @brief relay_version
         * @note Relay-Version 头，中继版本
         */
        relay_version,

        /**
         * @brief reply_by
         * @note Reply-By 头，回复截止时间
         */
        reply_by,

        /**
         * @brief reply_to
         * @note Reply-To 头，回复地址（邮件）
         */
        reply_to,

        /**
         * @brief require_recipient_valid_since
         * @note Require-Recipient-Valid-Since 头，收件人有效期要求
         */
        require_recipient_valid_since,

        /**
         * @brief resent_bcc
         * @note Resent-Bcc 头，重发密送
         */
        resent_bcc,

        /**
         * @brief resent_cc
         * @note Resent-Cc 头，重发抄送
         */
        resent_cc,

        /**
         * @brief resent_date
         * @note Resent-Date 头，重发日期
         */
        resent_date,

        /**
         * @brief resent_from
         * @note Resent-From 头，重发来源
         */
        resent_from,

        /**
         * @brief resent_message_id
         * @note Resent-Message-ID 头，重发消息 ID
         */
        resent_message_id,

        /**
         * @brief resent_reply_to
         * @note Resent-Reply-To 头，重发回复地址
         */
        resent_reply_to,

        /**
         * @brief resent_sender
         * @note Resent-Sender 头，重发发送者
         */
        resent_sender,

        /**
         * @brief resent_to
         * @note Resent-To 头，重发收件人
         */
        resent_to,

        /**
         * @brief resolution_hint
         * @note Resolution-Hint 头，解析提示
         */
        resolution_hint,

        /**
         * @brief resolver_location
         * @note Resolver-Location 头，解析器位置
         */
        resolver_location,

        /**
         * @brief retry_after
         * @note Retry-After 头，稍后重试时间（秒或日期）
         */
        retry_after,

        /**
         * @brief return_path
         * @note Return-Path 头，退回路径（邮件）
         */
        return_path,

        /**
         * @brief safe
         * @note Safe 头，安全标记（试验）
         */
        safe,

        /**
         * @brief schedule_reply
         * @note Schedule-Reply 头，CalDAV 计划回复
         */
        schedule_reply,

        /**
         * @brief schedule_tag
         * @note Schedule-Tag 头，CalDAV 计划标签
         */
        schedule_tag,

        /**
         * @brief sec_fetch_dest
         * @note Sec-Fetch-Dest 头，Fetch 元数据：目标
         */
        sec_fetch_dest,

        /**
         * @brief sec_fetch_mode
         * @note Sec-Fetch-Mode 头，Fetch 元数据：模式
         */
        sec_fetch_mode,

        /**
         * @brief sec_fetch_site
         * @note Sec-Fetch-Site 头，Fetch 元数据：站点关系
         */
        sec_fetch_site,

        /**
         * @brief sec_fetch_user
         * @note Sec-Fetch-User 头，Fetch 元数据：用户触发
         */
        sec_fetch_user,

        /**
         * @brief sec_websocket_accept
         * @note Sec-WebSocket-Accept 头，WebSocket 握手响应密钥
         */
        sec_websocket_accept,

        /**
         * @brief sec_websocket_extensions
         * @note Sec-WebSocket-Extensions 头，WebSocket 扩展列表
         */
        sec_websocket_extensions,

        /**
         * @brief sec_websocket_key
         * @note Sec-WebSocket-Key 头，WebSocket 握手请求密钥
         */
        sec_websocket_key,

        /**
         * @brief sec_websocket_protocol
         * @note Sec-WebSocket-Protocol 头，WebSocket 子协议
         */
        sec_websocket_protocol,

        /**
         * @brief sec_websocket_version
         * @note Sec-WebSocket-Version 头，WebSocket 协议版本
         */
        sec_websocket_version,

        /**
         * @brief security_scheme
         * @note Security-Scheme 头，安全方案（试验）
         */
        security_scheme,

        /**
         * @brief see_also
         * @note See-Also 头，参考链接
         */
        see_also,

        /**
         * @brief sender
         * @note Sender 头，实际发送者地址
         */
        sender,

        /**
         * @brief sensitivity
         * @note Sensitivity 头，敏感度标记
         */
        sensitivity,

        /**
         * @brief server
         * @note Server 头，服务器软件信息
         */
        server,

        /**
         * @brief set_cookie
         * @note Set-Cookie 头，服务器下发 Cookie
         */
        set_cookie,

        /**
         * @brief set_cookie2
         * @note Set-Cookie2 头，Cookie2 版本（已废弃）
         */
        set_cookie2,

        /**
         * @brief setprofile
         * @note SetProfile 头，设置配置文件
         */
        setprofile,

        /**
         * @brief sio_label
         * @note SIO-Label 头，安全标签（试验）
         */
        sio_label,

        /**
         * @brief sio_label_history
         * @note SIO-Label-History 头，安全标签历史
         */
        sio_label_history,

        /**
         * @brief slug
         * @note Slug 头，AtomPub 资源简短名称
         */
        slug,

        /**
         * @brief soapaction
         * @note SOAPAction 头，SOAP 动作（RFC 3902）
         */
        soapaction,

        /**
         * @brief solicitation
         * @note Solicitation 头，征集标记
         */
        solicitation,

        /**
         * @brief status_uri
         * @note Status-URI 头，状态 URI
         */
        status_uri,

        /**
         * @brief strict_transport_security
         * @note Strict-Transport-Security 头，强制 HTTPS（HSTS）
         */
        strict_transport_security,

        /**
         * @brief subject
         * @note Subject 头，主题/标题
         */
        subject,

        /**
         * @brief subok
         * @note SubOK 头，订阅确认
         */
        subok,

        /**
         * @brief subst
         * @note Subst 头，替换标记
         */
        subst,

        /**
         * @brief summary
         * @note Summary 头，摘要信息
         */
        summary,

        /**
         * @brief supersedes
         * @note Supersedes 头，取代标识
         */
        supersedes,

        /**
         * @brief surrogate_capability
         * @note Surrogate-Capability 头，代理能力声明
         */
        surrogate_capability,

        /**
         * @brief surrogate_control
         * @note Surrogate-Control 头，代理控制指令
         */
        surrogate_control,

        /**
         * @brief tcn
         * @note TCN 头，透明内容协商
         */
        tcn,

        /**
         * @brief te
         * @note TE 头，传输编码容忍度
         */
        te,

        /**
         * @brief timeout
         * @note Timeout 头，WebDAV 锁定超时
         */
        timeout,

        /**
         * @brief title
         * @note Title 头，标题（遗留）
         */
        title,

        /**
         * @brief to
         * @note To 头，收件人地址
         */
        to,

        /**
         * @brief topic
         * @note Topic 头，主题关键词
         */
        topic,

        /**
         * @brief trailer
         * @note Trailer 头，分块传输尾部字段预告
         */
        trailer,

        /**
         * @brief transfer_encoding
         * @note Transfer-Encoding 头，传输编码（chunked 等）
         */
        transfer_encoding,

        /**
         * @brief ttl
         * @note TTL 头，生存时间（秒）
         */
        ttl,

        /**
         * @brief ua_color
         * @note UA-Color 头，客户端颜色能力
         */
        ua_color,

        /**
         * @brief ua_media
         * @note UA-Media 头，客户端媒体能力
         */
        ua_media,

        /**
         * @brief ua_pixels
         * @note UA-Pixels 头，客户端像素能力
         */
        ua_pixels,

        /**
         * @brief ua_resolution
         * @note UA-Resolution 头，客户端分辨率
         */
        ua_resolution,

        /**
         * @brief ua_windowpixels
         * @note UA-Windowpixels 头，客户端窗口像素
         */
        ua_windowpixels,

        /**
         * @brief upgrade
         * @note Upgrade 头，协议升级请求
         */
        upgrade,

        /**
         * @brief urgency
         * @note Urgency 头，紧急程度
         */
        urgency,

        /**
         * @brief uri
         * @note URI 头，统一资源标识（遗留）
         */
        uri,

        /**
         * @brief user_agent
         * @note User-Agent 头，客户端软件标识
         */
        user_agent,

        /**
         * @brief variant_vary
         * @note Variant-Vary 头，变体变化标记
         */
        variant_vary,

        /**
         * @brief vary
         * @note Vary 头，缓存键变化字段列表
         */
        vary,

        /**
         * @brief vbr_info
         * @note VBR-Info 头，可变比特率信息
         */
        vbr_info,

        /**
         * @brief version
         * @note Version 头，版本标识（遗留）
         */
        version,

        /**
         * @brief via
         * @note Via 头，代理/网关路径
         */
        via,

        /**
         * @brief want_digest
         * @note Want-Digest 头，期望摘要算法（RFC 3230）
         */
        want_digest,

        /**
         * @brief warning
         * @note Warning 头，警告信息（RFC 7234）
         */
        warning,

        /**
         * @brief www_authenticate
         * @note WWW-Authenticate 头，服务器认证质询
         */
        www_authenticate,

        /**
         * @brief x_archived_at
         * @note X-Archived-At 头，归档地址（非标准）
         */
        x_archived_at,

        /**
         * @brief x_device_accept
         * @note X-Device-Accept 头，设备可接受类型
         */
        x_device_accept,

        /**
         * @brief x_device_accept_charset
         * @note X-Device-Accept-Charset 头，设备可接受字符集
         */
        x_device_accept_charset,

        /**
         * @brief x_device_accept_encoding
         * @note X-Device-Accept-Encoding 头，设备可接受编码
         */
        x_device_accept_encoding,

        /**
         * @brief x_device_accept_language
         * @note X-Device-Accept-Language 头，设备可接受语言
         */
        x_device_accept_language,

        /**
         * @brief x_device_user_agent
         * @note X-Device-User-Agent 头，设备用户代理
         */
        x_device_user_agent,

        /**
         * @brief x_frame_options
         * @note X-Frame-Options 头，框架嵌入限制
         */
        x_frame_options,

        /**
         * @brief x_mittente
         * @note X-Mittente 头，发件人（非标准）
         */
        x_mittente,

        /**
         * @brief x_pgp_sig
         * @note X-PGP-Sig 头，PGP 签名
         */
        x_pgp_sig,

        /**
         * @brief x_ricevuta
         * @note X-Ricevuta 头，接收确认（非标准）
         */
        x_ricevuta,

        /**
         * @brief x_riferimento_message_id
         * @note X-Riferimento-Message-ID 头，引用消息 ID（非标准）
         */
        x_riferimento_message_id,

        /**
         * @brief x_tiporicevuta
         * @note X-TipoRicevuta 头，接收类型（非标准）
         */
        x_tiporicevuta,

        /**
         * @brief x_trasporto
         * @note X-Trasporto 头，传输方式（非标准）
         */
        x_trasporto,

        /**
         * @brief x_verificasicurezza
         * @note X-VerificaSicurezza 头，安全验证（非标准）
         */
        x_verificasicurezza,

        /**
         * @brief x400_content_identifier
         * @note X400-Content-Identifier 头，X400 内容标识
         */
        x400_content_identifier,

        /**
         * @brief x400_content_return
         * @note X400-Content-Return 头，X400 内容返回
         */
        x400_content_return,

        /**
         * @brief x400_content_type
         * @note X400-Content-Type 头，X400 内容类型
         */
        x400_content_type,

        /**
         * @brief x400_mts_identifier
         * @note X400-MTS-Identifier 头，X400 传输系统标识
         */
        x400_mts_identifier,

        /**
         * @brief x400_originator
         * @note X400-Originator 头，X400 发起者
         */
        x400_originator,

        /**
         * @brief x400_received
         * @note X400-Received 头，X400 接收信息
         */
        x400_received,

        /**
         * @brief x400_recipients
         * @note X400-Recipients 头，X400 收件人信息
         */
        x400_recipients,

        /**
         * @brief x400_trace
         * @note X400-Trace 头，X400 跟踪信息
         */
        x400_trace,

        /**
         * @brief xref
         * @note Xref 头，交叉引用（新闻组）
         */
        xref
    }; // enum class header

} // namespace ngx::protocol::http
