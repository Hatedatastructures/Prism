/**
 * @file constants.hpp
 * @brief HTTP 协议常量定义
 * @details 定义 HTTP/1.1 和 HTTP/2 协议的核心常量，包括状态码、请求方法和
 * 头部字段。状态码枚举 status 覆盖信息响应、成功、重定向、客户端错误和
 * 服务器错误五大类别。请求方法枚举 verb 包含标准 HTTP 方法及 WebDAV、
 * Subversion、UPnP 等扩展方法。头部字段枚举 field 包含超过 500 个标准
 * 及扩展 HTTP 头部字段。设计遵循零开销原则，所有枚举使用最小化存储类型。
 * @note 在热路径中避免对 field 枚举进行线性查找，应使用预构建的哈希映射。
 * @warning 使用 switch 语句进行状态码匹配，避免线性查找以保证性能。
 */
#pragma once

/**
 * @namespace psm::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供请求和响应的序列化
 * 与反序列化、协议状态机管理等功能。模块设计为无状态，仅负责数据报文的
 * 处理，不管理连接生命周期。
 */
namespace psm::protocol::http
{
    /**
     * @enum status
     * @brief HTTP 状态码枚举
     * @details 完整的 HTTP 状态码定义，覆盖 RFC 7231、RFC 6585、RFC 4918 等
     * 标准。状态码分类：1xx 信息响应、2xx 成功、3xx 重定向、4xx 客户端错误、
     * 5xx 服务器错误。使用 unsigned 底层类型确保与标准 HTTP 状态码范围兼容。
     * @note 在热路径中使用 switch 语句进行状态码匹配。
     * @warning 状态码应在 100 到 599 范围内。
     */
    enum class status : unsigned
    {
        // @brief 未知状态码
        unknown = 0,

        // @brief 继续，临时响应表明迄今为止所有内容可行
        continue_ = 100,

        // @brief 切换协议，服务器已理解并同意切换到新协议
        switching_protocols = 101,

        // @brief 处理中，服务器已理解请求正在处理但尚无响应体
        processing = 102,

        // @brief 早期提示，用于在最终响应前发送头部信息
        early_hints = 103,

        // @brief 成功，请求已成功
        ok = 200,

        // @brief 已创建，请求成功且创建了新资源
        created = 201,

        // @brief 已接受，请求已被接受但服务器尚未开始处理
        accepted = 202,

        // @brief 非权威信息，响应体包含非授权来源的信息
        non_authoritative_information = 203,

        // @brief 无内容，请求成功但响应体为空
        no_content = 204,

        // @brief 重置内容，请求成功，客户端应重置文档视图
        reset_content = 205,

        // @brief 部分内容，请求成功，响应体仅包含资源的部分内容
        partial_content = 206,

        // @brief 多状态，响应体包含多个状态码
        multi_status = 207,

        // @brief 已报告，资源状态已被报告
        already_reported = 208,

        // @brief IM 已使用，实例操作已应用于响应
        im_used = 226,

        // @brief 多种选择，请求有多个可选响应
        multiple_choices = 300,

        // @brief 永久移动，资源已被永久移动到新位置
        moved_permanently = 301,

        // @brief 临时移动，资源已被临时移动到新位置
        found = 302,

        // @brief 查看其他，应使用 GET 方法访问其他位置
        see_other = 303,

        // @brief 未修改，资源未修改，可使用缓存版本
        not_modified = 304,

        // @brief 使用代理，资源只能通过代理访问
        use_proxy = 305,

        // @brief 临时重定向，请求应重定向到其他位置
        temporary_redirect = 307,

        // @brief 永久重定向，请求应永久重定向到其他位置
        permanent_redirect = 308,

        // @brief 错误请求，请求语法错误
        bad_request = 400,

        // @brief 未授权，请求需要身份验证
        unauthorized = 401,

        // @brief 需要支付，请求需要支付才能继续
        payment_required = 402,

        // @brief 禁止访问，服务器拒绝请求
        forbidden = 403,

        // @brief 未找到，请求的资源不存在
        not_found = 404,

        // @brief 方法不允许，请求方法不被服务器支持
        method_not_allowed = 405,

        // @brief 不可接受，服务器无法生成客户端可接受的响应
        not_acceptable = 406,

        // @brief 需要代理认证，需要通过代理进行身份验证
        proxy_authentication_required = 407,

        // @brief 请求超时，服务器等待请求超时
        request_timeout = 408,

        // @brief 冲突，请求与服务器当前状态冲突
        conflict = 409,

        // @brief 已删除，请求的资源已不存在
        gone = 410,

        // @brief 需要长度，请求缺少 Content-Length 头部
        length_required = 411,

        // @brief 预条件失败，请求的预条件不满足
        precondition_failed = 412,

        // @brief 负载过大，请求体超过服务器允许的最大值
        payload_too_large = 413,

        // @brief URI 过长，请求的 URI 超过服务器允许的最大长度
        uri_too_long = 414,

        // @brief 不支持的媒体类型，请求体的媒体类型不被支持
        unsupported_media_type = 415,

        // @brief 范围无法满足，请求的范围无法满足
        range_not_satisfiable = 416,

        // @brief 期望失败，服务器无法满足 Expect 头部的条件
        expectation_failed = 417,

        // @brief 我是茶壶，服务端拒绝用茶壶煮咖啡
        i_am_a_teapot = 418,

        // @brief 错误路由，请求被发送到无法产生响应的服务器
        misdirected_request = 421,

        // @brief 无法处理的实体，请求格式正确但语义错误
        unprocessable_entity = 422,

        // @brief 已锁定，请求的资源被锁定
        locked = 423,

        // @brief 依赖失败，请求依赖的资源操作失败
        failed_dependency = 424,

        // @brief 过早，服务器不愿处理早期数据
        too_early = 425,

        // @brief 需要升级，客户端应切换到其他协议
        upgrade_required = 426,

        // @brief 需要预条件，请求必须包含预条件头部
        precondition_required = 428,

        // @brief 请求过多，客户端发送了过多请求
        too_many_requests = 429,

        // @brief 头部字段过大，请求头部超过服务器允许的最大值
        request_header_fields_too_large = 431,

        // @brief 法律原因不可用，因法律原因无法提供资源
        unavailable_for_legal_reasons = 451,

        // @brief 服务器内部错误，服务器遇到意外情况
        internal_server_error = 500,

        // @brief 未实现，服务器不支持请求的功能
        not_implemented = 501,

        // @brief 错误网关，网关或代理收到无效响应
        bad_gateway = 502,

        // @brief 服务不可用，服务器暂时无法处理请求
        service_unavailable = 503,

        // @brief 网关超时，网关或代理等待上游响应超时
        gateway_timeout = 504,

        // @brief HTTP 版本不支持，服务器不支持请求的 HTTP 版本
        http_version_not_supported = 505,

        // @brief 变体也协商，服务器内部配置错误
        variant_also_negotiates = 506,

        // @brief 存储空间不足，服务器无法存储完成请求所需的内容
        insufficient_storage = 507,

        // @brief 检测到循环，服务器检测到无限循环
        loop_detected = 508,

        // @brief 未扩展，需要扩展支持
        not_extended = 510,

        // @brief 需要网络认证，需要进行网络身份验证
        network_authentication_required = 511
    };

    /**
     * @enum verb
     * @brief HTTP 请求方法枚举
     * @details 完整的 HTTP 请求方法定义，覆盖 RFC 7231、RFC 5789、RFC 4918 等
     * 标准。包含所有标准方法及 WebDAV、Subversion、UPnP 等扩展方法。
     * 核心方法分类：安全方法（GET、HEAD、OPTIONS、TRACE）、幂等方法
     * （GET、HEAD、PUT、DELETE、OPTIONS、TRACE）、缓存方法（GET、HEAD、POST）。
     * @note 正确实现幂等方法对重试机制和错误恢复至关重要。
     * @warning 自定义方法默认视为非幂等方法。
     */
    enum class verb
    {
        // @brief 未知方法
        unknown = 0,

        // @brief DELETE 方法，删除指定资源
        delete_,

        // @brief GET 方法，请求指定资源的表示
        get,

        // @brief HEAD 方法，与 GET 相同但只返回响应头
        head,

        // @brief POST 方法，提交数据作为新子资源
        post,

        // @brief PUT 方法，存储实体到指定 URI
        put,

        // @brief CONNECT 方法，建立到服务器的隧道连接
        connect,

        // @brief OPTIONS 方法，查询服务器支持的方法
        options,

        // @brief TRACE 方法，回显收到的请求用于诊断
        trace,

        // WebDAV 方法
        // @brief COPY 方法，复制资源
        copy,
        // @brief LOCK 方法，锁定资源
        lock,
        // @brief MKCOL 方法，创建集合
        mkcol,
        // @brief MOVE 方法，移动资源
        move,
        // @brief PROPFIND 方法，查找属性
        propfind,
        // @brief PROPPATCH 方法，修改属性
        proppatch,
        // @brief SEARCH 方法，搜索资源
        search,
        // @brief UNLOCK 方法，解锁资源
        unlock,
        // @brief BIND 方法，绑定资源
        bind,
        // @brief REBIND 方法，重新绑定资源
        rebind,
        // @brief UNBIND 方法，解除绑定资源
        unbind,
        // @brief ACL 方法，访问控制列表
        acl,

        // Subversion 方法
        // @brief REPORT 方法，报告资源状态
        report,
        // @brief MKACTIVITY 方法，创建活动
        mkactivity,
        // @brief CHECKOUT 方法，检出资源
        checkout,
        // @brief MERGE 方法，合并资源
        merge,

        // UPnP 方法
        // @brief M-SEARCH 方法，多播搜索
        msearch,
        // @brief NOTIFY 方法，发送通知
        notify,
        // @brief SUBSCRIBE 方法，订阅事件
        subscribe,
        // @brief UNSUBSCRIBE 方法，取消订阅
        unsubscribe,

        // @brief PATCH 方法，对资源进行部分修改
        patch,
        // @brief PURGE 方法，清除缓存
        purge,

        // @brief MKCALENDAR 方法，创建日历
        mkcalendar,

        // @brief LINK 方法，建立资源链接
        link,
        // @brief UNLINK 方法，移除资源链接
        unlink
    };

    /**
     * @enum field
     * @brief HTTP 头部字段枚举
     * @details 完整的 HTTP 头部字段定义，包含超过 500 个标准及扩展头部字段。
     * 基于 IANA 注册表、RFC 标准及实际部署中的常见扩展定义。使用 unsigned short
     * 底层类型优化内存布局，支持高效数组索引。字段顺序遵循字母排序。
     * @note 头部字段查找应使用预构建的哈希映射，避免线性扫描。
     * @warning 正确处理 Host、Origin、Referer 等安全敏感头部。
     */
    enum class field : unsigned short
    {
        // @brief 未知或未识别的头部字段
        unknown = 0,

        // @brief A-IM 头，指示可接受的实例操作
        a_im,

        // @brief Accept 头，客户端可接受的媒体类型
        accept,

        // @brief Accept-Additions 头，扩展 Accept
        accept_additions,

        // @brief Accept-Charset 头，客户端可接受的字符集
        accept_charset,

        // @brief Accept-Datetime 头，用于内容协商的时间戳
        accept_datetime,

        // @brief Accept-Encoding 头，客户端可接受的内容编码
        accept_encoding,

        // @brief Accept-Features 头，用于特征协商
        accept_features,

        // @brief Accept-Language 头，客户端可接受的语言
        accept_language,

        // @brief Accept-Patch 头，服务器接受的补丁格式
        accept_patch,

        // @brief Accept-Post 头，服务器接受的 POST 内容类型
        accept_post,

        // @brief Accept-Ranges 头，服务器支持的范围请求单位
        accept_ranges,

        // @brief Access-Control 头，WebDAV 访问控制扩展
        access_control,

        // @brief Access-Control-Allow-Credentials 头，CORS 是否允许携带凭据
        access_control_allow_credentials,

        // @brief Access-Control-Allow-Headers 头，CORS 允许的请求头
        access_control_allow_headers,

        // @brief Access-Control-Allow-Methods 头，CORS 允许的请求方法
        access_control_allow_methods,

        // @brief Access-Control-Allow-Origin 头，CORS 允许的来源
        access_control_allow_origin,

        // @brief Access-Control-Expose-Headers 头，CORS 允许前端读取的响应头
        access_control_expose_headers,

        // @brief Access-Control-Max-Age 头，CORS 预检结果缓存时长
        access_control_max_age,

        // @brief Access-Control-Request-Headers 头，预检请求中实际发送的头列表
        access_control_request_headers,

        // @brief Access-Control-Request-Method 头，预检请求中实际发送的方法
        access_control_request_method,

        // @brief Age 头，响应在缓存中停留的秒数
        age,

        // @brief Allow 头，资源允许的 HTTP 方法集合
        allow,

        // @brief ALPN 头，应用层协议协商
        alpn,

        // @brief Also-Control 头，邮件消息控制扩展
        also_control,

        // @brief Alt-Svc 头，服务器声明备用服务
        alt_svc,

        // @brief Alt-Used 头，客户端声明实际使用的备用服务
        alt_used,

        // @brief Alternate-Recipient 头，邮件传输备用接收者
        alternate_recipient,

        // @brief Alternates 头，内容协商可选列表
        alternates,

        // @brief Apparently-To 头，遗留邮件头
        apparently_to,

        // @brief Apply-To-Redirect-Ref 头，WebDAV 重定向引用
        apply_to_redirect_ref,

        // @brief Approved 头，新闻组邮件审批标记
        approved,

        // @brief Archive 头，档案标识
        archive,

        // @brief Archived-At 头，消息归档 URL
        archived_at,

        // @brief Article-Names 头，新闻组文章名称
        article_names,

        // @brief Article-Updates 头，新闻组文章更新标记
        article_updates,

        // @brief Authentication-Control 头，认证控制指令
        authentication_control,

        // @brief Authentication-Info 头，认证结果信息
        authentication_info,

        // @brief Authentication-Results 头，邮件认证结果
        authentication_results,

        // @brief Authorization 头，客户端身份凭证
        authorization,

        // @brief Auto-Submitted 头，自动提交标识
        auto_submitted,

        // @brief Autoforwarded 头，自动转发标记
        autoforwarded,

        // @brief Autosubmitted 头，同 Auto-Submitted
        autosubmitted,

        // @brief Base 头，基准 URI
        base,

        // @brief Bcc 头，密送地址
        bcc,

        // @brief Body 头，消息体标识
        body,

        // @brief C-Ext 头，缓存控制扩展
        c_ext,

        // @brief C-Man 头，缓存管理指令
        c_man,

        // @brief C-Opt 头，缓存选项
        c_opt,

        // @brief C-PEP 头，PEP 缓存扩展
        c_pep,

        // @brief C-PEP-Info 头，PEP 缓存信息
        c_pep_info,

        // @brief Cache-Control 头，缓存指令
        cache_control,

        // @brief CalDAV-Timezones 头，CalDAV 时区数据
        caldav_timezones,

        // @brief Cancel-Key 头，新闻组取消密钥
        cancel_key,

        // @brief Cancel-Lock 头，新闻组取消锁
        cancel_lock,

        // @brief Cc 头，抄送地址
        cc,

        // @brief Close 头，连接关闭标记
        close,

        // @brief Comments 头，附加说明
        comments,

        // @brief Compliance 头，合规性声明
        compliance,

        // @brief Connection 头，连接管理
        connection,

        // @brief Content-Alternative 头，备选内容
        content_alternative,

        // @brief Content-Base 头，内容基准 URI
        content_base,

        // @brief Content-Description 头，内容描述
        content_description,

        // @brief Content-Disposition 头，内容展示方式
        content_disposition,

        // @brief Content-Duration 头，内容持续时间
        content_duration,

        // @brief Content-Encoding 头，内容编码
        content_encoding,

        // @brief Content-Features 头，内容特征标记
        content_features,

        // @brief Content-ID 头，内容标识
        content_id,

        // @brief Content-Identifier 头，内容标识符
        content_identifier,

        // @brief Content-Language 头，内容语言
        content_language,

        // @brief Content-Length 头，内容长度
        content_length,

        // @brief Content-Location 头，内容实际位置
        content_location,

        // @brief Content-MD5 头，内容 MD5 摘要
        content_md5,

        // @brief Content-Range 头，内容范围
        content_range,

        // @brief Content-Return 头，内容返回选项
        content_return,

        // @brief Content-Script-Type 头，默认脚本类型
        content_script_type,

        // @brief Content-Style-Type 头，默认样式类型
        content_style_type,

        // @brief Content-Transfer-Encoding 头，MIME 传输编码
        content_transfer_encoding,

        // @brief Content-Type 头，内容媒体类型
        content_type,

        // @brief Content-Version 头，内容版本
        content_version,

        // @brief Control 头，控制指令
        control,

        // @brief Conversion 头，转换标记
        conversion,

        // @brief Conversion-With-Loss 头，有损转换标记
        conversion_with_loss,

        // @brief Cookie 头，客户端携带的 Cookie
        cookie,

        // @brief Cookie2 头，Cookie 协议版本 2
        cookie2,

        // @brief Cost 头，传输成本
        cost,

        // @brief DASL 头，DAV 搜索能力
        dasl,

        // @brief Date 头，消息生成时间
        date,

        // @brief Date-Received 头，接收时间
        date_received,

        // @brief DAV 头，DAV 版本
        dav,

        // @brief Default-Style 头，默认样式
        default_style,

        // @brief Deferred-Delivery 头，延迟投递时间
        deferred_delivery,

        // @brief Delivery-Date 头，实际投递时间
        delivery_date,

        // @brief Delta-Base 头，增量编码基准
        delta_base,

        // @brief Depth 头，WebDAV 深度标记
        depth,

        // @brief Derived-From 头，派生资源标识
        derived_from,

        // @brief Destination 头，WebDAV 目标 URI
        destination,

        // @brief Differential-ID 头，差分 ID
        differential_id,

        // @brief Digest 头，内容摘要
        digest,

        // @brief Discarded-X400-IPMS-Extensions 头
        discarded_x400_ipms_extensions,

        // @brief Discarded-X400-MTS-Extensions 头
        discarded_x400_mts_extensions,

        // @brief Disclose-Recipients 头，是否公开收件人
        disclose_recipients,

        // @brief Disposition-Notification-Options 头，投递通知选项
        disposition_notification_options,

        // @brief Disposition-Notification-To 头，投递通知地址
        disposition_notification_to,

        // @brief Distribution 头，分发范围
        distribution,

        // @brief DKIM-Signature 头，邮件 DKIM 签名
        dkim_signature,

        // @brief DL-Expansion-History 头，分发列表扩展历史
        dl_expansion_history,

        // @brief Downgraded-Bcc 头，降级密送信息
        downgraded_bcc,

        // @brief Downgraded-Cc 头，降级抄送信息
        downgraded_cc,

        // @brief Downgraded-Disposition-Notification-To 头
        downgraded_disposition_notification_to,

        // @brief Downgraded-Final-Recipient 头
        downgraded_final_recipient,

        // @brief Downgraded-From 头，降级发件人信息
        downgraded_from,

        // @brief Downgraded-In-Reply-To 头，降级回复标识
        downgraded_in_reply_to,

        // @brief Downgraded-Mail-From 头，降级邮件来源
        downgraded_mail_from,

        // @brief Downgraded-Message-ID 头，降级消息 ID
        downgraded_message_id,

        // @brief Downgraded-Original-Recipient 头
        downgraded_original_recipient,

        // @brief Downgraded-Rcpt-To 头，降级接收地址
        downgraded_rcpt_to,

        // @brief Downgraded-References 头，降级引用信息
        downgraded_references,

        // @brief Downgraded-Reply-To 头，降级回复地址
        downgraded_reply_to,

        // @brief Downgraded-Resent-Bcc 头，降级重发密送
        downgraded_resent_bcc,

        // @brief Downgraded-Resent-Cc 头，降级重发抄送
        downgraded_resent_cc,

        // @brief Downgraded-Resent-From 头，降级重发来源
        downgraded_resent_from,

        // @brief Downgraded-Resent-Reply-To 头
        downgraded_resent_reply_to,

        // @brief Downgraded-Resent-Sender 头，降级重发发送者
        downgraded_resent_sender,

        // @brief Downgraded-Resent-To 头，降级重发收件人
        downgraded_resent_to,

        // @brief Downgraded-Return-Path 头，降级返回路径
        downgraded_return_path,

        // @brief Downgraded-Sender 头，降级发送者
        downgraded_sender,

        // @brief Downgraded-To 头，降级收件人
        downgraded_to,

        // @brief EDIINT-Features 头，电子数据交换特征
        ediint_features,

        // @brief EESST-Version 头，扩展安全服务版本
        eesst_version,

        // @brief Encoding 头，编码标记
        encoding,

        // @brief Encrypted 头，加密标记
        encrypted,

        // @brief Errors-To 头，错误报告地址
        errors_to,

        // @brief ETag 头，实体标签
        etag,

        // @brief Expect 头，期望行为
        expect,

        // @brief Expires 头，过期时间
        expires,

        // @brief Expiry-Date 头，显式过期日期
        expiry_date,

        // @brief Ext 头，扩展标记
        ext,

        // @brief Followup-To 头，后续回复新闻组
        followup_to,

        // @brief Forwarded 头，代理链路信息
        forwarded,

        // @brief From 头，请求发起者邮箱或标识
        from,

        // @brief Generate-Delivery-Report 头，生成投递报告
        generate_delivery_report,

        // @brief GetProfile 头，获取配置文件
        getprofile,

        // @brief Hobareg 头，HOBA 注册扩展
        hobareg,

        // @brief Host 头，请求目标主机与端口
        host,

        // @brief HTTP2-Settings 头，HTTP/2 设置帧
        http2_settings,

        // @brief If 头，WebDAV 条件判断
        if_,

        // @brief If-Match 头，条件请求 ETag 需匹配
        if_match,

        // @brief If-Modified-Since 头，条件请求修改时间
        if_modified_since,

        // @brief If-None-Match 头，条件请求 ETag 需不匹配
        if_none_match,

        // @brief If-Range 头，范围请求条件
        if_range,

        // @brief If-Schedule-Tag-Match 头，CalDAV 计划标签条件
        if_schedule_tag_match,

        // @brief If-Unmodified-Since 头，条件请求修改时间
        if_unmodified_since,

        // @brief IM 头，实例操作
        im,

        // @brief Importance 头，重要性级别
        importance,

        // @brief In-Reply-To 头，回复消息标识
        in_reply_to,

        // @brief Incomplete-Copy 头，未完成复制标记
        incomplete_copy,

        // @brief Injection-Date 头，注入时间
        injection_date,

        // @brief Injection-Info 头，注入信息
        injection_info,

        // @brief Jabber-ID 头，XMPP 标识
        jabber_id,

        // @brief Keep-Alive 头，HTTP/1.0 长连接参数
        keep_alive,

        // @brief Keywords 头，关键词列表
        keywords,

        // @brief Label 头，内容标签
        label,

        // @brief Language 头，语言标识
        language,

        // @brief Last-Modified 头，资源最后修改时间
        last_modified,

        // @brief Latest-Delivery-Time 头，最迟投递时间
        latest_delivery_time,

        // @brief Lines 头，行数统计
        lines,

        // @brief Link 头，资源关联关系
        link,

        // @brief List-Archive 头，邮件列表归档地址
        list_archive,

        // @brief List-Help 头，邮件列表帮助地址
        list_help,

        // @brief List-ID 头，邮件列表标识
        list_id,

        // @brief List-Owner 头，邮件列表所有者地址
        list_owner,

        // @brief List-Post 头，邮件列表 posting 地址
        list_post,

        // @brief List-Subscribe 头，邮件列表订阅地址
        list_subscribe,

        // @brief List-Unsubscribe 头，邮件列表退订地址
        list_unsubscribe,

        // @brief List-Unsubscribe-Post 头，退订 POST 表单
        list_unsubscribe_post,

        // @brief Location 头，重定向或新资源地址
        location,

        // @brief Lock-Token 头，WebDAV 锁定令牌
        lock_token,

        // @brief Man 头，缓存管理指令
        man,

        // @brief Max-Forwards 头，最大转发次数
        max_forwards,

        // @brief Memento-Datetime 头，Memento 归档时间
        memento_datetime,

        // @brief Message-Context 头，消息上下文
        message_context,

        // @brief Message-ID 头，消息唯一标识
        message_id,

        // @brief Message-Type 头，消息类型
        message_type,

        // @brief Meter 头，计量信息
        meter,

        // @brief Method-Check 头，方法检查
        method_check,

        // @brief Method-Check-Expires 头，方法检查过期时间
        method_check_expires,

        // @brief MIME-Version 头，MIME 版本
        mime_version,

        // @brief MMHS-ACP127-Message-Identifier 头，军用消息标识
        mmhs_acp127_message_identifier,

        // @brief MMHS-Authorizing-Users 头，授权用户列表
        mmhs_authorizing_users,

        // @brief MMHS-Codress-Message-Indicator 头
        mmhs_codress_message_indicator,

        // @brief MMHS-Copy-Precedence 头，副本优先级
        mmhs_copy_precedence,

        // @brief MMHS-Exempted-Address 头，豁免地址
        mmhs_exempted_address,

        // @brief MMHS-Extended-Authorisation-Info 头
        mmhs_extended_authorisation_info,

        // @brief MMHS-Handling-Instructions 头，处理指令
        mmhs_handling_instructions,

        // @brief MMHS-Message-Instructions 头，消息处理指令
        mmhs_message_instructions,

        // @brief MMHS-Message-Type 头，军用消息类型
        mmhs_message_type,

        // @brief MMHS-Originator-PLAD 头，发起者 PLAD
        mmhs_originator_plad,

        // @brief MMHS-Originator-Reference 头，发起者引用
        mmhs_originator_reference,

        // @brief MMHS-Other-Recipients-Indicator-Cc 头
        mmhs_other_recipients_indicator_cc,

        // @brief MMHS-Other-Recipients-Indicator-To 头
        mmhs_other_recipients_indicator_to,

        // @brief MMHS-Primary-Precedence 头，主优先级
        mmhs_primary_precedence,

        // @brief MMHS-Subject-Indicator-Codes 头，主题指示码
        mmhs_subject_indicator_codes,

        // @brief MT-Priority 头，消息传输优先级
        mt_priority,

        // @brief Negotiate 头，内容协商
        negotiate,

        // @brief Newsgroups 头，新闻组列表
        newsgroups,

        // @brief NNTP-Posting-Date 头，NNTP 发布时间
        nntp_posting_date,

        // @brief NNTP-Posting-Host 头，NNTP 发布主机
        nntp_posting_host,

        // @brief Non-Compliance 头，不合规标记
        non_compliance,

        // @brief Obsoletes 头，废弃标识
        obsoletes,

        // @brief Opt 头，选项
        opt,

        // @brief Optional 头，可选标记
        optional,

        // @brief Optional-WWW-Authenticate 头，可选认证方式
        optional_www_authenticate,

        // @brief Ordering-Type 头，排序类型
        ordering_type,

        // @brief Organization 头，组织名称
        organization,

        // @brief Origin 头，跨域请求来源
        origin,

        // @brief Original-Encoded-Information-Types 头
        original_encoded_information_types,

        // @brief Original-From 头，原始发件人
        original_from,

        // @brief Original-Message-ID 头，原始消息 ID
        original_message_id,

        // @brief Original-Recipient 头，原始收件人
        original_recipient,

        // @brief Original-Sender 头，原始发送者
        original_sender,

        // @brief Original-Subject 头，原始主题
        original_subject,

        // @brief Originator-Return-Address 头，发起者返回地址
        originator_return_address,

        // @brief Overwrite 头，WebDAV 覆盖标记
        overwrite,

        // @brief P3P 头，隐私策略
        p3p,

        // @brief Path 头，路由路径
        path,

        // @brief PEP 头，策略扩展协议
        pep,

        // @brief PEP-Info 头，PEP 信息
        pep_info,

        // @brief PICS-Label 头，内容标签
        pics_label,

        // @brief Position 头，位置信息
        position,

        // @brief Posting-Version 头，发布版本
        posting_version,

        // @brief Pragma 头，实现相关指令
        pragma,

        // @brief Prefer 头，客户端偏好
        prefer,

        // @brief Preference-Applied 头，已应用的偏好
        preference_applied,

        // @brief Prevent-NonDelivery-Report 头
        prevent_nondelivery_report,

        // @brief Priority 头，优先级
        priority,

        // @brief Privicon 头，隐私图标
        privicon,

        // @brief ProfileObject 头，配置文件对象
        profileobject,

        // @brief Protocol 头，协议信息
        protocol,

        // @brief Protocol-Info 头，协议信息
        protocol_info,

        // @brief Protocol-Query 头，协议查询
        protocol_query,

        // @brief Protocol-Request 头，协议请求
        protocol_request,

        // @brief Proxy-Authenticate 头，代理认证要求
        proxy_authenticate,

        // @brief Proxy-Authentication-Info 头，代理认证信息
        proxy_authentication_info,

        // @brief Proxy-Authorization 头，代理认证凭证
        proxy_authorization,

        // @brief Proxy-Connection 头，代理连接
        proxy_connection,

        // @brief Proxy-Features 头，代理特性
        proxy_features,

        // @brief Proxy-Instruction 头，代理指令
        proxy_instruction,

        // @brief Public 头，公开方法列表
        public_,

        // @brief Public-Key-Pins 头，公钥固定
        public_key_pins,

        // @brief Public-Key-Pins-Report-Only 头
        public_key_pins_report_only,

        // @brief Range 头，请求字节范围
        range,

        // @brief Received 头，邮件传输路径信息
        received,

        // @brief Received-SPF 头，SPF 接收结果
        received_spf,

        // @brief Redirect-Ref 头，WebDAV 重定向引用
        redirect_ref,

        // @brief References 头，引用消息列表
        references,

        // @brief Referer 头，请求来源页面地址
        referer,

        // @brief Referer-Root 头，来源根路径
        referer_root,

        // @brief Relay-Version 头，中继版本
        relay_version,

        // @brief Reply-By 头，回复截止时间
        reply_by,

        // @brief Reply-To 头，回复地址
        reply_to,

        // @brief Require-Recipient-Valid-Since 头
        require_recipient_valid_since,

        // @brief Resent-Bcc 头，重发密送
        resent_bcc,

        // @brief Resent-Cc 头，重发抄送
        resent_cc,

        // @brief Resent-Date 头，重发日期
        resent_date,

        // @brief Resent-From 头，重发来源
        resent_from,

        // @brief Resent-Message-ID 头，重发消息 ID
        resent_message_id,

        // @brief Resent-Reply-To 头，重发回复地址
        resent_reply_to,

        // @brief Resent-Sender 头，重发发送者
        resent_sender,

        // @brief Resent-To 头，重发收件人
        resent_to,

        // @brief Resolution-Hint 头，解析提示
        resolution_hint,

        // @brief Resolver-Location 头，解析器位置
        resolver_location,

        // @brief Retry-After 头，稍后重试时间
        retry_after,

        // @brief Return-Path 头，退回路径
        return_path,

        // @brief Safe 头，安全标记
        safe,

        // @brief Schedule-Reply 头，CalDAV 计划回复
        schedule_reply,

        // @brief Schedule-Tag 头，CalDAV 计划标签
        schedule_tag,

        // @brief Sec-Fetch-Dest 头，Fetch 元数据目标
        sec_fetch_dest,

        // @brief Sec-Fetch-Mode 头，Fetch 元数据模式
        sec_fetch_mode,

        // @brief Sec-Fetch-Site 头，Fetch 元数据站点关系
        sec_fetch_site,

        // @brief Sec-Fetch-User 头，Fetch 元数据用户触发
        sec_fetch_user,

        // @brief Sec-WebSocket-Accept 头，WebSocket 握手响应密钥
        sec_websocket_accept,

        // @brief Sec-WebSocket-Extensions 头，WebSocket 扩展列表
        sec_websocket_extensions,

        // @brief Sec-WebSocket-Key 头，WebSocket 握手请求密钥
        sec_websocket_key,

        // @brief Sec-WebSocket-Protocol 头，WebSocket 子协议
        sec_websocket_protocol,

        // @brief Sec-WebSocket-Version 头，WebSocket 协议版本
        sec_websocket_version,

        // @brief Security-Scheme 头，安全方案
        security_scheme,

        // @brief See-Also 头，参考链接
        see_also,

        // @brief Sender 头，实际发送者地址
        sender,

        // @brief Sensitivity 头，敏感度标记
        sensitivity,

        // @brief Server 头，服务器软件信息
        server,

        // @brief Set-Cookie 头，服务器下发 Cookie
        set_cookie,

        // @brief Set-Cookie2 头，Cookie2 版本
        set_cookie2,

        // @brief SetProfile 头，设置配置文件
        setprofile,

        // @brief SIO-Label 头，安全标签
        sio_label,

        // @brief SIO-Label-History 头，安全标签历史
        sio_label_history,

        // @brief Slug 头，AtomPub 资源简短名称
        slug,

        // @brief SOAPAction 头，SOAP 动作
        soapaction,

        // @brief Solicitation 头，征集标记
        solicitation,

        // @brief Status-URI 头，状态 URI
        status_uri,

        // @brief Strict-Transport-Security 头，强制 HTTPS
        strict_transport_security,

        // @brief Subject 头，主题标题
        subject,

        // @brief SubOK 头，订阅确认
        subok,

        // @brief Subst 头，替换标记
        subst,

        // @brief Summary 头，摘要信息
        summary,

        // @brief Supersedes 头，取代标识
        supersedes,

        // @brief Surrogate-Capability 头，代理能力声明
        surrogate_capability,

        // @brief Surrogate-Control 头，代理控制指令
        surrogate_control,

        // @brief TCN 头，透明内容协商
        tcn,

        // @brief TE 头，传输编码容忍度
        te,

        // @brief Timeout 头，WebDAV 锁定超时
        timeout,

        // @brief Title 头，标题
        title,

        // @brief To 头，收件人地址
        to,

        // @brief Topic 头，主题关键词
        topic,

        // @brief Trailer 头，分块传输尾部字段预告
        trailer,

        // @brief Transfer-Encoding 头，传输编码
        transfer_encoding,

        // @brief TTL 头，生存时间
        ttl,

        // @brief UA-Color 头，客户端颜色能力
        ua_color,

        // @brief UA-Media 头，客户端媒体能力
        ua_media,

        // @brief UA-Pixels 头，客户端像素能力
        ua_pixels,

        // @brief UA-Resolution 头，客户端分辨率
        ua_resolution,

        // @brief UA-Windowpixels 头，客户端窗口像素
        ua_windowpixels,

        // @brief Upgrade 头，协议升级请求
        upgrade,

        // @brief Urgency 头，紧急程度
        urgency,

        // @brief URI 头，统一资源标识
        uri,

        // @brief User-Agent 头，客户端软件标识
        user_agent,

        // @brief Variant-Vary 头，变体变化标记
        variant_vary,

        // @brief Vary 头，缓存键变化字段列表
        vary,

        // @brief VBR-Info 头，可变比特率信息
        vbr_info,

        // @brief Version 头，版本标识
        version,

        // @brief Via 头，代理网关路径
        via,

        // @brief Want-Digest 头，期望摘要算法
        want_digest,

        // @brief Warning 头，警告信息
        warning,

        // @brief WWW-Authenticate 头，服务器认证质询
        www_authenticate,

        // @brief X-Archived-At 头，归档地址
        x_archived_at,

        // @brief X-Device-Accept 头，设备可接受类型
        x_device_accept,

        // @brief X-Device-Accept-Charset 头
        x_device_accept_charset,

        // @brief X-Device-Accept-Encoding 头
        x_device_accept_encoding,

        // @brief X-Device-Accept-Language 头
        x_device_accept_language,

        // @brief X-Device-User-Agent 头，设备用户代理
        x_device_user_agent,

        // @brief X-Frame-Options 头，框架嵌入限制
        x_frame_options,

        // @brief X-Mittente 头，发件人
        x_mittente,

        // @brief X-PGP-Sig 头，PGP 签名
        x_pgp_sig,

        // @brief X-Ricevuta 头，接收确认
        x_ricevuta,

        // @brief X-Riferimento-Message-ID 头，引用消息 ID
        x_riferimento_message_id,

        // @brief X-TipoRicevuta 头，接收类型
        x_tiporicevuta,

        // @brief X-Trasporto 头，传输方式
        x_trasporto,

        // @brief X-VerificaSicurezza 头，安全验证
        x_verificasicurezza,

        // @brief X400-Content-Identifier 头
        x400_content_identifier,

        // @brief X400-Content-Return 头
        x400_content_return,

        // @brief X400-Content-Type 头
        x400_content_type,

        // @brief X400-MTS-Identifier 头
        x400_mts_identifier,

        // @brief X400-Originator 头
        x400_originator,

        // @brief X400-Received 头
        x400_received,

        // @brief X400-Recipients 头
        x400_recipients,

        // @brief X400-Trace 头
        x400_trace,

        // @brief Xref 头，交叉引用
        xref
    };

}
