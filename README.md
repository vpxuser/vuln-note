# HTTP缺少安全头漏洞

**HTTP 安全响应头**是前端安全防护的第一道“声明式防火墙”，由服务端设置，帮助浏览器**限制危险行为**。

| HTTP响应头                        | 作用                                                         | 配置                                                         | 绕过                                                         | 业务影响                                                     | 业务影响程度 |
| --------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------ |
| Content-Security-Policy (CSP)     | 限制页面加载资源的来源（如 JS、CSS、img、iframe）            | Content-Security-Policy: default-src 'self'                  | \- 使用漏洞源绕白名单域名（如 CDN 域名上传恶意 JS）<br/>\- 利用 `unsafe-inline`、`unsafe-eval` 等弱配置<br/>\- CSP 未配置或配置错误 | 拦截不符合策略的 JS、CSS、iframe 加载，可能导致页面报错或样式/功能异常。 | 高           |
| X-Frame-Options                   | 防止网页被 `<iframe>` 嵌入                                   | X-Frame-Options: DENY                                        | \- 使用无效响应（301/302重定向时未继承头部）<br/>\- 使用 CSP 替代时未设置 `frame-ancestors`<br/>\- 通过 JS 动态注入 iframe 绕过检测 | 页面不能被其他页面通过 iframe 加载；如果业务中有内嵌需求会被阻止。 | 中           |
| Strict-Transport-Security (HSTS)  | 强制使用 HTTPS 访问，避免中间人降级                          | Strict-Transport-Security: max-age=63072000; includeSubDomains; preload | \- 首次访问未命中 HSTS（“首次访问劫持”）<br/>\- 使用恶意 WiFi 劫持首次请求<br/>\- 若未 preload，攻击者有时间窗口干预 | 一旦开启，客户端会强制走 HTTPS；切回 HTTP 需要等缓存失效。   | 低           |
| X-Content-Type-Options            | 强制浏览器遵循 Content-Type，不猜测 MIME 类型                | X-Content-Type-Options: nosniff                              | \- 上传内容类型绕过（如 `.svg` 被解析为 HTML）<br/>\- 某些服务端未正确声明 Content-Type | 防止 MIME 类型猜测；上传/下载接口返回类型不规范时可能出现错误。 | 低           |
| Referrer-Policy                   | 控制 HTTP Referer 信息发送策略                               | Referrer-Policy: no-referrer-when-downgrade                  | \- 配置宽松，如 `no-referrer-when-downgrade`，泄露来源 URL<br/>\- 服务端直接泄露敏感 Referer | 控制 referrer 行为，可能会影响跳转后页面的统计参数。         | 低           |
| Permissions-Policy                | 控制浏览器功能访问权限（如摄像头、麦克风、地理位置）         | Permissions-Policy: geolocation=(), microphone=(), camera=() | 子页面未继承、iframe滥用                                     | 限制访问权限功能，除非你业务用到了摄像头/麦克风。            | 无           |
| X-Download-Options                | 防止 IE 浏览器用户“直接打开”下载的文件，尤其是 HTML。防止 XSS。 | X-Download-Options: noopen                                   | 被忽略、IE漏洞绕过                                           | **几乎没有影响**，除非你的网站特别支持让 IE 用户在下载后直接打开文件（极罕见）。 | 无           |
| X-Permitted-Cross-Domain-Policies | 禁止 Flash、Adobe Reader 等插件请求站点跨域策略文件（crossdomain.xml）。防止插件跨域窃取数据。 | X-Permitted-Cross-Domain-Policies: none                      | 加载其他域策略文件、插件漏洞                                 | **99.9% 业务无影响**。唯一可能受影响的情况是你真的在用 Flash 或老版 Acrobat 加载你的站点资源（基本已经淘汰）。 | 无           |
| X-XSS-Protection                  | 启用浏览器的反射型 XSS 防护机制（老版 Chrome、IE 支持）。    | X-XSS-Protection: 1; mode=block                              | \- 不起作用于现代浏览器<br/>- 利用 DOM-based XSS、JS 引擎执行链绕过检测 | 可能存在**误判拦截**的风险，比如某些页面需要将 URL 参数回显到页面中（如搜索页面、留言表单），浏览器误判为 XSS 而拦截页面渲染。 | 高           |



