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

# DDOS类型及防御方案

| **攻击类型**        | **发起成本（攻击者视角）**                                   | **企业防御方案（务实）**                                     | **典型被攻击目标**                    |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------- |
| **UDP Flood**       | 极低：<br/> \- ❌无需维持连接，不占用端口  <br/> \- ✅源IP可伪造，支持IP随机化 <br/> \- ✅极低资源消耗（适合廉价肉鸡）<br/> \- ⬆️带宽消耗大，但并发量要求低 | ✅接入CDN分散流量<br/>✅边缘防火墙丢弃无效UDP<br/>✅BGP高防或清洗服务（如阿里盾、金盾） | 游戏服务器、直播节点、VPN服务器       |
| **SYN Flood**       | 低：<br/> \- ❌仅发送 SYN，不需握手，不占连接资源 <br/> \- ✅可伪造IP，规避追踪 <br/> \- ✅单机可高并发发起，资源消耗小 <br/> \- 🚫攻击目标连接队列，压垮TCP堆栈 | ✅云WAF或云主机启用SYN Cookie<br/>✅在ISP侧布署抗DDoS服务<br/>✅服务端限半连接数 | Web服务、TCP网关、VPN、数据库前置系统 |
| **ACK Flood**       | 低：<br/> \- ❌无需三次握手 <br/> \- ✅IP可伪造，防火墙难识别<br/> \- ✅基本不占用端口、资源消耗低 <br/> \- ⬆️攻击需大量带宽，但发起容易 | ✅部署深度包检测（DPI）<br/>✅结合行为防火墙识别异常ACK模式<br/>✅流量清洗 | 游戏CDN边缘节点、出口设备             |
| **HTTP Flood**      | 高：<br/> \- ✅必须完成TCP握手 + 发送完整HTTP请求 <br/> \- ✅需维持大量长连接，端口资源占用严重 <br/> \- 🚫源IP不能伪造，需大量代理或肉鸡（如：IP池/动态IP）<br/> \- ⬆️攻击需高并发、真实请求构造，资源消耗高 | ✅接入CDN防WAF绕过<br/>✅云WAF检测并封禁异常行为<br/>✅验证码、人机挑战<br/>✅熔断限速机制 | 网站、商城、Web登录、管理后台         |
| **Slowloris**       | 中：<br/> \- ✅每条连接需保持活跃（超时前不断发数据）<br/> \- ✅占用攻击者大量本地端口/连接资源<br/> \- 🚫源IP不能伪造，适合长时间稳定资源攻击<br/> \- ❌适合 Apache/Nginx 的线程型服务 | ✅切换为事件驱动Web服务（如Nginx）<br/>✅设置连接超时<br/>✅限制Header接收速率 | Apache类老旧网站、低并发Web服务       |
| **SSL Exhaustion**  | 中：<br/> \- ✅需完整TLS握手，攻击者需耗CPU计算开销<br/> \- ❌源IP不能伪造<br/> \- ⬆️端口占用+高并发线程支持<br/> \- ❗目标SSL计算压力极高 | ✅使用SSL卸载器或加速卡<br/>✅接入HTTPS分流网关<br/>✅限握手频率/连接频率 | HTTPS服务、支付网关、OAuth认证        |
| **DNS Query Flood** | 中：<br/> \- ✅不需握手，快速并发请求<br/> \- 🚫源IP一般不伪造（否则收不到回应）<br/> \- ❌攻击本身消耗小，但需持续发包<br/> \- ❗目标DNS CPU和内存快速消耗 | ✅采用多节点Anycast DNS<br/>✅设置IP限速/查询速率<br/>✅DNS负载均衡 + 缓存 | 企业自建DNS、权威DNS、直播解析服务    |
| **DNS反射攻击**     | 极低：<br/> \- ✅伪造源IP为目标 <br/> \- ❌不需接收响应 <br/> \- ✅发一个小请求换几十倍响应，适合反射<br/> \- ❗几乎不占端口或内存，1台机器可发起上G流量 | ✅目标部署高防IP清洗<br/>✅加速入口使用CDN隔离真实IP<br/>✅ISP端边界流量清洗 | 任意公网服务（VPN、后台、数据库）     |
| **NTP反射攻击**     | 极低：<br/> \- ✅利用`monlist`查询，极小请求换大响应<br/> \- ✅IP伪造+无需响应<br/> \- ✅攻击者资源几乎为0，最典型反射方式之一 | ✅封锁UDP/123端口在边界<br/>✅后端使用高防或BGP清洗节点<br/>✅隐藏真实服务器IP（通过跳板） | 云主机、办公系统、监控服务            |
| **Memcached反射**   | 极低：<br/>- ✅构造一个指令返回超大payload（最大放大率）  <br/>- ✅伪造IP、无需接收回应  <br/>- ✅只需1个可利用的服务就能打出TB流量 | ✅关闭Memcached UDP支持<br/>✅仅监听内网IP<br/>✅核心服务走CDN或公网高防线路 | API服务器、商城、CDN源站              |
| **SSDP反射攻击**    | 极低：<br/> \- ✅扫描开放UPnP设备即可利用<br/> \- ✅无需连接保持，极小资源消耗<br/> \- ❗家庭设备多但分散，需要批量收集IP | ✅封锁UDP 1900端口<br/>✅边界层清洗或代理分发<br/>✅IoT设备自检及封锁外部UPnP | IoT云平台、中小企业公网IP服务         |
