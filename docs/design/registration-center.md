# TeeTLS 上游认证中心(Registration Center)

## 目标 / 非目标

**目标**:让第三方 reseller 上游(阿里 dashscope、openrouter、minimax…)**自助接入**一套共享的、可远程证明(attested)的 0G 基础设施;每个 reseller 成为一个**可独立 pin 的链上 provider**;TEE 对每个请求给出**可验证的诚实路由证明**。

**非目标**:不共用一个链上身份;不改 router 的 canonical 路由 / `(model_id, address)` 主键 / 按地址 pin;不为接入而新增容器/域名/重部署(见 §9)。

## 1. 核心不变量与已核实前提

| 不变量 | 状态 |
|---|---|
| 每个 reseller = 一个独立链上 provider 地址(→ 页面/pin/canonical 聚合不变,同模型多家不撞) | 设计选择 |
| 一个 attested 中心镜像 + 一个 endpoint/域名(→ DNS/证书恒定、measurement 稳定) | 设计选择 |
| 接入 = 数据(链上一条记录 + enclave 内密封 slot),不改镜像 | 设计选择 |

**已核实(读过 router/合约代码)**:
- router 全链**按 address keying,无按 servingUrl 去重**;N 地址共用一 servingUrl → N 独立行。✓
- router 转发已带**按 `provider.Address` 铸发的鉴权 `Authorization: Bearer` token**(路由内 TEE node `CreateApiKey(address)`,可 recover router-TEE 签发者)→ 中心据此**不可伪造地**辨识 reseller。✓
- 合约:多 address 可共用一 servingUrl;充值/结算按 `(user, provider address)`;`removeService` 不动用户余额;提现有 `lockTime`;**每 service 只存一个 `TeeSignerAddress`(无历史版本)**;proof 文本**硬性 5 字段** `req:resp:providerType:providerIdentity:tlsCertFingerprint`(router `response_processor.go` 强校验字段数)。✓
- router 当前把 `providerIdentity` 当**展示字段**(cert↔identity 目录校验是 Phase 2 未做)→ 强保证目前落在 **attested enclave + 链上 TeeSigner** 上,D 是 **proof 内的 enclave 断言**,验证方暂不复查(§5.1)。✓

## 2. 架构

```
                     链上 InferenceServing
   provider A  servingUrl=center.x  models=[glm-5.2,…]  TeeSigner=Sa(由稳定 id 确定性派生)
   provider B  servingUrl=center.x  models=[glm-5.2,…]  TeeSigner=Sb
   provider C  servingUrl=center.x  …                                             ← 自注册新增
        ▲ 不同 address(=reseller 身份),servingUrl 都指向同一 endpoint
        │ router:按 canonical 聚合、按 address pin;转发带 per-address 鉴权 token
   ┌────┴──────────────────────────────────────────────────┐
   │  Center(一个 attested dstack 镜像 / 一个域名 center.x) │
   │   · 密封 vault:  slot → { 上游 API key, TeeSigner 私钥 }│
   │   · 上游表(热更): slot → { targetUrl, 溯源域名D, models }│
   │   · 注册 API   · 从鉴权 token 定 slot 路由   · 代注册/结算│
   │   · 自铸 UUID → 每个 proof;UUID→slot 持久化到结算后      │
   └────────────────────────────────────────────────────────┘
        ▼ 各 slot 连各自上游(全链 TLS 校验 → 记录溯源域名 D / CA)
   dashscope.aliyuncs.com   open.bigmodel.cn   newvendor.com  …
```

## 3. 两种身份,别混(本方案的地基)

- **溯源域名 D**:enclave **运行时**对上游做完整 TLS 链 + hostname 校验后,得到"这次输出确实来自持 CA 有效证书、域名 = D 的主机"。**D 非唯一**(多个 reseller 可合法都连 `dashscope.aliyuncs.com`);它证明**输出来源**,不证明"注册者是谁"。**不要求、也无法要求 reseller 拥有 D 的 DNS。**
- **reseller 身份 = 其链上地址**(可选 + reseller **自控域名**用 DNS-01 证明,作为跨地址的**声誉/slash 锚点**)。slash/removal 钉在这里,不钉在 D 上。
- **canonicalId→上游模型是自报**:reseller 声明"我的 `glm-5.2` 映射到上游某模型",TEE 只保证忠实转发,不保证上游没拿廉价/量化后端顶替 → catalog **标注该映射为"未验证自报"**。

> 由此消解了旧稿的矛盾:D 若唯一会垄断 dashscope 身份、锁死其他合法 reseller;D 非唯一则声誉不能锚在 D。正解是 **D=溯源(非唯一)+ 地址/自控域名=身份(唯一锚)**。

## 4. 流程

### 4.1 自注册(原子化)
1. **验中心**:reseller 取中心 TDX quote;**SDK 强制校验 quote 的 measurement 在治理发布的链上 allowlist 上**(§5.3),再 encrypt-to-enclave 交上游 key(否则运营方可换恶意镜像 MITM 骗 key)。
2. **提交 + 签名**:`{ 上游 URL, models[](自报 canonicalId), 加密上游 key, stake, 提现地址 }`,用 reseller wallet 签名(证明本人 + 提现凭据)。
3. **运行时溯源**:enclave 连 `上游 URL` 做全链 TLS 校验 → 得溯源域名 D,记录 D/CA。**`providerIdentity` = D,enclave 写入,拒自填**(不能"连 evil.com 却盖 aliyun")。
4. **确定性密钥 + 原子提交**:
   - **TeeSigner 从稳定 id 确定性派生**(master ⊗ reseller-address)→ 重注册复现**同一** signer,旧 proof 仍可验(合约只存一个 TeeSignerAddress,故不可"版本化")。**master 必须来自按稳定 app-id 的持久密钥供给(如 dstack KMS),不得绑 measurement**——否则 allowlist 内的镜像升级会丢 master → 派生出新 signer → 旧 proof 失效(等于把"版本化"问题又打开)。**多运营方冗余(§7/§10)会打破此假设**(各运营方各自 master → 同一 reseller 派生不同 signer,而合约只存一个)→ 届时需共享/门限签名方案(§11)。
   - 密封 wallet+TeeSigner+key 到**待定区,并存该 `addOrUpdateService` 的 tx hash**;
   - 发 tx(`address`、`servingUrl=center.x`、`models`、`providerType=centralized`、`providerIdentity=D`、`TeeSigner`、stake);
   - **仅链上确认后**把 slot 从待定区提升进热更表;失败抹待定区。
5. **启动对账(先促成 pending)**:先拿**待定区的 tx hash 比对链上**,已确认的**先提升**;然后才做双向核对——`servingUrl=center.x` 的链上 provider 无 slot 且无 pending → 标 degraded / 自动 `removeService`;密封 slot 无链上记录且无 pending tx → GC。(避免把"已上链但没来得及提升"的合法 provider 误拆。)

### 4.2 请求(用户 pin 了 A)
1. client → router:`model=glm-5.2` + `X-0G-Provider-Address: A`(或未 pin,router 按 canonical 选 A)。
2. router → 中心 endpoint,带**按 A 铸发的鉴权 token**。
3. 中心:**校验 token 是真 0G 结算 token(recover router-TEE 签发者)→ 从中定 slot A**(token.provider 权威、不可伪造)→ **中心(attested/可信)对 `(user, A, nonce)` 在窗口内去重**(重复即拒,**这才是真正的防重放**——router 只验签名+字段数、从不重算 `req`,故防重放必须由中心侧强制,而非靠把 nonce 折进 `req`)→ 用 A 的密封 key 调 D → 全链 TLS 校验 → 用 A 的 TeeSigner 签 5 字段 proof(nonce 折进 `req=sha256(含 nonce 的请求)`,格式不变,仅供会重算 `req` 的 SDK 侧验证方额外校验)→ 计量结算走 `(user, A)` 账户(**链上双花去重复用合约既有 per-(user,provider) 结算 nonce**)。
   - 直连 broker 路径(用户持 per-provider 凭据)才额外断言 `token.provider == credential.provider`;router/未 pin 路径**以 token.provider 为准**(见 §5.2)。
4. **签名回取**:中心为每个 proof **自铸全局唯一 UUID**(经 `ZG-Res-Key` 返回,不用上游 completion id,防跨 reseller 撞车/串号),按 `UUID→slot` 返回;**按请求者的不可猜 UUID 做能力授权**(UUID 全熵、绝不记日志/泄露;回取端点无 bearer,仅靠 UUID 不可猜),不泄他人 proof;**proof/输入持久化到结算 + 争议窗口后**才回收(非 TTL 缓存,防"已结算却无法出证")。用量统计按 slot 分账并回显 ProviderAddress。

### 4.3 撤销 / 下线
1. **先 quiesce**:把 slot 移出热更表、停止接单;
2. **drain + 结算**在途用量;
3. `removeService(A)` + 清 slot + 抹密封 key;
4. 向用户暴露 provider-dead,让其尽早开始提现(余额独立、`lockTime` 后可提)。
- **removeService 加 timelock/通知**:因 wallet 托管、中心是结算提交方,运营方若跳过 drain 直接 remove+抹 key 会**吞掉 reseller 未结算收入**(资金风险,§7)→ 用延时让 reseller 能先强制结算。

## 5. 信任与威胁模型(诚实版)

### 5.1 身份 / 溯源
- proof 精确含义:"attested enclave 通过 TLS 连到持 CA 有效证书、域名 = D 的主机并诚实转发"(全链 + hostname 校验,记 CA/issuer;运营方拥有网络是最强 MITM,只有 in-enclave 全链校验能防)。
- `providerIdentity = D` 由 enclave 派生;reseller 身份 = 链上地址(§3)。
- **诚实边界**:router 当前不复查 cert↔identity(Phase 2),故"D 真实"依赖 **attested 镜像**;验证方要拿到强保证,需 SDK 侧按 measurement + 链上 TeeSigner 验(§5.3)。"官方品牌"另由目录标 first-party;UI 展示 D、并标 canonicalId 映射"未验证"。

### 5.2 selector / 计费(防伪造、防错计费)
- slot 与账户**都来自不可伪造的 per-address 鉴权 token**(router-TEE 铸,中心必须 recover 其签发者验真——**载荷项**);不看明文 header。计费走 `(user, A)`;**若合约/LedgerManager 要求该账户已 acknowledge/充值为硬前置**,则 router 只能计到用户已授权的 provider;**若 LedgerManager 会在首次使用时自动开户/充值**(需确认,§11),则退化为"router 策略信任 + proof 可审计"。无论哪种,**proof 记录了实际计费的 A + 其 TeeSigner → 每笔可审计**。
- 残留:未 pin 时用户没指定 A,贪婪的运营方-router 可把量导向自家/回扣 reseller(仍限于用户已充值的 provider,且事后可审计)→ 属 **router 策略信任边界**,靠 proof 可审计缓解;要更强则未 pin 走两阶段 acknowledge(非 MVP)。
- 重放:**由中心侧对 `(user, provider, nonce)` 去重强制**(router 只验签名+字段数、不重算 `req`,故折进 `req` 的 nonce 对 router 路径**无效**,仅对会重算 `req` 的 SDK 验证方有意义)。双花:复用合约既有 per-(user,provider) 结算 nonce(**须确认线上 `settleFees` 确实拒重复/非递增 nonce**;若不拒则是既有问题,非本方案引入)。

### 5.3 机密面 / SSRF / 运营方(measurement 自动化是关键)
- **targetUrl 视为 SSRF sink**:拒内网/元数据 IP、禁重定向、只允许公网 https;slot↔wallet 绑定(写表校验防串槽)。
- **爆炸半径**:单镜像持所有 slot 的 key(密封)。真正制约运营方换恶意镜像偷 vault / 注册期 MITM 的,是 **measurement 校验默认自动化**:SDK 注册流程和 client proof 验证都**默认拒绝 measurement 不在治理链上 allowlist 的 quote**(而非"谁想起来才手动核")。可复现构建配套。**不自动化就得如实降级 §5.1 的强度声明为"对不校验者=信任运营方"。**

## 6. 复用 #604 vs 新增
- **复用**:一 broker 多真实上游、per-上游 key、proof 现抓活证书。
- **新增**:注册 API、运行时溯源、密封 vault、确定性 TeeSigner、基于 token 的 slot 路由、自铸 UUID→slot 持久化、原子注册+对账、quiesce+drain、SSRF 收口、measurement 自动校验。
- **合约不改**(前提:线上 `settleFees` 已按 per-(user,provider) nonce 去重;§5.2 须确认)。

## 7. 已接受的固有风险(单镜像 / 单 endpoint / 单运营方)
attestation 只买**完整性**,不买**可用性/抗审查/资金可达性**:
- **静默审查**:运营方丢弃 selector=A 或墙掉到 D 的出口 → A 无链上证据自证。
- **removeService-不-drain 吞未结算收入**(资金风险)→ §4.3 timelock 缓解,但根治需非托管 wallet / 去中心结算。
- **噪声邻居**:一个 reseller 拖垮共享镜像 → per-slot 限流+连接配额+上游超时(有界化,不解审查)。
- **单点**:唯一真正解 = **多运营方各跑同 measurement 的中心镜像**(冗余),留作演进项,非 MVP。

## 8. 反滥用 / 反 Sybil
- **声誉/slash 锚 = reseller 地址(+ 可选自控域名),不是 D**(D 非唯一)。有自控域名 → 声誉跨地址不可洗白;无 → 声誉 per-address、由 stake 有界(Sybil 成本 = 每地址 stake+gas)。
- **canonicalId 映射标"未验证自报"**,防同域名换廉价后端顶替。
- **TeeSigner 恒中心密封 + 由稳定 id 确定性派生**;reseller 自持 signer = 可离线签夸大 proof,**绝不下放**;§11 的"自带 wallet"仅指 wallet(链上身份/提现)可选自持,TeeSigner 无论如何中心密封。

## 9. 被否决的替代方案(留档)
- **共享一个地址 + 命名空间 model id**:router 按 canonical 路由、客户端发 canonical,命名空间内部 id 客户端够不着 → 选不了家;canonical 命名空间化则失聚合。与"按地址 pin"冲突。
- **一机多 broker + 共享域名(基础设施式)**:每 reseller 一容器/端口/子域名 → Cloudflare 每 reseller 3 条记录撞上限、改 compose 破坏 measurement、爆炸半径叠加。

## 10. MVP(安全最小集,不含破捷径)
- ✅ 运行时溯源 D + enclave 全链 TLS 校验;`providerIdentity=D` 派生非自填;reseller 身份=地址。
- ✅ slot/账户绑定不可伪造 per-address token;nonce 折进 req;结算复用合约 nonce。
- ✅ TeeSigner 确定性派生(免版本化);自铸 UUID→slot 持久化到结算后。
- ✅ 原子注册 + 先促成 pending 的对账;quiesce→drain→remove;removeService timelock;per-slot 限流。
- ✅ **measurement 校验在 SDK 默认自动**(注册 + proof 验证)。
- ⬜ 暂缓:reseller 自控域名声誉锚、自带 wallet(TeeSigner 永不)、first-party 目录、未 pin 两阶段 acknowledge、自动 slash、多运营方冗余。

## 11. 待拍板
1. wallet 托管:中心派生密封(MVP)vs reseller 自持(需 attested 提现流程)。
2. gas 来源:从 stake 扣 / 中心 float;注册前 min-stake 预检。
3. 声誉:是否要求 reseller 自控域名(DNS-01)做跨地址锚,还是接受 per-address + stake 有界。
4. 抗审查:是否上多运营方冗余,还是接受单运营方可用性/资金可达性信任。**多运营方需 per-reseller 共享/门限 TeeSigner 方案**(§4.1 step4),届时再设计。
5. 确认线上 `settleFees` 的 nonce 去重语义(决定 §6"合约不改"是否成立)。
6. 确认 acknowledge/充值是否结算硬前置(决定 §5.2 计费授权强度,还是退化为 router 策略信任)。
