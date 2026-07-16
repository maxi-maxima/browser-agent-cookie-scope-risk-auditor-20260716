# 浏览器 Agent Cookie 范围风险审计器

## 解决的痛点
把登录 Cookie 交给浏览器 Agent 前，很难快速判断作用域是否过宽。

## 为什么现在值得做
浏览器自动化 Agent 走热，真实会话安全成为落地阻塞点。

## 安装/运行
```bash
python -m browser_agent_cookie_scope_risk_auditor_20260716 examples/cookies.json
```

## 策略模式
使用 `--allow-domain` 指定允许交给浏览器 Agent 的域名；可以重复传多个域名。CI 中可加 `--strict`，当发现高风险 Cookie 时以退出码 `2` 失败。

```bash
python -m browser_agent_cookie_scope_risk_auditor_20260716 examples/cookies.json --allow-domain example.com --strict
```

JSON 报告现在包含 `flag_counts`，会统计过期 Cookie 和域名白名单外 Cookie。

## 示例
输入 cookie JSON，输出宽域名、非 HttpOnly、弱 SameSite 等风险。

## 路线图
- HAR 导入
- 域名白名单策略
- 过期时间评分

MIT License
