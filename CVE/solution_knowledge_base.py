"""
CVE 解决方案知识库
包含详细的解决方案模板和具体操作步骤
"""

class SolutionKnowledgeBase:
    """CVE 解决方案知识库"""

    def __init__(self):
        # 详细的解决方案模板
        self.solutions = {
            "remote_code_execution": {
                "title": "远程代码执行漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-24小时内修复】",
                    "HIGH": "【高危-72小时内修复】",
                    "MEDIUM": "【中危-7天内修复】",
                    "LOW": "【低危-30天内修复】"
                },
                "immediate_actions": [
                    "1. 立即隔离受影响系统：断开网络连接，防止攻击扩散",
                    "2. 启用应急响应计划：通知安全团队和管理层",
                    "3. 临时缓解措施：配置防火墙规则，限制访问源IP",
                    "4. 收集日志：保存系统日志、网络日志用于后续分析"
                ],
                "remediation_steps": [
                    "5. 安装官方补丁：访问厂商官网下载对应版本补丁",
                    "6. 验证补丁安装：检查版本号确认补丁已正确安装",
                    "7. 配置入侵检测：部署IDS/IPS规则监控相关攻击模式",
                    "8. 代码审计：检查是否存在类似漏洞的其他代码"
                ],
                "long_term_measures": [
                    "9. 安全加固：实施最小权限原则，关闭不必要的服务",
                    "10. 定期扫描：每周执行漏洞扫描，及时发现新问题",
                    "11. 培训提升：开展安全编码培训，提高开发人员安全意识",
                    "12. 建立流程：制定漏洞管理流程，确保快速响应"
                ],
                "tools": [
                    "推荐工具：Nessus/OpenVAS (漏洞扫描)",
                    "推荐工具：Metasploit (验证测试)",
                    "推荐工具：Wireshark (流量分析)",
                    "推荐工具：SIEM系统 (日志分析)"
                ]
            },

            "sql_injection": {
                "title": "SQL注入漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-立即修复】",
                    "HIGH": "【高危-48小时内修复】",
                    "MEDIUM": "【中危-5天内修复】",
                    "LOW": "【低危-14天内修复】"
                },
                "immediate_actions": [
                    "1. WAF防护：启用Web应用防火墙，配置SQL注入防护规则",
                    "2. 输入验证：临时添加输入长度和字符类型限制",
                    "3. 数据库权限：立即收回不必要的数据库权限",
                    "4. 监控告警：配置数据库审计，监控异常SQL语句"
                ],
                "remediation_steps": [
                    "5. 参数化查询：将所有动态SQL改为预编译语句(PreparedStatement)",
                    "6. 存储过程：使用存储过程替代动态拼接的SQL",
                    "7. 输入过滤：实施白名单验证，拒绝特殊字符(<,>,',\",;等)",
                    "8. 错误处理：自定义错误页面，避免暴露数据库信息"
                ],
                "long_term_measures": [
                    "9. 代码审查：使用静态代码分析工具扫描所有SQL相关代码",
                    "10. 最小权限：为应用创建专用数据库账号，仅授予必要权限",
                    "11. 数据加密：敏感数据采用AES加密存储",
                    "12. 定期测试：每月进行SQL注入渗透测试"
                ],
                "tools": [
                    "推荐工具：SQLMap (漏洞检测)",
                    "推荐工具：ModSecurity (WAF)",
                    "推荐工具：SonarQube (代码审计)",
                    "推荐工具：AppScan (应用扫描)"
                ]
            },

            "cross_site_scripting": {
                "title": "跨站脚本(XSS)漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-24小时内修复】",
                    "HIGH": "【高危-48小时内修复】",
                    "MEDIUM": "【中危-7天内修复】",
                    "LOW": "【低危-14天内修复】"
                },
                "immediate_actions": [
                    "1. CSP策略：配置Content-Security-Policy响应头",
                    "2. WAF规则：启用XSS防护规则，过滤恶意脚本",
                    "3. Cookie安全：设置HttpOnly和Secure标志",
                    "4. 临时过滤：对用户输入进行HTML实体编码"
                ],
                "remediation_steps": [
                    "5. 输出编码：使用框架提供的编码函数(htmlspecialchars等)",
                    "6. DOM净化：使用DOMPurify库清理用户输入",
                    "7. 模板引擎：使用自动编码的模板引擎(如React、Vue)",
                    "8. 验证框架：实施输入验证框架(如OWASP Java Encoder)"
                ],
                "long_term_measures": [
                    "9. 安全框架：采用具有XSS防护的现代Web框架",
                    "10. 代码规范：制定安全编码规范，强制输出编码",
                    "11. 自动化测试：集成XSS扫描到CI/CD流程",
                    "12. 安全培训：定期开展XSS防护培训"
                ],
                "tools": [
                    "推荐工具：XSSer (漏洞检测)",
                    "推荐工具：BeEF (XSS利用框架)",
                    "推荐工具：OWASP ZAP (Web扫描)",
                    "推荐工具：Burp Suite (渗透测试)"
                ]
            },

            "buffer_overflow": {
                "title": "缓冲区溢出漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-立即修复】",
                    "HIGH": "【高危-24小时内修复】",
                    "MEDIUM": "【中危-72小时内修复】",
                    "LOW": "【低危-7天内修复】"
                },
                "immediate_actions": [
                    "1. 系统隔离：隔离受影响的系统和服务",
                    "2. ASLR启用：开启地址空间随机化(ASLR)",
                    "3. DEP启用：启用数据执行保护(DEP/NX)",
                    "4. 监控部署：部署入侵检测系统监控异常行为"
                ],
                "remediation_steps": [
                    "5. 补丁安装：立即安装厂商提供的安全补丁",
                    "6. 代码修复：使用安全的函数(strncpy代替strcpy)",
                    "7. 边界检查：添加输入长度验证和边界检查",
                    "8. 编译选项：使用-fstack-protector编译选项"
                ],
                "long_term_measures": [
                    "9. 安全编译：使用GCC的-D_FORTIFY_SOURCE=2",
                    "10. 代码审计：使用静态分析工具检查不安全函数",
                    "11. Fuzzing测试：定期进行模糊测试",
                    "12. 内存安全语言：考虑使用Rust等内存安全语言"
                ],
                "tools": [
                    "推荐工具：Valgrind (内存检测)",
                    "推荐工具：AddressSanitizer (内存错误检测)",
                    "推荐工具：AFL (模糊测试)",
                    "推荐工具：IDA Pro (二进制分析)"
                ]
            },

            "denial_of_service": {
                "title": "拒绝服务(DoS)漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-立即缓解】",
                    "HIGH": "【高危-4小时内缓解】",
                    "MEDIUM": "【中危-24小时内缓解】",
                    "LOW": "【低危-72小时内缓解】"
                },
                "immediate_actions": [
                    "1. 流量限制：配置速率限制(Rate Limiting)",
                    "2. 连接限制：限制单IP最大连接数",
                    "3. CDN防护：启用CDN的DDoS防护功能",
                    "4. 黑名单：封禁攻击源IP地址"
                ],
                "remediation_steps": [
                    "5. 资源限制：设置进程资源使用上限(ulimit)",
                    "6. 超时配置：调整连接和请求超时时间",
                    "7. 队列管理：实现请求队列和优先级机制",
                    "8. 负载均衡：部署负载均衡分散请求压力"
                ],
                "long_term_measures": [
                    "9. 弹性架构：实施自动扩缩容机制",
                    "10. 监控告警：配置性能监控和告警阈值",
                    "11. 容量规划：定期进行压力测试和容量评估",
                    "12. 应急预案：制定DDoS攻击应急响应预案"
                ],
                "tools": [
                    "推荐工具：CloudFlare (DDoS防护)",
                    "推荐工具：fail2ban (自动封禁)",
                    "推荐工具：netstat/ss (连接监控)",
                    "推荐工具：Nagios (性能监控)"
                ]
            },

            "privilege_escalation": {
                "title": "权限提升漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-立即修复】",
                    "HIGH": "【高危-24小时内修复】",
                    "MEDIUM": "【中危-48小时内修复】",
                    "LOW": "【低危-7天内修复】"
                },
                "immediate_actions": [
                    "1. 权限审查：立即审查所有用户和服务账号权限",
                    "2. 账号禁用：临时禁用不必要的高权限账号",
                    "3. 审计启用：开启系统审计日志记录所有权限变更",
                    "4. MFA部署：为管理员账号启用多因素认证"
                ],
                "remediation_steps": [
                    "5. 补丁更新：安装操作系统和应用程序补丁",
                    "6. 权限分离：实施职责分离和最小权限原则",
                    "7. sudo配置：限制sudo权限，使用sudoers精确控制",
                    "8. SUID审查：检查并移除不必要的SUID/SGID位"
                ],
                "long_term_measures": [
                    "9. RBAC实施：部署基于角色的访问控制",
                    "10. PAM配置：强化PAM认证模块配置",
                    "11. 定期审计：每月进行权限审计和复查",
                    "12. 零信任架构：向零信任安全模型迁移"
                ],
                "tools": [
                    "推荐工具：Lynis (系统审计)",
                    "推荐工具：LinPEAS (权限枚举)",
                    "推荐工具：CIS-CAT (合规检查)",
                    "推荐工具：OSSEC (入侵检测)"
                ]
            },

            "authentication_bypass": {
                "title": "认证绕过漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-立即修复】",
                    "HIGH": "【高危-12小时内修复】",
                    "MEDIUM": "【中危-48小时内修复】",
                    "LOW": "【低危-7天内修复】"
                },
                "immediate_actions": [
                    "1. 会话失效：立即使所有现有会话失效",
                    "2. 密码重置：强制所有用户重置密码",
                    "3. 登录监控：监控异常登录行为和地理位置",
                    "4. IP白名单：临时限制管理后台访问IP"
                ],
                "remediation_steps": [
                    "5. 认证修复：修复认证逻辑漏洞，加强验证流程",
                    "6. 会话管理：实施安全的会话管理机制",
                    "7. 令牌安全：使用加密的JWT或随机令牌",
                    "8. 密码策略：强制复杂密码和定期更换"
                ],
                "long_term_measures": [
                    "9. MFA部署：全面部署多因素认证",
                    "10. SSO集成：集成企业单点登录系统",
                    "11. OAuth2/OIDC：采用标准认证协议",
                    "12. 生物识别：考虑引入生物识别认证"
                ],
                "tools": [
                    "推荐工具：Hydra (密码测试)",
                    "推荐工具：John the Ripper (密码审计)",
                    "推荐工具：OWASP ASVS (安全验证)",
                    "推荐工具：Keycloak (身份管理)"
                ]
            },

            "information_disclosure": {
                "title": "信息泄露漏洞",
                "severity_actions": {
                    "CRITICAL": "【极危-立即处理】",
                    "HIGH": "【高危-24小时内处理】",
                    "MEDIUM": "【中危-72小时内处理】",
                    "LOW": "【低危-7天内处理】"
                },
                "immediate_actions": [
                    "1. 信息清理：立即移除泄露的敏感信息",
                    "2. 访问限制：限制对敏感资源的访问",
                    "3. 日志检查：审查访问日志查找可疑活动",
                    "4. 错误页定制：替换默认错误页面"
                ],
                "remediation_steps": [
                    "5. 错误处理：实施统一的错误处理机制",
                    "6. 日志脱敏：对日志中的敏感信息进行脱敏",
                    "7. 响应头安全：移除泄露版本信息的响应头",
                    "8. 目录权限：正确配置文件和目录权限"
                ],
                "long_term_measures": [
                    "9. 数据分类：建立数据分类和标记体系",
                    "10. DLP部署：部署数据泄露防护系统",
                    "11. 加密存储：对敏感数据进行加密存储",
                    "12. 安全培训：加强员工数据安全意识培训"
                ],
                "tools": [
                    "推荐工具：GitGuardian (代码泄露检测)",
                    "推荐工具：TruffleHog (密钥扫描)",
                    "推荐工具：Nikto (Web扫描)",
                    "推荐工具：DLP解决方案 (数据防护)"
                ]
            }
        }

    def get_detailed_solution(self, cve_data):
        """
        生成详细的解决方案

        Args:
            cve_data: CVE数据字典，包含severity和description

        Returns:
            详细的解决方案文本
        """
        severity = cve_data.get("severity", "MEDIUM")
        description = cve_data.get("description", "").lower()

        # 识别漏洞类型
        vuln_type = self._identify_vulnerability_type(description)

        if vuln_type and vuln_type in self.solutions:
            solution = self.solutions[vuln_type]

            # 构建详细解决方案
            detailed_solution = []

            # 严重性行动
            action = solution["severity_actions"].get(severity, "【待评估】")
            detailed_solution.append(f"{action}")
            detailed_solution.append("")

            # 立即行动
            detailed_solution.append("=== 立即行动 ===")
            detailed_solution.extend(solution["immediate_actions"])
            detailed_solution.append("")

            # 修复步骤
            detailed_solution.append("=== 修复步骤 ===")
            detailed_solution.extend(solution["remediation_steps"])
            detailed_solution.append("")

            # 长期措施
            detailed_solution.append("=== 长期措施 ===")
            detailed_solution.extend(solution["long_term_measures"])
            detailed_solution.append("")

            # 推荐工具
            detailed_solution.append("=== 推荐工具 ===")
            detailed_solution.extend(solution["tools"])

            return "\n".join(detailed_solution)
        else:
            # 通用解决方案
            return self._get_generic_solution(severity)

    def get_brief_solution(self, cve_data):
        """
        生成简短的解决方案（用于表格显示）

        Args:
            cve_data: CVE数据字典

        Returns:
            简短的解决方案文本
        """
        severity = cve_data.get("severity", "MEDIUM")
        description = cve_data.get("description", "").lower()

        # 识别漏洞类型
        vuln_type = self._identify_vulnerability_type(description)

        if vuln_type and vuln_type in self.solutions:
            solution = self.solutions[vuln_type]
            action = solution["severity_actions"].get(severity, "【待评估】")

            # 提取关键措施
            key_actions = []
            if severity in ["CRITICAL", "HIGH"]:
                # 安全地提取关键措施
                if solution["immediate_actions"]:
                    action_text = solution["immediate_actions"][0]
                    if ":" in action_text:
                        key_actions.append(action_text.split(":")[1].strip()[:30])
                    else:
                        key_actions.append(action_text.split(".")[1].strip()[:30] if "." in action_text else action_text[:30])

                if solution["remediation_steps"]:
                    step_text = solution["remediation_steps"][0]
                    if ":" in step_text:
                        key_actions.append(step_text.split(":")[1].strip()[:30])
                    else:
                        key_actions.append(step_text.split(".")[1].strip()[:30] if "." in step_text else step_text[:30])
            else:
                if solution["remediation_steps"]:
                    step_text = solution["remediation_steps"][0]
                    if ":" in step_text:
                        key_actions.append(step_text.split(":")[1].strip()[:50])
                    else:
                        key_actions.append(step_text.split(".")[1].strip()[:50] if "." in step_text else step_text[:50])

            if key_actions:
                return f"{action} | {' | '.join(key_actions)}..."
            else:
                return action
        else:
            return self._get_generic_brief_solution(severity)

    def _identify_vulnerability_type(self, description):
        """识别漏洞类型"""
        vuln_patterns = {
            "remote_code_execution": ["remote code execution", "rce", "code execution", "command injection"],
            "sql_injection": ["sql injection", "sqli", "sql", "database"],
            "cross_site_scripting": ["cross-site scripting", "xss", "script injection", "javascript"],
            "buffer_overflow": ["buffer overflow", "stack overflow", "heap overflow", "memory corruption"],
            "denial_of_service": ["denial of service", "dos", "ddos", "resource exhaustion"],
            "privilege_escalation": ["privilege escalation", "elevation of privilege", "local privilege"],
            "authentication_bypass": ["authentication bypass", "auth bypass", "login bypass"],
            "information_disclosure": ["information disclosure", "data leak", "information leak", "exposure"]
        }

        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in description:
                    return vuln_type

        return None

    def _get_generic_solution(self, severity):
        """获取通用解决方案"""
        generic = {
            "CRITICAL": """【极危-立即修复】

=== 立即行动 ===
1. 立即隔离受影响系统
2. 通知安全团队和管理层
3. 启动应急响应流程
4. 收集和保存相关日志

=== 修复步骤 ===
5. 查找并安装官方补丁
6. 如无补丁，实施临时缓解措施
7. 验证修复效果
8. 监控异常行为

=== 长期措施 ===
9. 加强安全监控
10. 定期漏洞扫描
11. 更新安全策略
12. 安全意识培训""",

            "HIGH": """【高危-48小时内修复】

=== 立即行动 ===
1. 评估影响范围
2. 制定修复计划
3. 通知相关团队
4. 加强监控

=== 修复步骤 ===
5. 安装安全补丁
6. 配置安全策略
7. 测试修复效果
8. 更新文档

=== 长期措施 ===
9. 定期更新
10. 安全审计
11. 流程优化""",

            "MEDIUM": """【中危-7天内修复】

=== 修复步骤 ===
1. 评估漏洞影响
2. 制定修复计划
3. 测试环境验证
4. 生产环境部署
5. 监控和验证

=== 长期措施 ===
6. 加入定期更新计划
7. 安全配置审查
8. 文档更新""",

            "LOW": """【低危-30天内修复】

=== 修复步骤 ===
1. 记录漏洞信息
2. 纳入下次更新
3. 测试验证
4. 常规部署

=== 长期措施 ===
5. 定期维护
6. 持续监控"""
        }

        return generic.get(severity, generic["MEDIUM"])

    def _get_generic_brief_solution(self, severity):
        """获取通用简短解决方案"""
        brief = {
            "CRITICAL": "【极危-立即修复】立即隔离系统 | 安装紧急补丁 | 24小时监控",
            "HIGH": "【高危-48小时内修复】评估影响 | 安装补丁 | 加强监控",
            "MEDIUM": "【中危-7天内修复】计划更新 | 测试验证 | 常规部署",
            "LOW": "【低危-30天内修复】纳入更新计划 | 定期维护"
        }

        return brief.get(severity, brief["MEDIUM"])

# 导出知识库实例
solution_kb = SolutionKnowledgeBase()