"""
展示详细解决方案的示例
"""
from solution_knowledge_base import SolutionKnowledgeBase

def demo():
    kb = SolutionKnowledgeBase()

    print("=" * 80)
    print("CVE 监控系统 - 详细解决方案演示")
    print("=" * 80)

    # 测试不同类型的漏洞
    test_cases = [
        {
            "title": "远程代码执行漏洞",
            "cve": {
                "cve_id": "CVE-2024-RCE-001",
                "severity": "CRITICAL",
                "description": "Apache Struts remote code execution vulnerability allows attackers to execute arbitrary commands"
            }
        },
        {
            "title": "SQL注入漏洞",
            "cve": {
                "cve_id": "CVE-2024-SQL-002",
                "severity": "HIGH",
                "description": "SQL injection vulnerability in web application allows database access"
            }
        },
        {
            "title": "认证绕过漏洞",
            "cve": {
                "cve_id": "CVE-2024-AUTH-003",
                "severity": "CRITICAL",
                "description": "Authentication bypass vulnerability allows unauthorized access to admin panel"
            }
        }
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"\n{'#' * 80}")
        print(f"示例 {i}: {test['title']}")
        print("#" * 80)

        # 获取简短解决方案
        brief = kb.get_brief_solution(test['cve'])
        print(f"\n简短解决方案（表格显示）:")
        print("-" * 60)
        print(brief)

        # 获取详细解决方案
        detailed = kb.get_detailed_solution(test['cve'])
        print(f"\n详细解决方案:")
        print("-" * 60)
        print(detailed)

        input(f"\n按 Enter 继续查看下一个示例...")

if __name__ == "__main__":
    demo()