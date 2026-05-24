#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE 数据处理工具函数"""

import re
from typing import List, Set, Union


# CVE ID 正则表达式
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def clean_cve_ids(cve_input: Union[str, List[str], Set[str]]) -> List[str]:
    """
    清洗和去重 CVE ID 列表

    处理以下问题：
    1. 重复的 CVE ID（如 'CVE-2026-28265  CVE-2026-28265'）
    2. 多余的空格和特殊字符
    3. 大小写不一致
    4. 非法格式的 CVE ID

    Args:
        cve_input: CVE ID 字符串、列表或集合

    Returns:
        清洗后的 CVE ID 列表（去重、标准化格式）

    Examples:
        >>> clean_cve_ids('CVE-2026-28265  CVE-2026-28265')
        ['CVE-2026-28265']

        >>> clean_cve_ids(['CVE-2024-1234', 'cve-2024-5678', 'CVE-2024-1234'])
        ['CVE-2024-1234', 'CVE-2024-5678']

        >>> clean_cve_ids('Some text CVE-2024-1234 and CVE-2024-5678 here')
        ['CVE-2024-1234', 'CVE-2024-5678']
    """
    if not cve_input:
        return []

    # 统一转换为字符串处理
    if isinstance(cve_input, str):
        text = cve_input
    elif isinstance(cve_input, (list, set)):
        # 将列表/集合中的所有元素拼接成一个字符串
        text = ' '.join(str(item) for item in cve_input if item)
    else:
        return []

    # 使用正则表达式提取所有合法的 CVE ID
    matches = CVE_PATTERN.findall(text)

    # 去重并标准化为大写格式
    seen = set()
    cleaned = []

    for cve_id in matches:
        # 标准化为大写
        cve_id_upper = cve_id.upper()

        # 去重
        if cve_id_upper not in seen:
            seen.add(cve_id_upper)
            cleaned.append(cve_id_upper)

    # 按 CVE ID 排序（年份-编号）
    cleaned.sort()

    return cleaned


def extract_cve_ids(text: str) -> List[str]:
    """
    从文本中提取 CVE ID（clean_cve_ids 的别名）

    Args:
        text: 包含 CVE ID 的文本

    Returns:
        清洗后的 CVE ID 列表
    """
    return clean_cve_ids(text)


def validate_cve_id(cve_id: str) -> bool:
    """
    验证 CVE ID 格式是否合法

    Args:
        cve_id: CVE ID 字符串

    Returns:
        True 如果格式合法，否则 False

    Examples:
        >>> validate_cve_id('CVE-2024-1234')
        True

        >>> validate_cve_id('CVE-2024-1234  CVE-2024-5678')
        False

        >>> validate_cve_id('invalid')
        False
    """
    if not cve_id or not isinstance(cve_id, str):
        return False

    # 去除首尾空格后检查
    cve_id = cve_id.strip()

    # 必须完全匹配 CVE 格式，不能包含额外内容
    match = CVE_PATTERN.fullmatch(cve_id)
    return match is not None


if __name__ == "__main__":
    # 测试用例
    print("=== CVE ID 清洗工具测试 ===\n")

    test_cases = [
        # 重复的 CVE ID
        'CVE-2026-28265  CVE-2026-28265',

        # 列表中的重复
        ['CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-1234'],

        # 大小写混合
        ['cve-2024-1234', 'CVE-2024-5678', 'Cve-2024-9999'],

        # 文本中提取
        'Some text CVE-2024-1234 and CVE-2024-5678 here',

        # 空输入
        '',
        [],
        None,

        # 复杂情况：多个 CVE ID 在一个字符串中
        ['CVE-2024-1234  CVE-2024-5678', 'CVE-2024-9999'],
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"测试 {i}: {repr(test)}")
        result = clean_cve_ids(test)
        print(f"结果: {result}\n")

    # 验证测试
    print("=== CVE ID 验证测试 ===\n")
    validation_tests = [
        'CVE-2024-1234',
        'CVE-2024-1234  CVE-2024-5678',
        'cve-2024-1234',
        'invalid',
        '',
        None,
    ]

    for test in validation_tests:
        is_valid = validate_cve_id(test)
        print(f"{repr(test):40} -> {is_valid}")
