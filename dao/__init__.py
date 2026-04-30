"""数据访问层 (DAO) 包

将所有数据库操作集中管理，实现关注点分离。
GUI 层通过 DAO 接口访问数据，不直接写 SQL。

使用方式:
    from dao import CveDAO, DellAdvisoryDAO, DellKbDAO

    cve_dao = CveDAO(conn)
    cve = cve_dao.get_by_id("CVE-2024-1234")
"""
from dao.cve_dao import CveDAO
from dao.dell_dao import DellAdvisoryDAO
from dao.dell_kb_dao import DellKbDAO

__all__ = ['CveDAO', 'DellAdvisoryDAO', 'DellKbDAO']
