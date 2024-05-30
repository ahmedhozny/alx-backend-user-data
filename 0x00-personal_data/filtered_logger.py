#!/usr/bin/env python3
"""
Filtered logging module
"""
import os
import re
from typing import List
import logging

from mysql import connector


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Constructor of RedactingFormatter
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        formats a LogRecord.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def extract(x: List[str], y: str) -> str:
    """
    Creates a regex pattern to extract specified fields.
    """
    return r'(?P<field>{})=[^{}]*'.format('|'.join(x), y)


def replace(x):
    """
    Creates a replacement pattern for redacted fields.
    """
    return r'\g<field>={}'.format(x)


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
) -> str:
    """Filters a log line."""
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """
    Creates a new logger for user data.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db() -> connector.connection.MySQLConnection:
    """
    Creates a connector to a database.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """
    Main function that retrieves user data from the database and logs it.
    """
    columns = [
        'name', 'email', 'phone', 'ssn',
        'password', 'ip', 'last_login', 'user_agent'
    ]
    query = "SELECT {} FROM users;".format(",".join(columns))
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            get_logger().handle(log_record)


if __name__ == "__main__":
    main()
