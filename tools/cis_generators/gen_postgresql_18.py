"""Generate the CIS PostgreSQL 18 module. usage: python3 gen_postgresql_18.py <workbook.xlsx> <out_dir>"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_postgresql import main  # noqa: E402

main(18, sys.argv[1], sys.argv[2])
