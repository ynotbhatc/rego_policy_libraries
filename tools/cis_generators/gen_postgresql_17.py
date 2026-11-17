"""Generate the CIS PostgreSQL 17 module. usage: python3 gen_postgresql_17.py <workbook.xlsx> <out_dir>"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_postgresql import main  # noqa: E402

main(17, sys.argv[1], sys.argv[2])
