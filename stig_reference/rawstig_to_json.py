#!/usr/bin/env python3

# Convert STIG.zip files like those from https://cyber.trackr.live/stig/Oracle_Database_19c/1/5
# Thanks to https://github.com/pkeech/stig_parser
#
# python3 -m venv .venv
# source .vent/bin/activate
# python3 -m pip install stig_parser
# python3 (this_file)

## LOAD PYTHON MODULE
from stig_parser import convert_xccdf
from stig_parser import convert_stig
import json
import os

## PARSE STIG ZIP FILE
## ASSUMES ZIP FILE IS IN CURRENT WORKING DIRECTORY
#json_results = convert_stig('./U_Oracle_Database_12c_V2R9_STIG.zip')

## LOAD XML FILE (OPTIONAL)
import os

with open("U__Oracle_Database_12c_V1R2_Manual-xccdf.xml", "r") as fh:
    raw_file = fh.read()

## PARSE XCCDF(XML) to JSON
json_results = convert_xccdf(raw_file)

with open ("oracle_database_12c_stig_v1r2_controls.json", "w") as file:
    json.dump(json_results, file, indent=4)


