import sqlite3
import os
import re
import yaml
from icecream import ic
from pathlib import Path

ROOT = Path.cwd()


def extract_date_from_name(name):
    # Define a regular expression pattern to match dates in the 'Name' field
    pattern = r'CVE-(\d{4})-\d{4,7}'
    match = re.search(pattern, name)

    if match:
        return match.group(1)
    else:
        return None


# Connect to your SQLite database
conn = sqlite3.connect(os.path.join(ROOT, 'Logs', 'cve_database.sqlite3'))
cursor = conn.cursor()
conn.create_function("extract_date", 1, extract_date_from_name)

# Define the search term
search_terms = """
companies:
  - Siemens
  - ABB
  - Schneider
  - Rockwell
  - Honeywell
  - Emerson
  - Yokogawa
  - GE

industrial_protocols:
  - Modbus
  - EtherNet/IP
  - Profinet
  - HART
  - OPC
  - DNP3
  - MQTT
  - LORAWAN

industrial_firewall_and_security_devices:
  - Cisco
  - Moxa
  - Hirschmann
  - Westermo
  - Scalance
  - Tofino
  - Palo Alto
  - Fortinet
  - Check Point
  
operating_systems:
  - Windows XP
  - Windows 10
  - Windows Server
  - RHEL
  - Debian
  - OS X
"""

search_terms = yaml.load(search_terms, Loader=yaml.FullLoader)

arr = []
for category, terms in search_terms.items():
    for search_term in terms:
        # Create the SQL query with placeholders
        sql = """
            SELECT "{}" AS search_term, extract_date(Name), Count(Name) AS CVE_Count
            FROM cve_items
            WHERE
                Status LIKE ? OR
                Description LIKE ? OR
                `References` LIKE ? OR
                Phase LIKE ? OR
                Votes LIKE ? OR
                Comments LIKE ?
            GROUP BY 2 ORDER BY 2 
        """.format(search_term)

        # Execute the query with placeholders
        cursor.execute(sql, ('%' + search_term + '%',) * 6)  # Use the search_term 6 times for each placeholder

        # Fetch and print the results
        results = cursor.fetchall()
        for search_term, dt, cve_count in results:
            if dt != '2023':
                arr.append([category, search_term, dt, cve_count])


conn.execute('DROP TABLE IF EXISTS CVEs')
conn.commit()


# Create a table to store the data
cursor.execute('''
    CREATE TABLE IF NOT EXISTS CVEs (
        category TEXT,
        company TEXT,
        year TEXT,
        count INTEGER
    )
''')

# Insert data into the table
cursor.executemany('INSERT INTO CVEs VALUES (?, ?, ?, ?)', arr)

# Commit the changes and close the database
conn.commit()
conn.close()
