import csv
import sqlite3
import os
from pathlib import Path

ROOT = Path.cwd()

# Connect to SQLite3 database (this will create a new database file named 'cve_database.db')
conn = sqlite3.connect(os.path.join(ROOT, 'cve_database.sqlite3'))
cursor = conn.cursor()

# Create a new table named 'cve_items'
cursor.execute('''CREATE TABLE IF NOT EXISTS cve_items
                  (Name TEXT, Status TEXT, Description TEXT, `References` TEXT, Phase TEXT, Votes TEXT, Comments TEXT)''')

# Open and read the CSV file
with open(os.path.join(ROOT, 'allitems.csv'), 'r', encoding='utf-8', errors="replace") as csvfile:
    reader = csv.reader(csvfile, delimiter=',', quotechar='"')
    next(reader)  # Skip the header row

    # Insert data into the SQLite3 database
    for row in reader:
        try:
            cursor.execute("INSERT INTO cve_items VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (row[0], row[1], row[2], row[3], row[4], row[5], row[6]))
        except:
            pass

# Commit the transaction and close the connection
conn.commit()
conn.close()
