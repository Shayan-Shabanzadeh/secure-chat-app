import sqlite3

# Establish a connection to the database
conn = sqlite3.connect('server_database.db')
cursor = conn.cursor()

# Execute the SQL query to delete the column
cursor.execute('''
    ALTER TABLE groups
    ADD COLUMN admin VARCHAR(255);
''')

# Commit the changes and close the connection
conn.commit()
conn.close()