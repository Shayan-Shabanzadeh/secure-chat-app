import sqlite3

# Establish a connection to the database
conn = sqlite3.connect('client_database.db')
cursor = conn.cursor()

# Execute the SQL query to delete the column
cursor.execute('''
    DELETE from Chat
''')

# Commit the changes and close the connection
conn.commit()
conn.close()