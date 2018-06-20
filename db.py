import MySQLdb

conn = MySQLdb.connect(user='root', password='', host='localhost', database='zabbix')
cur = conn.cursor()
cur.execute("select * from users;")
for row in cur.fetchall():
    print(row[0],row[1])
cur.close
conn.close