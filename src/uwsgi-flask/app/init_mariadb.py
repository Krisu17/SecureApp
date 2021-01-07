import mysql.connector as mariadb
db = mariadb.connect(host="mariadb", user="root", password="root")
sql = db.cursor()
sql.execute("DROP DATABASE IF EXISTS db;")
sql.execute("CREATE DATABASE db;")
sql.execute("USE db;")

sql.execute("DROP TABLE IF EXISTS user;")
sql.execute("CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
sql.execute("DELETE FROM user;")
sql.execute("INSERT INTO user (username, password) VALUES ('bach', 'haslo');")
sql.execute("INSERT INTO user (username, password) VALUES ('john', 'snow');")
sql.execute("INSERT INTO user (username, password) VALUES ('bob', 'bob');")
for i in range(1,30):
  sql.execute(f"INSERT INTO user (username, password) VALUES ('user{i}', 'pass');")

sql.execute("DROP TABLE IF EXISTS session;")
sql.execute("CREATE TABLE session (sid VARCHAR(32), username VARCHAR(32), PRIMARY KEY(sid));")
sql.execute("DELETE FROM session;")
sql.execute("INSERT INTO session (sid, username) VALUES ('deadbeef', 'bach');")

sql.execute("DROP TABLE IF EXISTS posts;")
sql.execute("CREATE TABLE posts (id INT AUTO_INCREMENT, username VARCHAR(32), post VARCHAR(256), PRIMARY KEY(id));")
sql.execute("DELETE FROM posts;")
sql.execute("INSERT INTO posts (username, post, id) VALUES ('bob', 'To jest sekret!', 1);")
db.commit()

sql.execute("SELECT username FROM user;")
for u, in sql:
  print(u)

sql.execute("SELECT password FROM user")
print(sql.fetchall())

sql.execute("SELECT password FROM user WHERE username = 'bach'")
pw, = sql.fetchone()
print(pw)