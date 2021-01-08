import mysql.connector as mariadb
import os

MYSQL_ROOT_PASSWORD = "MYSQL_ROOT_PASSWORD"
db = mariadb.connect(host="mariadb", user="root", password="root")  # os.environ.get(ROOT_PASSWORD)
sql = db.cursor()
sql.execute("DROP DATABASE IF EXISTS db;")
sql.execute("CREATE DATABASE db;")
sql.execute("USE db;")

sql.execute("DROP TABLE IF EXISTS users;")
sql.execute("CREATE TABLE users (login VARCHAR(32), password VARCHAR(128), name VARCHAR(32), surname VARCHAR(32), email VARCHAR(64), birthDate DATE);")
sql.execute("DELETE FROM users;")
sql.execute("INSERT INTO users (login, password, name, surname, email) VALUES ('admin', 'haslo', 'Honey', 'Pot', 'honeypot@alert.com');")
db.commit()

sql.execute("DROP TABLE IF EXISTS session;")
sql.execute("CREATE TABLE session (sid VARCHAR(32), login VARCHAR(32), PRIMARY KEY(sid));")
sql.execute("DELETE FROM session;")


sql.execute("DROP TABLE IF EXISTS posts;")
sql.execute("CREATE TABLE posts (id INT AUTO_INCREMENT, login VARCHAR(32), post VARCHAR(256), PRIMARY KEY(id));")
sql.execute("DELETE FROM posts;")
sql.execute("INSERT INTO posts (login, post, id) VALUES ('bob', 'To jest sekret!', 1);")
db.commit()

sql.execute("DROP TABLE IF EXISTS security_table;")
sql.execute("CREATE TABLE security_table (ip VARCHAR(32), attemps INT, last DATETIME);")
sql.execute("DELETE FROM security_table;")

sql.execute("DROP TABLE IF EXISTS blocked;")
sql.execute("CREATE TABLE blocked (ip VARCHAR(32), until DATETIME);")
sql.execute("DELETE FROM blocked;")
