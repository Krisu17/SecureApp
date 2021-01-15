import mysql.connector as mariadb
import os

MYSQL_ROOT_PASSWORD = "MYSQL_ROOT_PASSWORD"
db = mariadb.connect(host="mariadb", user="root", password=os.environ.get(MYSQL_ROOT_PASSWORD))  # 
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
db.commit()

sql.execute("DROP TABLE IF EXISTS notes;")
sql.execute("CREATE TABLE notes (id INT AUTO_INCREMENT, login VARCHAR(32), title VARCHAR(128), text VARCHAR(256), iv VARCHAR(32), salt VARCHAR(32), filename VARCHAR(64), uuidFileName VARCHAR(64), PRIMARY KEY(id));")
sql.execute("DELETE FROM notes;")
db.commit()

sql.execute("DROP TABLE IF EXISTS public_notes;")
sql.execute("CREATE TABLE public_notes (id INT AUTO_INCREMENT, login VARCHAR(32), title VARCHAR(128), text VARCHAR(256), iv VARCHAR(32), salt VARCHAR(32), filename VARCHAR(64), uuidFileName VARCHAR(64), PRIMARY KEY(id));")
sql.execute("DELETE FROM public_notes;")
sql.execute("INSERT INTO public_notes (login, title, text, filename) VALUES ('bob', 'To jest sekret!', 'text sekretu publicznego', '');")
db.commit()

sql.execute("DROP TABLE IF EXISTS security_table;")
sql.execute("CREATE TABLE security_table (id INT AUTO_INCREMENT, ip VARCHAR(32), attemps INT, last DATETIME, PRIMARY KEY(id));")
sql.execute("DELETE FROM security_table;")
db.commit()

sql.execute("DROP TABLE IF EXISTS blocked;")
sql.execute("CREATE TABLE blocked (ip VARCHAR(32), until DATETIME);")
sql.execute("DELETE FROM blocked;")
db.commit()

sql.execute("DROP TABLE IF EXISTS reset_urls;")
sql.execute("CREATE TABLE reset_urls (login VARCHAR(32), url VARCHAR(128), until DATETIME);")
sql.execute("DELETE FROM reset_urls;")
db.commit()