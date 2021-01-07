import time
import flask
import mysql.connector as mariadb
class MariaDBDAO:
  def deny_semicolon(self, *args):
    for arg in args:
      if not isinstance(arg, str):
        continue
      if ';' in arg:
        raise mariadb.InterfaceError("Multiple statements are forbidden")

  def connect(self, host, user, password):
    try:
      db = mariadb.connect(host=host,user="root",password="root")
      sql = db.cursor(buffered=True)
      sql.execute("USE mysql")
      sql.execute("SELECT 1")
      sql.fetchall()
      return db
    except Exception as err:
      print(f"Error while connecting with MariaDB: {err}")
      time.sleep(3)
      return None
  
  def choose_database(self, database):
    try:
      sql = self.db.cursor(buffered=True)
      sql.execute(f"USE {database}")
      sql.execute("SELECT 1")
      sql.fetchall()
      return sql
    except Exception as err:
      print(f"Error while choosing DB with MariaDB: {err}")
      print(f"Initiating database")
      import app.init_mariadb
      time.sleep(3)
      return None

  def __init__(self, hostname):
    self.db = None
    self.sql = None
    while self.db is None:
      self.db = self.connect(hostname, "root", "root")
    while self.sql is None:
      self.sql = self.choose_database("db")
    print("Connected to MariaDB")
    
  def get_username(self, sid):
    try:
      self.deny_semicolon(sid)
      self.sql.execute(f"SELECT username FROM session WHERE sid = '{sid}'")
      username, = self.sql.fetchone() or (None,)
      return username
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None

  def get_password(self, username):
    try:
      self.deny_semicolon(username)
      print(f"SELECT password FROM user WHERE username = '{username}'")
      self.sql.execute(f"SELECT password FROM user WHERE username = '{username}'")
      password, = self.sql.fetchone() or (None,)
      return password
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None

  def set_session(self, sid, username):
    try:
      self.deny_semicolon(sid, username)
      self.sql.execute(f"INSERT INTO session (sid, username) VALUES ('{sid}', '{username}')")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def add_post(self, username, post):
    try:
      self.deny_semicolon(username, post)
      self.sql.execute(f"INSERT INTO posts (username, post) VALUES ('{username}', '{post}')")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def get_posts(self, username):
    try:
      self.deny_semicolon(username)
      self.sql.execute(f"SELECT post FROM posts WHERE username = '{username}' ORDER BY id DESC")
      posts = self.sql.fetchmany(size=4)
      if len(posts) == 0:
        return ["(nie masz postów)"]
      return [post for post, in posts]
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return []

  def get_post(self, username, index):
    try:
      self.deny_semicolon(username, index)
      self.sql.execute(f"SELECT post FROM posts WHERE username = '{username}' AND id = {index}")
      post, = self.sql.fetchone() or (None,)
      return post
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None