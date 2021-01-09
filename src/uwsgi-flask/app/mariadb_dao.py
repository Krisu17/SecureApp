import time
import os
import flask
import mysql.connector as mariadb
MYSQL_ROOT_PASSWORD = "MYSQL_ROOT_PASSWORD"


class MariaDBDAO:
  def deny_semicolon(self, *args):
    for arg in args:
      if not isinstance(arg, str):
        continue
      if ';' in arg:
        raise mariadb.InterfaceError("Multiple statements are forbidden")

  def connect(self, host, user, password):
    try:
      db = mariadb.connect(host=host,user=user,password=password)
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
      self.db = self.connect(hostname, "root", os.environ.get(MYSQL_ROOT_PASSWORD))
    while self.sql is None:
      self.sql = self.choose_database("db")
    print("Connected to MariaDB")

  def setNewlyRegisteredUser(self, login, crypted_password, name, surname, email, birthDate):
    try:
      self.deny_semicolon(login, crypted_password, name, surname, email, birthDate)
      self.sql.execute(f"INSERT INTO users (login, password, name, surname, email, birthDate) VALUES ('{login}', '{crypted_password}', '{name}', '{surname}', '{email}', '{birthDate}')")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def setNewPassword(self, login, crypted_password):
    try:
      self.deny_semicolon(login, crypted_password)
      self.sql.execute(f"UPDATE users SET password = '{crypted_password}' WHERE login = '{login}'")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def isIpBlocked(self, ip):
    try:
      self.sql.execute(f"SELECT ip FROM blocked WHERE until > NOW()")
      ip, = self.sql.fetchone() or (None,)
      return ip
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
  
  def incrLoggingAttemps(self, ip):
    try:
      self.sql.execute(f"SELECT attemps FROM security_table WHERE ip = '{ip}'")
      attemps, = self.sql.fetchone() or (None,)
      if(attemps is None):
        self.sql.execute(f"INSERT INTO security_table (ip, attemps, last) VALUES ('{ip}', 1, NOW())")
        self.db.commit()
      else:  
        self.sql.execute(f"SELECT attemps FROM security_table WHERE ip = '{ip}' AND last + INTERVAL 5 MINUTE > NOW()")
        attemps, = self.sql.fetchone() or (None,)
        if(attemps is None):
          self.sql.execute(f"UPDATE security_table SET attemps = 1 WHERE ip = '{ip}'")
        else:
          if(attemps == 5):
            self.blockUser(ip)
            return False
          else:
            attemps = attemps + 1
            self.sql.execute(f"UPDATE security_table SET attemps = {attemps} WHERE ip = '{ip}'")
        self.sql.execute(f"UPDATE security_table SET last = NOW() WHERE ip = '{ip}'")
        self.db.commit()
        return True
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
      return False

  def blockUser(self, ip):
    try:
      self.sql.execute(f"SELECT ip FROM blocked WHERE ip = '{ip}' ")
      ips, = self.sql.fetchone() or (None,)
      if(ips is None):
        self.sql.execute(f"INSERT INTO blocked (ip, until) VALUES ('{ip}', NOW() + INTERVAL 1 MINUTE)")
        self.db.commit()
      else:
        self.sql.execute(f"UPDATE blocked SET until = NOW() + INTERVAL 1 MINUTE WHERE ip = '{ip}'")
        self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def resetSecurityRecord(self, ip):
    try:
      self.sql.execute(f"SELECT attemps FROM security_table WHERE ip = '{ip}' AND last + INTERVAL 5 MINUTE > NOW()")
      attemps, = self.sql.fetchone() or (None,)
      if(attemps is None):
        self.sql.execute(f"UPDATE security_table SET attemps = 0 WHERE ip = '{ip}'")
        self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def checkLoginAvailability(self, login):
    try:
      self.deny_semicolon(login)
      self.sql.execute(f"SELECT login FROM users WHERE login = '{login}'")
      login, = self.sql.fetchone() or (None,)
      return login
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None

  def fetchAll(self):
    self.sql.execute(f"SELECT * FROM reset_urls")
    all, = self.sql.fetchmany() or (None,)
    return all


  def returnLoginToPassRecovery(self, birthDate, email):
    try:
      self.deny_semicolon(birthDate, email)
      self.sql.execute(f"SELECT login FROM users WHERE birthDate = '{birthDate}' AND email = '{email}'")
      login, = self.sql.fetchone() or (None,)
      return login
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None

  def addSafeUrl(self, login, url):
    try:
      self.sql.execute(f"SELECT login FROM reset_urls WHERE login = '{login}'")
      login, = self.sql.fetchone() or (None,)
      if(login is None):
        self.sql.execute(f"INSERT INTO reset_urls (login, url, until) VALUES ('{login}', '{url}', NOW() + INTERVAL 10 MINUTE)")
      else:
        self.sql.execute(f"UPDATE reset_urls SET url = '{url}' WHERE login = '{login}'")
        self.sql.execute(f"UPDATE reset_urls SET until = NOW() + INTERVAL 10 MINUTE WHERE login = '{login}'")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}") 

  def ifCorrectReturnLoginToPassRecovery(self, url):
    try:
      self.deny_semicolon(url)
      self.sql.execute(f"SELECT login FROM reset_urls WHERE url = '{url}' AND until > NOW()")
      login, = self.sql.fetchone() or (None,)
      return login
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}") 

  def get_login(self, sid):
    try:
      self.deny_semicolon(sid)
      self.sql.execute(f"SELECT login FROM session WHERE sid = '{sid}'")
      login, = self.sql.fetchone() or (None,)
      return login
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None

  def getCryptedPassword(self, login):
    try:
      self.deny_semicolon(login)
      self.sql.execute(f"SELECT password FROM users WHERE login = '{login}'")
      password, = self.sql.fetchone() or (None,)
      return password
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None

  def set_session(self, sid, login):
    try:
      self.deny_semicolon(sid, login)
      self.sql.execute(f"INSERT INTO session (sid, login) VALUES ('{sid}', '{login}')")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def add_post(self, login, post):
    try:
      self.deny_semicolon(login, post)
      self.sql.execute(f"INSERT INTO posts (login, post) VALUES ('{login}', '{post}')")
      self.db.commit()
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")

  def get_posts(self, login):
    try:
      self.deny_semicolon(login)
      self.sql.execute(f"SELECT post FROM posts WHERE login = '{login}' ORDER BY id DESC")
      posts = self.sql.fetchmany(size=4)
      if len(posts) == 0:
        return ["(nie masz postów)"]
      return [post for post, in posts]
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return []

  def get_post(self, login, index):
    try:
      self.deny_semicolon(login, index)
      self.sql.execute(f"SELECT post FROM posts WHERE login = '{login}' AND id = {index}")
      post, = self.sql.fetchone() or (None,)
      return post
    except mariadb.Error as err:
      flask.flash(f"Database error: {err}")
    return None