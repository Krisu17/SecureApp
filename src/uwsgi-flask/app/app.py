import time, os, re
from flask import Flask, render_template, send_file, request, jsonify, redirect, url_for, abort, session, make_response
import hashlib
import bcrypt
import base64
import json
from datetime import datetime
from .mariadb_dao import MariaDBDAO
from secrets import token_urlsafe

APP_SECRET = "APP_SECRET"

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.secret_key = os.environ.get(APP_SECRET)


dao = MariaDBDAO("mariadb")

GET = "GET"
POST = "POST"
PEPPER = "PASSWORD_PEPPER"
URL = "https://localhost/"


@app.route('/')
def index():
    if ('username' in session.keys()):
        isValidCookie = True
    else:
        isValidCookie = False
    response = make_response(render_template("index.html", isValidCookie=isValidCookie))
    response.headers['server'] = None
    return response

@app.route('/login')
def login():
    if ('username' in session.keys()):
        isValidCookie = True
    else:
        isValidCookie = False
    response = make_response(render_template("login.html", isValidCookie=isValidCookie))
    response.headers['server'] = None
    return response

@app.route('/register', methods=[GET])
def register():
    if ('username' in session.keys()):
        isValidCookie = True
    else:
        isValidCookie = False
    response = make_response(render_template("register.html", isValidCookie=isValidCookie))
    response.headers['server'] = None
    return response

@app.route('/add_note', methods=[GET])
def add():
    if ('username' in session.keys()):
        isValidCookie = True
        response = make_response(render_template("add.html", isValidCookie=isValidCookie))
        response.headers['server'] = None
        return response
    else:
        abort(403)
    

@app.route('/password_recovery', methods=[GET])
def password_recovery():
    response = make_response(render_template("password_recovery.html"))
    response.headers['server'] = None
    return response

@app.route('/reset_password', methods=[POST])
def reset_password():
    resetForm = request.form
    login = dao.returnLoginToPassRecovery(resetForm.get("birthDate"), resetForm.get("email"))
    if (login is not None):
        urlToReset = token_urlsafe(64)
        dao.addSafeUrl(login, urlToReset)
        print("=================================================")
        print("------------------Wysyłam link:------------------")
        print(URL + "reset_urls/" + urlToReset)
        print("--------------------Na adres:--------------------")
        print(resetForm.get("email"))
        print("=================================================")
    response = make_response("OK", 200)
    response.headers['server'] = None
    return response

@app.route("/fetchall")
def fetchall():
    all = dao.fetchAll()
    print(all)
    return ("OK",200)

@app.route('/reset_urls/<string:token_url>', methods=[GET])
def reset_urls(token_url):
    login = dao.ifCorrectReturnLoginToPassRecovery(token_url)
    if(login is not None):
        response = make_response(render_template("password_recovery_form.html", login=login, token_url=token_url))
        response.headers['server'] = None
        return response
    response = make_response("Not found", 404)
    response.headers['server'] = None
    return response

@app.route('/reset_password/<string:token_url>', methods=[POST])
def reset_password_url(token_url):
    login = dao.ifCorrectReturnLoginToPassRecovery(token_url)
    if(login is not None):
        registerForm = request.form
        if (registerForm.get("password") is None):
            response = make_response("Bad request", 400)
            response.headers['server'] = None
            return response
        passwordHashedOnce = hashlib.sha256((registerForm.get("password")).encode('utf-8'))
        passwordHashedTwice = hashlib.sha256((passwordHashedOnce.hexdigest() + os.environ.get(PEPPER)).encode('utf-8'))
        passwordHashedTriple = hashlib.sha256((passwordHashedTwice.hexdigest().encode('utf-8')))
        salt = bcrypt.gensalt()
        passwordBcrypted = bcrypt.hashpw(passwordHashedTriple.hexdigest().encode('utf-8'), salt) 
        dao.setNewPassword(login, passwordBcrypted)
        del passwordHashedOnce
        del passwordHashedTwice
        del passwordHashedTriple
        del salt
        del passwordBcrypted
        response = make_response("Password changed", 201)
        response.headers['server'] = None
        return response
    else:
        response = make_response("Not found", 404)
        response.headers['server'] = None
        return response

@app.route("/logout")
def logout():
    if ('username' in session.keys()):
        session.pop('username',None)
    return redirect("/")

@app.route('/register_new_user', methods=[POST])
def register_new_user():
    registerForm = request.form
    if(registerForm.get("login") is None or
    registerForm.get("password") is None or
    registerForm.get("name") is None or
    registerForm.get("surname") is None or
    registerForm.get("email") is None or
    registerForm.get("birthDate") is None ) :
        response = make_response("Bad request", 400)
        response.headers['server'] = None
        return response
    if(True): # to inspekt
        passwordHashedOnce = hashlib.sha256((registerForm.get("password")).encode('utf-8'))
        passwordHashedTwice = hashlib.sha256((passwordHashedOnce.hexdigest() + os.environ.get(PEPPER)).encode('utf-8'))
        passwordHashedTriple = hashlib.sha256((passwordHashedTwice.hexdigest().encode('utf-8')))

        salt = bcrypt.gensalt()
        passwordBcrypted = bcrypt.hashpw(passwordHashedTriple.hexdigest().encode('utf-8'), salt) 
        dao.setNewlyRegisteredUser(registerForm.get("login"), passwordBcrypted, registerForm.get("name"), registerForm.get("surname"),  registerForm.get("email"), registerForm.get("birthDate"))
        del passwordHashedOnce
        del passwordHashedTwice
        del passwordHashedTriple
        del salt
        del passwordBcrypted
        response = make_response("User created", 201)
        response.headers['server'] = None
        return response
    else:
        response = make_response("Bad request", 400)
        response.headers['server'] = None
        return response


@app.route('/register/<string:login>')
def checkLoginAvailability(login):
    if(dao.checkLoginAvailability(login) is None):
        response = make_response("User not found", 404)
        response.headers['server'] = None
        return response
    else:
        response = make_response("User found", 200)
        response.headers['server'] = None
        return response


@app.route('/login_user', methods=[POST])
def login_user():
    if(True):
        loginForm = request.form
        login = loginForm.get("login")
        password = loginForm.get("password")
        time.sleep(1)
        if(dao.isIpBlocked(request.remote_addr) is None):
            cryptedPassFromDb = dao.getCryptedPassword(login)
            if(cryptedPassFromDb is not None):
                passwordHashedOnce = hashlib.sha256(password.encode('utf-8'))
                passwordHashedTwice = hashlib.sha256((passwordHashedOnce.hexdigest() + os.environ.get(PEPPER)).encode('utf-8'))
                passwordHashedTriple = hashlib.sha256((passwordHashedTwice.hexdigest().encode('utf-8')))
                if(bcrypt.checkpw(passwordHashedTriple.hexdigest().encode('utf-8'), cryptedPassFromDb.encode('utf-8'))):
                    dao.resetSecurityRecord(request.remote_addr)
                    session['username'] = login
                    del passwordHashedOnce
                    del passwordHashedTwice
                    del passwordHashedTriple
                    del cryptedPassFromDb
                    response = make_response("Logged successfully", 200)
                    response.headers['server'] = None
                    return response
            else:
                if(dao.incrLoggingAttemps(request.remote_addr)):
                    response = make_response("Bad request", 400)
                    response.headers['server'] = None
                    return response
                else:
                    response = make_response("User is blocked", 403)
                    response.headers['server'] = None
                    return response
        else:
            dao.incrLoggingAttemps(request.remote_addr)
            response = make_response("User is blocked", 403)
            response.headers['server'] = None
            return response
    else:
        if(dao.incrLoggingAttemps(request.remote_addr)):
            response = make_response("Bad request", 400)
            response.headers['server'] = None
            return response
        else:
            response = make_response("User is blocked", 403)
            response.headers['server'] = None
            return response



@app.errorhandler(400)
def bad_request(error):
    response = make_response(render_template("400.html", error=error))
    return response

@app.errorhandler(401)
def unauthorized(error):
    response = make_response(render_template("401.html", error=error))
    return response

@app.errorhandler(403)
def forbidden(error):
    response = make_response(render_template("403.html", error=error))
    return response

@app.errorhandler(404)
def page_not_found(error):
    response = make_response(render_template("404.html", error=error))
    return response

@app.errorhandler(500)
def internal_server_error(error):
    response = make_response(render_template("500.html", error=error))
    return response

