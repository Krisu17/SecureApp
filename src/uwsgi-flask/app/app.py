import time, os, re
from flask import Flask, render_template, send_file, request, jsonify, redirect, url_for, abort, session, make_response
import hashlib
import bcrypt
import base64
import json
from datetime import datetime
from .mariadb_dao import MariaDBDAO

APP_SECRET = "APP_SECRET"

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.secret_key = os.environ.get(APP_SECRET)


dao = MariaDBDAO("mariadb")

GET = "GET"
POST = "POST"
PEPPER = "PASSWORD_PEPPER"


@app.route('/')
def index():
    return make_response(render_template("index.html"))

@app.route('/login')
def login():
    return make_response(render_template("login.html"))

@app.route('/register', methods=[GET])
def register():
    return make_response(render_template("register.html"))

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
    if(True):
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


# def checkRegisterForm(request):
#     if (len(request.get("login")) > 32 or
#     len(registerForm.get("name")) > 32 or
#     len(registerForm.get("surname")) > 32 or
#     len(registerForm.get("email")) > 64 or
#     len(registerForm.get("birthDate")) > 32 )
#     ):
#         return False
#     else:
#         return True

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
        time.sleep(2)
        if(dao.isIpBlocked(loginForm.remote_addr) is None):
            cryptedPassFromDb = dao.getCryptedPassword(login)
            if(cryptedPassFromDb is not None):
                passwordHashedOnce = hashlib.sha256(password.encode('utf-8'))
                passwordHashedTwice = hashlib.sha256((passwordHashedOnce.hexdigest() + os.environ.get(PEPPER)).encode('utf-8'))
                passwordHashedTriple = hashlib.sha256((passwordHashedTwice.hexdigest().encode('utf-8')))
                if(bcrypt.checkpw(passwordHashedTriple.hexdigest().encode('utf-8'), cryptedPassFromDb.encode('utf-8'))):
                    dao.resetSecurityRecord(loginForm.remote_addr)
                    session['username'] = login
                    del passwordHashedOnce
                    del passwordHashedTwice
                    del passwordHashedTriple
                    del cryptedPassFromDb
                    response = make_response("Logged successfully", 200)
                    response.headers['server'] = None
                    return response
            else:
                if(dao.incrLoggingAttemps(loginForm.remote_addr)):
                    response = make_response("Bad request", 400)
                    response.headers['server'] = None
                    return response
                else:
                    response = make_response("User is blocked", 403)
                    response.headers['server'] = None
                    return response
        else:
            dao.incrLoggingAttemps(loginForm.remote_addr)
            response = make_response("User is blocked", 403)
            response.headers['server'] = None
            return response
    else:
        if(dao.incrLoggingAttemps(loginForm.remote_addr)):
            response = make_response("Bad request", 400)
            response.headers['server'] = None
            return response
        else:
            response = make_response("User is blocked", 403)
            response.headers['server'] = None
            return response

# def checkLoginForm(request):
#     if (len(request.get("login")) > 32):
#         return False
#     else:
#         return True