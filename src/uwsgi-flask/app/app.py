import time, os, re
from flask import Flask, render_template, send_file, request, jsonify, redirect, url_for, abort, session, make_response
from flask_wtf.csrf import CSRFProtect
import hashlib
import bcrypt
from uuid import uuid4
from base64 import b64decode, b64encode
import json
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from .mariadb_dao import MariaDBDAO
from secrets import token_urlsafe
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import re

APP_SECRET = "APP_SECRET"

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.secret_key = os.environ.get(APP_SECRET)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=300)
app.config['UPLOAD_FOLDER'] = "./app/files"
csrf = CSRFProtect(app)
ACCEPT_EXTENSIONS = {'jpg', 'png', 'jpeg', 'txt', 'pdf'}

dao = MariaDBDAO("mariadb")

GET = "GET"
POST = "POST"
PEPPER = "PASSWORD_PEPPER"
URL = "https://localhost/"


@app.after_request
def add_security_headers(response):
    response.headers['server'] = None
    response.headers['Content-Security-Policy']='default-src \'self\'; font-src \'self\'; style-src \'self\' https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css'
    return response


@app.route('/')
def index():
    if ('username' in session.keys()):
        isValidCookie = True
    else:
        isValidCookie = False
    response = make_response(render_template("index.html", isValidCookie=isValidCookie))
    return response

@app.route('/login')
def login():
    if ('username' in session.keys()):
        isValidCookie = True
    else:
        isValidCookie = False
    response = make_response(render_template("login.html", isValidCookie=isValidCookie))
    return response

@app.route('/register', methods=[GET])
def register():
    if ('username' in session.keys()):
        isValidCookie = True
    else:
        isValidCookie = False
    response = make_response(render_template("register.html", isValidCookie=isValidCookie))
    return response

@app.route('/notes', methods=[GET])
def notes():
    try:
        if ('username' in session.keys()):
            isValidCookie = True
            login = session['username']

            privateNotesId = dao.getPrivateNotesId(login)
            privateNotesLogin = dao.getPrivateNotesLogin(login)
            privateNotesTitle = dao.getPrivateNotesTitle(login)
            privateNotesText = dao.getPrivateNotesText(login)
            privateNotesFilename = dao.getPrivateNotesFilename(login)

            publicNotesId = dao.getPublicNotesId()
            publicNotesLogin = dao.getPublicNotesLogin()
            publicNotesTitle = dao.getPublicNotesTitle()
            publicNotesText = dao.getPublicNotesText()
            publicNotesFilename = dao.getPublicNotesFilename()

            response = make_response(render_template("notes.html", isValidCookie=isValidCookie, privateNotesId=privateNotesId, privateNotesLogin=privateNotesLogin, privateNotesText=privateNotesText, privateNotesTitle=privateNotesTitle, publicNotesId=publicNotesId, publicNotesLogin=publicNotesLogin, publicNotesText=publicNotesText, publicNotesTitle = publicNotesTitle, privateNotesFilename=privateNotesFilename, publicNotesFilename=publicNotesFilename))
            return response
        
        else:
            isValidCookie = False
            response = make_response(render_template("notes.html", isValidCookie=isValidCookie))
            return response
    except Exception as e:
        print("Catched error: ")
        print(e)
        return abort(400)
    


@app.route('/add_note', methods=[GET])
def add():
    if ('username' in session.keys()):
        isValidCookie = True
        response = make_response(render_template("add.html", isValidCookie=isValidCookie))
        return response
    else:
        abort(403)
    
@app.route('/add_new_note', methods=[POST])
def add_new_note():
    try:
        noteForm = request.form
        isWithPassword = noteForm.get("secure_checkbox")
        isPublic = noteForm.get("checkbox_public")
        print("Checkbox public status")
        print(isPublic)
        if(noteForm.get("title") is None or
        noteForm.get("note_text") is None) :
            response = make_response("Bad request", 400)
            return response
        title = noteForm.get("title")
        text = noteForm.get("note_text")
        login = session['username']
        file = request.files["note_file"]
        if(isSafeContent(title) and isSafeContent(text)): 
            password = ""
            iv = ""
            salt = ""
            filename = ""
            uuidFileNameSecure = ""
            if(file is not None):
                fileExtension = file.filename.rsplit('.', 1)[1].lower()
                if(isFileExtensionAllowed(fileExtension)):
                    filename = file.filename
                    uuidFileName = str(uuid4()) + '.' + fileExtension
                    uuidFileNameSecure = secure_filename(uuidFileName)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], uuidFileNameSecure))
                else:
                    response = make_response("Bad request", 400)
                    return response
            if (isWithPassword == "on"):
                password = noteForm.get("password")
                [text, iv, salt] = encode_text_from_note(text, password)
            if(isPublic == "on"):
                print("Adding new public note")
                dao.setNewPublicNote(login, title, text, iv, salt, filename, uuidFileNameSecure)
            else:
                print("Adding new private note")
                dao.setNewPrivateNote(login, title, text, iv, salt, filename, uuidFileNameSecure)
            response = make_response("Note added", 201)
            return response
        else:
            response = make_response("Bad request", 400)
            return response
    except Exception as e:
        print("Catched error: ")
        print(e)
        response = make_response("Bad request", 400)
        return response

def isFileExtensionAllowed(fileExtension):
    if(fileExtension in ACCEPT_EXTENSIONS):
        return True
    else:
        return False

@app.route('/decode_note', methods=[POST])
def decode_note():
    try:
        if ('username' in session.keys()):
            requestForm = request.form
            requestPassword = requestForm.get("password_decode")
            requestId = requestForm.get("id_decode")
            isPublic = requestForm.get("checkbox_public")
            login = session['username']
            print(requestPassword)
            print(requestId)
            print(login)
            if(isIdNoteValid(requestId) and isPasswordValid(requestPassword)):
                if(isPublic == "on"):
                    print("Pobieranie publicznych")
                    iv = dao.getIvFromPublicNote(requestId)
                    salt = dao.getSaltFromPublicNote(requestId)
                    text = dao.getTextFromPublicNote(requestId)
                else:
                    print("Pobieranie prywatnych")
                    iv = dao.getIvFromPrivateNote(requestId, login)
                    salt = dao.getSaltFromPrivateNote(requestId, login)
                    text = dao.getTextFromPrivateNote(requestId, login)
                    print(iv)
                    print(salt)
                    print(text)
                if (iv is None or
                salt is None or
                text is None):
                    return jsonify({'message': 'Bad request'}), 400
                iv = b64decode(iv)
                text = b64decode(text)
                salt = b64decode(salt)
                try:
                    key = PBKDF2(requestPassword.encode('utf-8'), salt)
                    aes = AES.new(key, AES.MODE_CBC, iv)
                    decryptedNote = unpad(aes.decrypt(text), AES.block_size).decode('utf-8')
                    return jsonify({'message': 'Succesfull decoding', 'text': decryptedNote}), 200
                except ValueError:
                    print("z errora wyjscie")
                    return jsonify({'message': 'Bad request'}), 400
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    except Exception as e:
        print("Catched error: ")
        print(e)
        return jsonify({'message': 'Bad request'}), 400


@app.route('/password_recovery', methods=[GET])
def password_recovery():
    response = make_response(render_template("password_recovery.html"))
    return response

@app.route('/reset_password', methods=[POST])
def reset_password():
    resetForm = request.form
    login = dao.returnLoginToPassRecovery(resetForm.get("login"), resetForm.get("birthDate"), resetForm.get("email"))
    if (login is not None):
        urlToReset = token_urlsafe(64)
        resp = dao.addSafeUrl(login, urlToReset)
        if(resp != 0):
            response = make_response("Bad request", 400)
            return response
        print("=================================================")
        print("------------------Wysyłam link:------------------")
        print(URL + "reset_urls/" + urlToReset)
        print("--------------------Na adres:--------------------")
        print(resetForm.get("email"))
        print("=================================================")
    response = make_response("OK", 200)
    return response

@app.route("/fetchall")
def fetchall():
    all = dao.fetchAll()
    print(all)
    return ("OK",200)

@app.route('/reset_urls/<string:token_url>', methods=[GET])
def reset_urls(token_url):
    login = dao.ifCorrectReturnLoginToPassRecovery(token_url)
    print("Login z ifCorrect======================================")
    print(login[0])
    if(login is not None):
        response = make_response(render_template("password_recovery_form.html", login=login[0], token_url=token_url))
        return response
    return abort(404)

@app.route('/reset_password/<string:token_url>', methods=[POST])
def reset_password_url(token_url):
    login = dao.ifCorrectReturnLoginToPassRecovery(token_url)
    if(login is not None):
        registerForm = request.form
        if (registerForm.get("password") is None):
            response = make_response("Bad request", 400)
            return response
        passwordHashedOnce = hashlib.sha256((registerForm.get("password")).encode('utf-8'))
        passwordHashedTwice = hashlib.sha256((passwordHashedOnce.hexdigest() + os.environ.get(PEPPER)).encode('utf-8'))
        passwordHashedTriple = hashlib.sha256((passwordHashedTwice.hexdigest().encode('utf-8')))
        salt = bcrypt.gensalt()
        passwordBcrypted = bcrypt.hashpw(passwordHashedTriple.hexdigest().encode('utf-8'), salt) 
        dao.setNewPassword(login[0], passwordBcrypted)
        del passwordHashedOnce
        del passwordHashedTwice
        del passwordHashedTriple
        del salt
        del passwordBcrypted
        response = make_response("Password changed", 201)
        return response
    else:
        response = make_response("Not found", 404)
        return response

@app.route("/logout")
def logout():
    if ('username' in session.keys()):
        session.pop('username',None)
        session.clear()
    return redirect("/")

@app.route('/register_new_user', methods=[POST])
def register_new_user():
    print("Numero uno")
    registerForm = request.form
    if(registerForm.get("login") is None or
    registerForm.get("password") is None or
    registerForm.get("name") is None or
    registerForm.get("surname") is None or
    registerForm.get("email") is None or
    registerForm.get("birthDate") is None ) :
        print("Pierwsze")
        response = make_response("Bad request", 400)
        return response
    if(isRegisterDataCorrect(registerForm)):
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
        return response
    else:
        print("Drugie")
        response = make_response("Bad request", 400)
        return response

def isRegisterDataCorrect(registerForm):
    login = registerForm.get("login") 
    name = registerForm.get("name")
    surname = registerForm.get("surname")
    email = registerForm.get("email")
    birthDate = registerForm.get("birthDate")
    password = registerForm.get("password")

    if(isLoginValid(login) and
    isIdentityValid(name) and
    isIdentityValid(surname) and
    isEmailIsValid(email) and
    isDateValid(birthDate) and
    isPasswordValid(password)
    ):
        return True
    else:
        return False

@app.route('/register/<string:login>')
def checkLoginAvailability(login):
    if(dao.checkLoginAvailability(login) is None):
        response = make_response("User not found", 404)
        return response
    else:
        response = make_response("User found", 200)
        return response


@app.route('/login_user', methods=[POST])
def login_user():
    try:
        loginForm = request.form
        dao.resetSecurityRecord(request.remote_addr)
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
                    session.permanent = True
                    del passwordHashedOnce
                    del passwordHashedTwice
                    del passwordHashedTriple
                    del cryptedPassFromDb
                    response = make_response("Logged successfully", 200)
                    return response
                else:
                    response = make_response("Bad request", 400)
                    return response
            else:
                print("Odp z bazy:")
                print(dao.incrLoggingAttemps(request.remote_addr))
                response = make_response("Bad request", 400)
                return response
                if(dao.incrLoggingAttemps(request.remote_addr)):
                    response = make_response("Bad request", 400)
                    return response
                else:
                    response = make_response("User is blocked", 403)
                    return response
        else:
            dao.incrLoggingAttemps(request.remote_addr)
            response = make_response("User is blocked", 403)
            return response
    except Exception as e:
        print("Catched error: ")
        print(e)
        response = make_response("Bad request", 400)
        return response

def isIdNoteValid(id):
    regex = '^[0-9]{1,5}$'
    if(re.match(regex, id)):
        return True
    else:
        return False

def isEmailIsValid(email):
    regex = '^[a-z0-9A-Z]+[\._]?[a-z0-9A-Z]+[@]\w+[.]\w{2,3}$'
    if(re.match(regex, email)):
        return True
    else:
        return False

def isIdentityValid(string):
    regex = '^[A-Za-ząćęłńóśźżĄĘŁŃÓŚŹŻ]{1,32}$'
    if(re.match(regex, string)):
        return True
    else:
        return False

def isDateValid(date):
    regex = '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
    if(re.match(regex, date)):
        return True
    else:
        return False

def isLoginValid(login):
    regex = '^[A-Za-z]{5,32}$'
    if(re.match(regex, login)):
        return True
    else:
        return False

def isPasswordValid(password):
    regex = '^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#\$%\^&\*]).{8,32}$'
    if(re.match(regex, password)):
        return True
    else:
        return False

def isSafeContent(text):
    if "'" in text:
        return False
    if "--" in text:
        return False
    if "/*" in text:
        return False
    if "#" in text:
        return False
    if ";" in text:
        return False
    if "<" in text:
        return False
    if ">" in text:
        return False
    return True

def encode_text_from_note(text, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password.encode('utf-8'), salt)
    utfText = text.encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    encryptedText = b64encode(aes.encrypt(pad(utfText, AES.block_size))).decode('utf-8')
    iv = b64encode(aes.iv).decode('utf-8')
    return encryptedText, iv, b64encode(salt).decode('utf-8')

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

