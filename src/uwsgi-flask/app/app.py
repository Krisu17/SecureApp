import time
from flask import Flask, render_template, send_file, request, jsonify, redirect, url_for, abort
from flask import request
from flask import make_response
app = Flask(__name__, static_url_path="")

GET = "GET"
POST = "POST"

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
    return make_response("Not implemented", 500)