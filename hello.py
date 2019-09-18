from flask import Flask, Markup, abort, escape, flash, get_flashed_messages, jsonify, make_response, redirect, request, render_template, session, url_for
from flask_bootstrap import Bootstrap

import requests, os, re
import base64
from io import BytesIO

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import ticker


app = Flask(__name__)
bootstrap = Bootstrap(app)


# print(os.urandom(16))
# app.config['SECRET_KEY'] = b"\xc1'\xdb7\xb3\x87?\x10?\xb9\x92\xf2\x9e\xc3p!"
app.secret_key = b"\xc1'\xdb7\xb3\x87?\x10?\xb9\x92\xf2\x9e\xc3p!"


@app.errorhandler(401)
def unauthorized(error):
	return "Access to this page is forbidden".upper(), 401


@app.errorhandler(404)
def page_not_found(error):
	return "This page does not exist".upper(), 404


def valid_login(login, psw):
	if login == "ruslan" and psw == "andrusyak":
		return True
	else:
		return False


@app.route('/', methods=['POST', 'GET'])
def index():
	if request.method == 'POST':

		if valid_login(request.form['username'], request.form['password']):
			resp = make_response(render_template('login.html', name=request.form['username']))
			resp.set_cookie('username', request.form['username'])
			resp.set_cookie('password', request.form['password'])
			return resp

		elif request.form['username'] == "admin" and request.form['password'] == "admin":
			session['admin'] = True
			return "You have got admin access"

		else:
			return "Invalid username/password"

	username = request.cookies.get('username')
	password = request.cookies.get('password')
	if valid_login(username, password):
		return render_template('index.html', login=username, psw=password)

	return render_template('index.html')


@app.route('/login')
@app.route('/login/<name>')
def login(name=None):

	if name == "admin":
		if not session.get('admin'):
			abort(401)
		else:
			return "Hello, admin!!!"

	elif name:
		return "Hello, %s. Log in to your account" % name

	else:
		return "Log in to your account"


@app.route('/search')
def search():
	query = request.args.get('query', '')

	if query == "api":
		return redirect(url_for('api'))

	elif query == "cookies":
		return redirect(url_for('cookies'))

	elif query == "post":
		return redirect(url_for('post'))

	elif query == "session":
		return redirect(url_for('view_session'))

	elif query == "teapot":
		return redirect(url_for('teapot'))

	elif query == "upload":
		return redirect(url_for('upload_file'))

	elif query == "clear cookies":
		resp = make_response("Cookies have been cleared")
		for key in request.cookies:
			resp.delete_cookie(key)
		return resp

	elif query == "clear session":
		session.clear()
		return "Your session has been cleared"

	else:
		return redirect('https://www.google.com/search?q=' + query)


def process_data(file):
	births = pd.read_csv(file)

	table = births.pivot_table(values='births', index='year', columns='gender', aggfunc=sum)
	table.columns = ['girls', 'boys']
	table.index.name = None

	table.plot(
		figsize=(12, 5.5), 
		fontsize=14, 
		color=['tab:red', 'tab:blue'], 
		style=['-s', '-s'], 
		rot=None, 

		linewidth=2, 
		markersize=6, 
		markerfacecolor='w', 
		markeredgecolor=None, 
		markeredgewidth=1, 

		layout=(1, 1), 
		subplots=False, 
		grid=True, 
		legend=True, 
		)

	plt.legend(loc='upper left', fontsize=14, borderpad=1, labelspacing=1, ncol=1, edgecolor='darkblue')

	plt.gca().xaxis.set_major_locator(ticker.MultipleLocator(5))
	plt.gca().xaxis.set_minor_locator(ticker.MultipleLocator(1))

	@ticker.FuncFormatter
	def func_fmt(y, pos):
		return '{:,.0f}'.format(y)
	plt.gca().yaxis.set_major_formatter(func_fmt)

	plt.tick_params(axis='both', which='major', width=1, length=5, pad=5, labelrotation=None)
	plt.tick_params(axis='x', which='minor', width=0.75, length=2.5)

	plt.grid(axis='both', which='major', linewidth=1, linestyle='-')
	plt.grid(axis='x', which='minor', linewidth=0.5)

	plt.title('Total number of US births by year and gender', color='darkblue', size=18)
	plt.xlabel('year', color='darkblue', size=16)
	plt.ylabel('total births per year', color='darkblue', size=16)

	plt.tight_layout()

	buf = BytesIO()
	plt.savefig(buf, format="png") 
	# supported formats: eps, pdf, pgf, png, ps, raw, rgba, svg, svgz
	data = base64.b64encode(buf.getbuffer()).decode("ascii")

	return table, f"<img src='data:image/png;base64,{data}'/>"


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
	global filename, table, image

	if request.method == 'POST':
		file = request.files['myFile']

		if file:
			match = re.search("(?i)\..+$", file.filename)

			if match and match.group().lower() in [".csv"]:
				filename = file.filename
				table, image = process_data(file)
				return render_template('upload.html', filename=filename)

			elif match:
				flash("File extension %s is forbidden" % match.group())
				return render_template('upload.html')

			else:
				flash("File without extension")
				return render_template('upload.html')

		else:
			flash("Choose a file")
			return render_template('upload.html')

	show = request.args.get('show', '')
	if show == "table":
		return render_template('upload.html', 
			filename=filename, 
			table=Markup(table.head(100).to_html(table_id="t01"))
			)

	if show == "image":
		return render_template('upload.html', filename=filename,  image=Markup(image))

	return render_template('upload.html')


@app.route('/teapot')
def teapot():
	r = requests.get('http://httpbin.org/status/418')
	return '<pre>' + r.text + '</pre>'


@app.route('/env')
def env():
	times = int(os.getenv('TIMES', 3))
	return "Hello! " * times


@app.route('/api')
def api():
	return jsonify({"username": "ruslan", "password": 123456})


@app.route('/post', methods=['GET', 'POST'])
def post():
	if request.method == 'POST':
		return request.form
	return render_template('api.html')


@app.route('/cookies')
def cookies():
	return request.cookies


@app.route('/session')
def view_session():
	return escape(session)


# with app.test_request_context():
# 	print(url_for('index'))
# 	print(url_for('login'))
# 	print(url_for('login', name='John Doe'))
# 	print(url_for('static', filename='style.css'))
