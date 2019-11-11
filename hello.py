#!venv/bin/python3

from flask import Flask, Markup, abort, escape, flash, get_flashed_messages, jsonify, make_response, redirect, render_template, request, session, url_for
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
	# return {'error': 'Not found'}


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
		return redirect(url_for('api_tasks'))

	elif query == "post":
		return redirect(url_for('post'))

	elif query == "teapot":
		return redirect(url_for('teapot'))

	elif query == "upload":
		return redirect(url_for('upload_file'))

	elif query == "cookies":
		return redirect(url_for('cookies'))

	elif query == "session":
		return redirect(url_for('view_session'))

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

	table.plot(figsize=(12, 5.5), fontsize=14, color=['tab:red', 'tab:blue'], style=['-s', '-s'], rot=None, 
		linewidth=2, markersize=6, markerfacecolor='w', markeredgecolor=None, markeredgewidth=1, 
		layout=(1, 1), subplots=False, grid=True, legend=True)

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


@app.route('/post', methods=['GET', 'POST'])
def post():
	if request.method == 'POST':
		return request.form
	return render_template('post.html')


@app.route('/cookies')
def cookies():
	return request.cookies


@app.route('/session')
def view_session():
	return escape(session)


#------------------------------HTTPBasicAuth------------------------------
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
auth = HTTPBasicAuth()


# users = {
# 	"john": generate_password_hash("hello"),
# 	"susan": generate_password_hash("bye")
# }


# @auth.verify_password
# def verify_password(username, password):
# 	if username in users:
# 		return check_password_hash(users.get(username), password)
# 	return False


def hash_password(password):
	salt = os.urandom(32)
	key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
	return salt + key


users = {
	"john": b'\x16\x8fU\xb2\x18Q\x83\xce\x8c\x00&=$acZ:\x92\x17\x06H\xbfwT\x99\xa3s\xed\
\xfe\xa3\xd2\x0c\x1b\xba\xd9\xd4\xde{-e9t\xa5\xe0C\n`\xb9\xe8\x80#\x89^\x88\xa7\x82!\xa3A"\x18L\xcc\x90',
	"susan": b'\xbd\x8e\x1f\xf9Vy\x115\x88\x8d|w:uoZ\xa9!\x91\xb4A\xdbmOd\xb4E\xb2Eb\xbf\
\xb6W\x9e@\x15eO#fm\x03\x13c\xe3\x89\x1a\x10r\xd5\x1cB\xbci\xd5\r\xbc5k\xf5\xf0\xe5\x08\x18'
}


# @auth.verify_password
# def verify_password(username, password):
# 	if username in users:
# 		salt = users[username][:32]
# 		key = users[username][32:]
# 		new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
# 		if new_key == key:
# 			return True
# 	return False


@auth.get_password
def get_password(username):
	return users.get(username)


@auth.hash_password
def hash_pw(username, password):
	if username in users:
		salt = users[username][:32]
		key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
		return salt + key


@auth.error_handler
def unauthorized():
	return {'error': 'Unauthorized access'}, 401
#------------------------------HTTPBasicAuth------------------------------


#------------------------------RESTful API------------------------------
tasks = [
	{
		'id': 1,
		'title': 'Buy groceries',
		'description': 'Milk, Cheese, Pizza, Fruit, Tylenol', 
		'done': False
	},
	{
		'id': 2,
		'title': 'Learn Python',
		'description': 'Need to find a good Python tutorial on the web', 
		'done': False
	}
]


def make_public_task(task):
	new_task = {}
	for field in task:
		if field == 'id':
			new_task['uri'] = url_for('api_tasks', task_id=task['id'], _external=True)
		else:
			new_task[field] = task[field]
	return new_task


@app.route('/api/tasks', methods=['GET', 'POST'])
@app.route('/api/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
@auth.login_required
def api_tasks(task_id=None):

#------------------------------POST------------------------------
	if request.method == 'POST':
		if not request.json or 'title' not in request.json:
			abort(400)

		task = {
			'id': tasks[-1]['id'] + 1,
			'title': request.json['title'],
			'description': request.json.get('description', ""),
			'done': False
		}

		tasks.append(task)
		return {'task': task}, 201
	
	task = list(filter(lambda t: t['id'] == task_id, tasks))

#------------------------------PUT------------------------------
	if request.method == 'PUT':
		if len(task) == 0:
			abort(404)

		if not request.json:
			abort(400)

		if 'title' in request.json and type(request.json['title']) is not str:
			abort(400)

		if 'description' in request.json and type(request.json['description']) is not str:
			abort(400)

		if 'done' in request.json and type(request.json['done']) is not bool:
			abort(400)

		task[0]['title'] = request.json.get('title', task[0]['title'])
		task[0]['description'] = request.json.get('description', task[0]['description'])
		task[0]['done'] = request.json.get('done', task[0]['done'])
		return {'task': task[0]}

#------------------------------DELETE------------------------------
	if request.method == 'DELETE':
		if len(task) == 0:
			abort(404)

		tasks.remove(task[0])
		return {'result': True}

#------------------------------GET------------------------------
	if not task_id:
		return {'tasks': list(map(make_public_task, tasks))}

	if len(task) == 0:
		abort(404)

	return jsonify({'task': make_public_task(task[0])})


'''
RESTful API:
curl -I -u john:hello http://localhost:5000/api/tasks
curl -i -u john:hello http://localhost:5000/api/tasks
curl -i -u john:hello http://localhost:5000/api/tasks/1
curl -i -u john:hello -H "Content-Type: application/json" -X POST -d '{"title":"Read a book"}' http://localhost:5000/api/tasks
curl -i -u john:hello -H "Content-Type: application/json" -X PUT -d '{"done":true}' http://localhost:5000/api/tasks/3
curl -i -u john:hello -X DELETE http://localhost:5000/api/tasks/3
'''


'''
import requests

MAKE A REQUEST
auth = ("john", "hello")
headers = {"Content-Type": "application/json"}

r = requests.get("http://localhost:5000/api/tasks", auth=auth)
r = requests.post("http://localhost:5000/api/tasks", auth=auth, headers=headers, data='{"title": "Read a book"}')
r = requests.put("http://localhost:5000/api/tasks/3", auth=auth, headers=headers, data='{"done": true}')
r = requests.delete("http://localhost:5000/api/tasks/3", auth=auth)

print("Status code:", r.status_code, end="\n\n")
print("Response Headers:", r.headers, sep="\n", end="\n\n")
print("JSON Response Content:", r.json(), sep="\n")
print("JSON Response Content:", r.text, sep="\n")

POST MULTIPART-ENCODED FILES
Flask: request.files["file1"]

curl -i -F "file1=@data/file1.jpg" http://localhost:5000/predict

files = {
    "file1": open("data/file1.jpg", "rb"), 
    "file2": open("data/file2.jpg", "rb")
}

r = requests.post(url, auth=auth, files=files)
'''


# with app.test_request_context():
# 	print(url_for('index'))
# 	print(url_for('login'))
# 	print(url_for('login', name='John Doe'))
# 	print(url_for('static', filename='style.css'))
# 	print(url_for('api_tasks', task_id=1, _external=True))


# if __name__ == '__main__':
# 	app.run(debug=True)
