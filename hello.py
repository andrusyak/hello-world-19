from flask import Flask, Markup, escape, request, render_template, url_for
from flask_bootstrap import Bootstrap


app = Flask(__name__)
bootstrap = Bootstrap(app)


@app.route('/')
def index():
	return render_template('index.html')


@app.route('/hello/', methods=['GET', 'POST'])
@app.route('/hello/<name>')
def hello(name=None):
	if request.method == 'POST':
		return render_template('hello.html', name=request.form['firstname'])
	else:
		return render_template('hello.html', name=name)


# with app.test_request_context():
# 	print(url_for('index'))
# 	print(url_for('hello'))
# 	print(url_for('hello', name='John Doe'))
# 	print(url_for('static', filename='style.css'))


