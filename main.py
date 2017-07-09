# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import hmac
import jinja2
import os
import random
import re
import webapp2

from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = "monnalisasmile"

def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def render_str(template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val)
			)

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
	def get(self):
		self.render("welcome.html")

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

def comment_key(name='default'):
	return db.Key.from_path('comments', name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	author_id = db.IntegerProperty(required=True)
	author_name = db.StringProperty(required=True)

	def render(self):
		comments = Comment.all().filter('parent_post_id = ', self.key().id()).order('-created')
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self, comments = comments)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name = ', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
						email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
			raise NotImplementedError

class Register(Signup):
	def done(self):

		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/blog')

class Login(BlogHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		if username and password:
			u = User.login(username, password)
			if u:
				self.login(u)
				self.redirect('/blog')
			else:
				msg = 'Incorrect username or password.'
				self.render('login-form.html', error = msg, username = username)
		else:
			msg = 'Please enter your username and password!'
			self.render('login-form.html', error = msg)

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/login')

class BlogFront(BlogHandler):
	def get(self):
		posts = Post.all().order('-created')
		if posts.get() is not None:
			self.render('front.html', posts = posts)
		else:
			self.render('front.html')


class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect('/login')

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')
		author_id = self.user.key().id()
		author_name = self.user.name

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content, author_id = author_id, author_name = author_name)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "You must have a subject and content."
			self.render("newpost.html", subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			if self.user.key().id() == post.author_id:
				self.render('delete_post.html', post = post)
			else:
				msg = "You cannot delete other people's posts!"
				self.render('permalink.html', post = post, main_msg = msg)
		else:
			self.redirect('/login')

	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		comments = Comment.all().filter('parent_post_id = ', post.key().id()).order('-created')
		for c in comments:
			c.delete()

		post.delete()

		msg = "Your post has been deleted."
		self.redirect('/blog')

class EditPost(BlogHandler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)

			if self.user.key().id() == post.author_id:
				subject = post.subject
				content = post.content
				self.render('newpost.html', subject = subject, content = content)
			else:
				msg = "You cannot delete other authors' posts!"
				self.render('permalink.html', post = post, main_msg = msg)
		else:
			self.redirect('/login')

	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		new_subject = self.request.get('subject')
		new_content = self.request.get('content')

		if new_subject and new_content:
			post.subject = new_subject
			post.content = new_content
			post.put()
			self.redirect('/blog/%s' % post.key().id())
		else:
			error = "You must have a subject and content."
			self.render("newpost.html", subject=new_subject, content=new_content, error=error, p = post)

class Comment(db.Model):
	parent_post_id = db.IntegerProperty(required=True)
	comment_id = db.IntegerProperty(required=True)
	commenter_id = db.IntegerProperty(required=True)
	commenter_name = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("comment.html", c = self)

class MakeComment(BlogHandler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			self.render("new-comment.html", post = post)
		else:
			self.redirect('/login')

	def post(self, post_id):
		content = self.request.get('comment')
		parent_post_id = int(post_id)
		commenter_id = self.user.key().id()
		commenter_name = self.user.name

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if content:
			c = Comment(content = content,
						parent_post_id = parent_post_id,
						commenter_id = commenter_id,
						commenter_name = commenter_name,
						comment_id = 1)
			c.put()
			c.comment_id = c.key().id()
			c.put()
			self.redirect('/blog/%s' % str(post.key().id()))
		else:
			msg = "You must have some content."
			self.render("new-comment.html", comment_error = msg, post = post)

class DeleteComment(BlogHandler):
	def get(self, comment_id):
		if self.user:
			key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
			comment = db.get(key)
			post_id = comment.parent_post_id
			key = db.Key.from_path('Post', post_id, parent=post_key())
			post = db.get(key)

			if self.user.key().id() == comment.commenter_id:
				self.render('delete_comment.html', comment = comment)
			else:
				msg = "You cannot delete other people's comments!"
				self.render('permalink.html', post = post, main_msg = msg)
		else:
			self.redirect('/login')

	def post(self, comment_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		comments = Comment.all().filter('parent_post_id = ', post.key().id()).order('-created')
		for c in comments:
			c.delete()

		post.delete()

		msg = "Your post has been deleted."
		self.redirect('/blog')

app = webapp2.WSGIApplication([	('/', MainPage),
								('/blog/?', BlogFront),
								('/blog/([0-9]+)', PostPage),
								('/blog/delete_post/([0-9]+)', DeletePost),
								('/blog/newpost', NewPost),
								('/blog/edit_post/([0-9]+)', EditPost),
								('/blog/new_comment/([0-9]+)', MakeComment),
								('/blog/delete_comment/([0-9]+)', DeleteComment),
								('/signup', Register),
								('/login', Login),
								('/logout', Logout)
								], debug = True)