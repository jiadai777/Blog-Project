import hashlib
import hmac
import jinja2
import os
import random
import re
import webapp2

from string import letters
from google.appengine.ext import db

"""
Create Jinja2 template string to render templates easily later.
"""
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "monnalisasmile"  # secret word for password hashing

"""
Functions for making a secured and hashed passwords.
"""
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# get a comment entity from Google database by using the comment's ID
def get_comment_by_id(comment_id):
    key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
    return db.get(key)


# get a post entity from Google database by using the post's ID
def get_post_by_id(post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    return db.get(key)


"""
get a like entity from Google database
# by using the like's ID and its parent post's id
"""


def get_like(post_id, liker_id):
    likes = Like.all(keys_only=True)
    likes_by_post = likes.filter('parent_post_id =', int(post_id))
    return likes_by_post.filter('liker_id =', liker_id).get()


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


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def comment_key(name='default'):
    return db.Key.from_path('comments', name)


def like_key(name='default'):
    return db.Key.from_path('likes', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author_id = db.IntegerProperty(required=True)
    author_name = db.StringProperty(required=True)
    """ how many people liked this post """
    num_of_likes = db.IntegerProperty(required=True)

    def render(self):
        # get all comments that belong to this post and render them
        comments = Comment.all().filter('parent_post_id = ',
                                        self.key().id()).order('-created')
        self._render_text = self.content.replace('\n', '<br>')
        if comments.get() is not None:
            return render_str("post.html", p=self, comments=comments)
        else:
            return render_str("post.html", p=self)


class Like(db.Model):
    parent_post_id = db.IntegerProperty(required=True)
    """ id of the person who liked """
    liker_id = db.IntegerProperty(required=True)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name = ', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

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


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


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

        params = dict(username=self.username,
                      email=self.email)

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
            self.render('signup-form.html', error_username=msg)
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
                self.render('login-form.html', error=msg, username=username)
        else:
            msg = 'Please enter your username and password!'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')


""" home page of the blog """


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        if posts.get() is not None:
            self.render('front.html', posts=posts)
        else:
            self.render('front.html')


""" page of a specific blog """


class PostPage(BlogHandler):
    def get(self, post_id):
        post = get_post_by_id(post_id)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            author_id = self.user.key().id()
            author_name = self.user.name

            if subject and content:
                p = Post(parent=blog_key(),
                         subject=subject,
                         content=content,
                         author_id=author_id,
                         author_name=author_name,
                         num_of_likes=0)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "You must have a subject and content."
                self.render("newpost.html",
                            subject=subject,
                            content=content,
                            error=error)
        else:
            self.redirect('/login')


class DeletePost(BlogHandler):
    # first direct to a page to confirm whether user wants to delete the post
    def get(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)
            if post is not None:
                if self.user.key().id() == post.author_id:
                    self.render('delete_post.html', post=post)
                else:
                    msg = "You cannot delete other people's posts!"
                    self.render('permalink.html', post=post, main_msg=msg)
        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)

            if post is not None:
                if self.user.key().id() == post.author_id:
                    # delete all belonging comments first
                    comments = Comment.all()
                    comments = comments.filter('parent_post_id = ',
                                               post.key().id())
                    comments = comments.order('-created')
                    for c in comments:
                        c.delete()

                    post.delete()
                    self.redirect('/blog')
                else:
                    msg = "You cannot delete other people's posts!"
                    self.render('permalink.html', post=post, main_msg=msg)
        else:
            self.redirect('/login')


class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)
            if post is not None:
                if self.user.key().id() == post.author_id:
                    subject = post.subject
                    content = post.content
                    # use the template of new post for editing post
                    self.render('newpost.html',
                                subject=subject,
                                content=content)
                else:
                    msg = "You cannot edit other people's posts!"
                    self.render('permalink.html', post=post, main_msg=msg)
        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)
            if post is not None:
                if self.user.key().id() == post.author_id:
                    new_subject = self.request.get('subject')
                    new_content = self.request.get('content')

                    if new_subject and new_content:
                        post.subject = new_subject
                        post.content = new_content
                        post.put()
                        self.redirect('/blog/%s' % post.key().id())
                    else:
                        error = "You must have a subject and content."
                        self.render("newpost.html",
                                    subject=new_subject,
                                    content=new_content,
                                    error=error, p=post)
                else:
                    msg = "You cannot edit other people's posts!"
                    self.render('permalink.html', post=post, main_msg=msg)
        else:
            self.redirect('/login')


class EditComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            post = get_post_by_id(comment.parent_post_id)
            if comment is not None and post is not None:
                if self.user.key().id() == comment.commenter_id:
                    content = comment.content
                    # use the template of writing comment for editing comment
                    self.render('new-comment.html', comment=content, post=post)
                else:
                    msg = "You cannot edit other people's comments!"
                    self.render('permalink.html', main_msg=msg)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            if comment is not None:
                if self.user.key().id() == comment.commenter_id:
                    new_content = self.request.get('comment')

                    if new_content:
                        comment.content = new_content
                        comment.put()
                        self.redirect('/blog/%s' % comment.parent_post_id)
                    else:
                        error = "You must have a subject and content."
                        self.render("new-comment.html",
                                    comment=new_content,
                                    error=error)
                else:
                    msg = "You cannot edit other people's comments!"
                    self.render('permalink.html', main_msg=msg)
        else:
            self.redirect('/login')

"""
This class handles like/unlike of a post.
"""


class LikeHandler(BlogHandler):
    def post(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)
            uid = self.user.key().id()

            if uid == post.author_id:
                msg = "You cannot like your own post!"
                self.render('permalink.html', post=post, main_msg=msg)
            else:
                like = get_like(post_id, uid)
                if like:
                    db.delete(like)
                    post.num_of_likes -= 1
                    msg = "You unliked this post."
                    self.render('permalink.html', post=post, main_msg=msg)
                else:
                    new_like = Like(parent=like_key(),
                                    parent_post_id=int(post_id),
                                    liker_id=uid)
                    new_like.put()
                    post.num_of_likes += 1
                    msg = "You liked this post."
                    self.render('permalink.html', post=post, main_msg=msg)
                post.put()
        else:
            self.redirect('/login')


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
        return render_str("comment.html", c=self)

"""
This class directs user to write a new comment for a post.
"""


class MakeComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)
            if post is not None:
                self.render("new-comment.html", post=post)
        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.user:
            content = self.request.get('comment')
            parent_post_id = int(post_id)
            commenter_id = self.user.key().id()
            commenter_name = self.user.name

            post = get_post_by_id(post_id)

            if content:
                c = Comment(parent=comment_key(),
                            content=content,
                            parent_post_id=parent_post_id,
                            commenter_id=commenter_id,
                            commenter_name=commenter_name,
                            comment_id=1)  # initialize a temperary id
                c.put()
                c.comment_id = c.key().id()
                c.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                msg = "You must have some content."
                self.render("new-comment.html", comment_error=msg, post=post)
        else:
            self.redirect('/login')


class DeleteComment(BlogHandler):
    """
    Directs user to confirmation page about whether
    they want to delete the comment or not.
    """
    def get(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            post = get_post_by_id(comment.commenter_id)
            if comment is not None and post is not None:
                if self.user.key().id() == comment.commenter_id:
                    self.render('delete_comment.html', comment=comment)
                else:
                    msg = "You cannot delete other people's comments!"
                    self.render('permalink.html', post=post, main_msg=msg)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        comment = get_comment_by_id(comment_id)

        comment.delete()

        self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/delete_post/([0-9]+)', DeletePost),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit_post/([0-9]+)', EditPost),
                               ('/blog/like_unlike_post/([0-9]+)',
                                LikeHandler),
                               ('/blog/new_comment/([0-9]+)', MakeComment),
                               ('/blog/delete_comment/([0-9]+)',
                                DeleteComment),
                               ('/blog/edit_comment/([0-9]+)', EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout)
                               ], debug=True)
