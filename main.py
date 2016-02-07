
import os
import webapp2
import jinja2
import urllib
import hashlib
import hmac
import json
import time
import logging
import cgi


from google.appengine.ext import db
from google.appengine.api import memcache



jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))



   

secret ="rand8752s"

def nl2br(value): 
     return value.replace('\n','<br>\n')


jinja_environment.filters['nl2br'] = nl2br 


class page(db.Model):
	page_id = db.StringProperty(required= True)
	content = db.TextProperty(required= False)
	created =db.DateTimeProperty(auto_now_add=True)


class user(db.Model):
  user_name = db.StringProperty(required= True)
  password = db.StringProperty(required= True)  


def hash_str(s):
  return hmac.new(secret,s).hexdigest()

def make_secure(s):
  return "%s|%s"  %(s, hash_str(s))

def check_secure_val(h):
  val=h.split('|')[0]
  if h==make_secure(val):
      return val  

def make_salt():
   return ''.join(random.choice(string.letters) for x in range(5))

class Handler(webapp2.RequestHandler):
    def write(self, *a, **k):
		self.response.out.write(*a,**k)

    def render_str(self, template, **params):
       t = jinja_environment.get_template(template)
       return t.render(params)	

    def render(self, template, **kw):
      self.write(self.render_str(template, **kw))  






class WikiPage(Handler):
  
  # def get(self):
  #       self.response.out.write('Hello world!')

  def write_logged_out(self,login,history,content=""):
    self.render("logged_out.html",content=content, login=login,history=history) 

  def write_logged_in(self,username,logout,edit,history,content=""):
    self.render("logged_in.html",content=content,username=username,logout=logout,edit=edit,history=history) 
  

  def get(self, page_id): 
     v = self.request.get('v')      # version number of page
     if not v:
       v=0
     v=int(v)  
     content=""
     pages = db.GqlQuery("SELECT * FROM page WHERE page_id = :1 ORDER by created DESC", page_id) 
     pages = list(pages) 
     if pages:
      content=pages[v].content
     username = self.request.cookies.get('username')
     history ='<a href="/_history%s">History</a>' % page_id
     if username and check_secure_val(username):                             # user is logged in
           if not pages:
             url="_edit" + page_id
             self.redirect(url)
           else:  
	           username = check_secure_val(username) 
	           logout ='<a href="/logout?page_id=%s">Logout</a>' % page_id
	           edit ='<a href="/_edit%s">Edit</a>' % page_id
	           self.write_logged_in(username, logout,edit,history, content=content)  
     else:
     	login ='<a href="/login?page_id=%s">Login</a>' % page_id
     	self.write_logged_out(login,history,content=content)









class signup(Handler):


  def write_html(self,username="",email="",user_error="", pass_error="", email_error="", verify_error=""):
    self.render("signup.html",username=username,email=email,user_error=user_error, pass_error=pass_error, email_error=email_error, verify_error=verify_error) 

  def get(self):   
    #self.render("signup.html",username="",email="",user_error="", pass_error="", email_error="", verify_error="")  
    self.write_html()  

  def post(self):

    flag=False;

    user_error=""; pass_error="";  email_error=""; verify_error=""

    import re
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    def valid_username(username):
      return USER_RE.match(username)

    PASS_RE = re.compile(r"^.{3,20}$")
    def valid_password(password):
      return PASS_RE.match(password)  

    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_email(email):
      return EMAIL_RE.match(email)    

    username = self.request.get('username')
    password = self.request.get('password')
    verify = self.request.get('verify')
    email = self.request.get('email')


    if (not valid_username(username)):
       user_error="That's not a valid username."
       flag=True
    else:
       query = user.all()
       query.filter('user_name =', username)
       result=query.get()
       if result:
        user_error="This user name is already taken"
        flag=True


    if (not valid_password(password)):
       pass_error="That's not a valid password."
       flag=True   

    if not (valid_email(email) or email ==""):
       email_error="That's not a valid email."
       flag=True 

    if (verify != password):
      verify_error= "Your passwords did not match"
      flag =True
    
    
    if flag:
      self.write_html(username,email,user_error,pass_error, email_error, verify_error)  
    else:
      #self.redirect("/welcome?username="+username) 
      password=hash_str(password)
      u=user(user_name=username, password=password)
      u.put()
      hash_user= str (make_secure(username)  )      
      self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % hash_user  )      
      self.redirect("/")



class login(Handler):
    def render_front(self,username="",login_error=""):
      self.render("login.html",username=username,login_error=login_error)

      

    def get(self):	
      self.render_front()
      


    def post(self):    
        page_id = self.request.get('page_id')	                                  
        username = self.request.get('username')
        password = self.request.get('password')
        #self.render_front(user_name)

        import re
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        def valid_username(username):
          return USER_RE.match(username)

        PASS_RE = re.compile(r"^.{3,20}$")
        def valid_password(password):
          return PASS_RE.match(password) 

        if (valid_username(username) and valid_password(password)):
           # self.render_front(username=username)
           query = user.all()
           query.filter('user_name =', username)
           user1=query.get()
           if user1:
              if user1.password==hash_str(password):
                hash_user= str (make_secure(username)  )   
                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % hash_user  )      
                self.redirect(page_id)


        self.render_front(username=username, login_error="Invalid login") 


class logout(Handler):
    def get(self):
      page_id = self.request.get('page_id')	
      self.response.headers.add_header('Set-Cookie', 'username=; Path=/'   )      
      self.redirect(page_id)        


class EditPage(Handler):

    def write_page(self,username,logout,content=""):
        self.render("edit_page.html",content=content,username=username,logout=logout) 


    def get(self, page_id): 
     v = self.request.get('v')      # version number of page
     if not v:
       v=0
     v=int(v)   
     content=""
     pages = db.GqlQuery("SELECT * FROM page WHERE page_id = :1 ORDER by created DESC", page_id) 
     pages = list(pages) 
     username = self.request.cookies.get('username')
     if pages:
      content=pages[v].content
     if username and check_secure_val(username):                             # user is logged in
           username = check_secure_val(username) 
           logout ='<a href="/logout?page_id=%s">Logout</a>' % page_id
           edit ='<a href="/_edit%s">Edit</a>' % page_id
           self.write_page(username, logout, content=content)  
     else:
     	self.redirect(page_id)


    def post (self, page_id):
     content = self.request.get('content')
     pages = db.GqlQuery("SELECT * FROM page WHERE page_id = :1 ORDER by created ", page_id) 
     username = self.request.cookies.get('username')
     if username and check_secure_val(username):
     	username = check_secure_val(username)
        p=page(page_id=page_id, content=content)
        p.put()
        self.redirect(page_id)
     else:
     	self.redirect(page_id)   


class History(Handler):  

  def write_logged_in(self,username,logout,edit,pages):
    self.render("hist_logged_in.html",pages=pages,username=username,logout=logout,edit=edit) 

  def write_logged_out(self,login,pages):
    self.render("hist_logged_out.html",pages=pages,login=login)     

  def get(self, page_id): 
     pages = db.GqlQuery("SELECT * FROM page WHERE page_id = :1 ORDER by created DESC", page_id) 
     pages = list(pages) 
     username = self.request.cookies.get('username')
     if username and check_secure_val(username):                             # user is logged in
           if not pages:
             url="../_edit" + page_id
             self.redirect(url)
           else:  
             username = check_secure_val(username) 
             logout ='<a href="/logout?page_id=%s">Logout</a>' % page_id
             edit ='<a href="/_edit%s">Edit</a>' % page_id
             self.write_logged_in(username, logout,edit, pages=pages)  
     else:
      login ='<a href="/login?page_id=%s">Login</a>' % page_id
      self.write_logged_out(login,pages=pages)  

      
     	         



# app = webapp2.WSGIApplication([('/', MainHandler),  ('/signup', signup), ('/login', login)],
#                               debug=True)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', signup),
                               ('/login', login),
                               ('/logout', logout),
                               ('/_edit' + PAGE_RE, EditPage), ('/_history' + PAGE_RE, History),
                               (PAGE_RE, WikiPage) 
                               ],
                              debug=True)