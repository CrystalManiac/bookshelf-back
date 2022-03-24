from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime
from flask_cors import CORS

app = Flask(__name__)
 
app.config['SECRET_KEY']='228f2af45d3a4e161a7dd2d17fdaa87b'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
CORS(app)

db = SQLAlchemy(app)


class Users(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   public_id = db.Column(db.Integer)
   name = db.Column(db.String(50))
   password = db.Column(db.String(50))
   admin = db.Column(db.Boolean)


class Books(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
   name = db.Column(db.String(50), unique=True, nullable=False)
   author = db.Column(db.String(50), unique=True, nullable=False)
   page = db.Column(db.Integer)


def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-token' in request.headers:
           token = request.headers['x-access-token']
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = Users.query.filter_by(public_id=data['public_id']).first()
       except:
           return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator


@app.route('/register', methods=['POST'])
def signup_user(): 
   data = request.get_json() 
   hashed_password = generate_password_hash(data['password'], method='sha256')

   new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
   db.session.add(new_user) 
   db.session.commit()   
   return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['POST']) 
def login_user():
    try:
        data = request.get_json()
        username = data['name']
        password = data['password']
        hashed_password = generate_password_hash(password, method='sha256')
        #if not data['name'] or not data['password']: 
            #return make_response('Authentication error', 401, {'Authentication': 'login required"'})   
        
        user = Users.query.filter_by(name=username).first()  
        if check_password_hash(user.password, password):
            token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        
            return jsonify({'accessToken' : token})
        
        return make_response('Authentication error',  401, {'Authentication': '"login required"'})
    except:
        return make_response('Authentication error', 401, {'Authentication': 'login required"'})


@app.route('/users', methods=['GET'])
def get_all_users(): 
 
   users = Users.query.all()
   result = []  
   for user in users:  
       user_data = {}  
       user_data['public_id'] = user.public_id 
       user_data['name'] = user.name
       user_data['password'] = user.password
       user_data['admin'] = user.admin
     
       result.append(user_data)  
   return jsonify({'users': result})


@app.route('/book', methods=['POST'])
@token_required
def create_book(current_user):
 
   data = request.get_json()
 
   new_books = Books(name=data['name'], author=data['author'], page=data['page'], user_id=current_user.id) 
   db.session.add(new_books)  
   db.session.commit() 
   return jsonify({'message' : 'New book is created'})


@app.route('/books', methods=['GET'])
@token_required
def get_books(current_user):
 
   books = Books.query.filter_by(user_id=current_user.id).all()
   output = []
   for book in books:
       book_data = {}
       book_data['id'] = book.id
       book_data['name'] = book.name
       book_data['author'] = book.author
       book_data['page'] = book.page
       output.append(book_data)
 
   return jsonify({'bookList' : output})


@app.route('/books/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id): 
 
   book = Books.query.filter_by(id=book_id, user_id=current_user.id).first()  
   if not book:  
       return jsonify({'message': 'Not Found'})  
 
   db.session.delete(book) 
   db.session.commit()  
   return jsonify({'message': 'Book deleted'})
 
if  __name__ == '__main__': 
    app.run(debug=True)

