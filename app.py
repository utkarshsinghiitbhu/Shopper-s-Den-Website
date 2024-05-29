from flask import Flask, flash, render_template, url_for, redirect, request, session, current_app,g
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_msearch import Search

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
search=Search()
search.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Merchant(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Cart(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    quantity=db.Column(db.Integer,nullable=False)
    product_id=db.Column(db.Integer, db.ForeignKey('products.id'))
    product=db.relationship('Products',backref=db.backref('products',lazy=True))
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
    user=db.relationship('User',backref=db.backref('users',lazy=True))

class Products(db.Model, UserMixin):
    __searchtable__=['name','unit']
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(20), nullable=False, unique=True)
    unit=db.Column(db.String(20), nullable=False)
    rate=db.Column(db.Integer,nullable=False)
    quantity=db.Column(db.Integer,nullable=False)
    category_id=db.Column(db.Integer, db.ForeignKey('category.id'),nullable=False)
    category=db.relationship('Category',backref=db.backref('categories',lazy=True))
    admin_id=db.Column(db.Integer, db.ForeignKey('merchant.id'),nullable=False)
    merchant=db.relationship('Merchant',backref=db.backref('merchants',lazy=True))

class Category(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(20), nullable=False, unique=True)
    admin_id=db.Column(db.Integer, db.ForeignKey('merchant.id'),nullable=False)
    merchant=db.relationship('Merchant',backref=db.backref('admin',lazy=True))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('User Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class MerchantRegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Merchant Register')

    def validate_username(self, username):
        existing_user_username = Merchant.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('User Login')

class MerchantLoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Merchant Login')

class AddProducts(FlaskForm):
    name=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
    unit=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Unit"})
    rate=StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Rate"})
    quantity=StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Quantity"})
    submit = SubmitField('Add Products')

class AddCategories(FlaskForm):
    name=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
    submit = SubmitField('Add Categories')

class Addtocart(FlaskForm):
    quantity=StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Quantity"})
    submit = SubmitField('Add to Cart')

@app.route('/')
def home():
    session.pop('user',None)
    session.pop('uid',None)
    return render_template('home.html')

@app.route('/result')
def result():
    searchword=request.args.get('q')
    categories=Category.query.all()
    products=Products.query.msearch(searchword,fields=['name','unit'],limit=3)
    return render_template('result.html', products=products, categories=categories)

@app.before_request
def before_request():
    g.user= None
    g.admin=None
    g.uid=None
    g.aid=None
    if 'user' in session:
        g.user=session['user']
    if 'uid' in session:
        g.uid=session['uid']
    if 'admin' in session:
        g.admin=session['admin']
    if 'uid' in session:
        g.uid=session['uid']

@ app.route('/user_register', methods=['GET', 'POST'])
def user_register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('user_login'))
    return render_template('user_register.html', form=form)

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()
    if request.method=='POST':
        session.pop('user',None)
        session.pop('uid',None)
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    session['user']=user.username
                    session['uid']=user.id
                    return redirect(url_for('user_dashboard'))
    return render_template('user_login.html', form=form)

@app.route('/user_logout', methods=['GET', 'POST'])
def user_logout():
    session.pop('user',None)
    session.pop('uid',None)
    return redirect(url_for('user_login'))


@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if g.user:
        products=Products.query.all()
        categories=Category.query.all()
        return render_template('user_dashboard.html', products=products, categories=categories, user=session['user'], uid=session['uid'])
    return redirect(url_for('user_login'))

@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if g.user:
        products=Cart.query.filter_by(user_id=session['uid'])
        return render_template('cart.html', products=products)
    return redirect(url_for('user_login'))

@app.route('/buy')
def buy():
    if g.user:
        items=Cart.query.filter_by(user_id=session['uid'])
        for item in items:
            product=Products.query.get_or_404(item.product_id)
            if (product.quantity>item.quantity):
                product.quantity=product.quantity-item.quantity
                db.session.delete(item)
            else:
                return redirect(url_for('cart'))
        db.session.commit()
        return render_template('buy.html')
    return redirect(url_for('user_login'))

@app.route('/deletefcart/<int:id>', methods=['POST'])
def deletefcart(id):
    if g.user:
        product = Cart.query.get_or_404(id)
        if request.method =="POST":
            db.session.delete(product)
            db.session.commit()
            return redirect(url_for('cart'))
        flash(f'Can not delete the product','success')
        return redirect(url_for('cart'))
    return redirect(url_for('user_login'))
    

@app.route('/product/<int:id>', methods=['GET', 'POST'])
def addcart(id):
    if g.user:
        products= Products.query.filter_by(id=id)
        form=Addtocart()
        if form.validate_on_submit():
            pname=request.form.get("pname")
            price=request.form.get("price")
            product_id=request.form.get("product_id")
            add_cart=Cart(pname=pname, quantity=form.quantity.data, price=price, product_id=product_id, user_id=session['uid'])
            db.session.add(add_cart)
            db.session.commit()
            return redirect(url_for('cart'))
        return render_template('product.html', form=form, products=products)
    return redirect(url_for('user_login'))

@app.route('/category/<int:id>')
def get_category(id):
    if g.user:
        category= Products.query.filter_by(category_id=id)
        return render_template('user_dashboard.html', category=category)
    return redirect(url_for('user_login'))
    

@app.route('/merchant_login', methods=['GET', 'POST'])
def merchant_login():
    session.pop('admin',None)
    session.pop('aid',None)
    form = MerchantLoginForm()
    if form.validate_on_submit():
        merchant = Merchant.query.filter_by(username=form.username.data).first()
        if merchant:
            if bcrypt.check_password_hash(merchant.password, form.password.data):
                session['admin']=merchant.username
                session['aid']=merchant.id
                return redirect(url_for('merchant_dashboard'))
    return render_template('merchant_login.html', form=form)

@app.route('/merchant_logout', methods=['GET', 'POST'])
def merchant_logout():
    session.pop('admin',None)
    session.pop('aid',None)
    return redirect(url_for('merchant_login'))


@ app.route('/merchant_register', methods=['GET', 'POST'])
def merchant_register():
    form = MerchantRegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_merchant = Merchant(username=form.username.data, password=hashed_password)
        db.session.add(new_merchant)
        db.session.commit()
        return redirect(url_for('merchant_login'))
    return render_template('merchant_register.html', form=form)


@app.route('/merchant_dashboard', methods=['GET', 'POST'])
def merchant_dashboard():
    if g.admin:
        categories=Category.query.all()
        form=AddProducts()
        if form.validate_on_submit():
            category_id=request.form.get("category")
            new_product= Products(name=form.name.data, unit=form.unit.data, rate=form.rate.data, quantity=form.quantity.data, category_id=category_id, admin_id=session['aid'])
            db.session.add(new_product)
            db.session.commit()
            return redirect(url_for('dash'))
        return render_template('merchant_dashboard.html', form=form,  categories=categories, admin=session['admin'])
    return redirect(url_for('merchant_login'))

@app.route('/merchant_list', methods=['GET','POST'])
def merchant_list():
    users=User.query.all()
    return render_template('user_list.html',users=users)

@app.route('/updateproduct/<int:id>', methods=['GET','POST'])
def updateproduct(id):
    if g.admin:
        form = AddProducts(request.form)
        product = Products.query.get_or_404(id)
        categories = Category.query.all()
        category = request.form.get('category')
        if request.method =="POST":
            product.name = form.name.data 
            product.unit = form.unit.data
            product.rate = form.rate.data
            product.quantity = form.quantity.data 
            product.category_id = category
            product.admin_id =session['aid']
            db.session.commit()
            return redirect(url_for('merchant_dashboard'))
        form.name.data = product.name
        form.unit.data = product.unit
        form.rate.data = product.rate
        form.quantity.data = product.quantity
        category = product.category.name
        return render_template('updateproduct.html', form=form, title='Update Product',getp=product,categories=categories)
    return redirect(url_for('merchant_login'))
    

@app.route('/deleteproduct/<int:id>', methods=['POST'])
def deleteproduct(id):
    if g.admin:
        product = Products.query.get_or_404(id)
        if request.method =="POST":
            db.session.delete(product)
            db.session.commit()
            flash(f'{product.name} was deleted!','success')
            return redirect(url_for('dash'))
        flash(f'Not able to delete!','success')
        return redirect(url_for('dash'))
    return redirect(url_for('merchant_login'))


@app.route('/dash', methods=['GET', 'POST'])
def dash():
    if g.admin:
        products=Products.query.filter_by(admin_id=session['aid'])
        return render_template('dash.html', products=products)
    return redirect(url_for('merchant_login'))

@app.route('/merchant_cat', methods=['GET', 'POST'])
def merchant_cat():
    if g.admin:
        form=AddCategories()
        categories=Category.query.filter_by(admin_id=session['aid'])
        if form.validate_on_submit():
            new_category= Category(name=form.name.data,admin_id=session['aid'])
            db.session.add(new_category)
            db.session.commit()
            return redirect(url_for('dash'))
        return render_template('merchant_cat.html', form=form ,categories=categories, admin=session['admin'])
    return redirect(url_for('merchant_login'))

@app.route('/deletecat/<int:id>', methods=['POST'])
def deletecat(id):
    if g.admin:
        category = Category.query.get_or_404(id)
        if request.method =="POST":
            db.session.delete(category)
            db.session.commit()
            flash(f'The product {category.name} deleted!','success')
            return redirect(url_for('merchant_cat'))
        flash(f'Not able to delete!','success')
        return redirect(url_for('merchant_cat'))
    return redirect(url_for('merchant_login'))



@app.route('/editcat/<int:id>', methods=['GET','POST'])
def editcat(id):
    if g.admin:
        form = AddCategories(request.form)
        category = Category.query.get_or_404(id)
        #categories = Category.query.all()
        #category = request.form.get('category')
        if request.method =="POST":
            category.name = form.name.data 
            category.admin_id =session['aid']
            flash('The product was updated!','success')
            db.session.commit()
            return redirect(url_for('merchant_dashboard'))
        form.name.data = category.name
        return render_template('updatecat.html', form=form, title='Update category',getcategory=category)
    return redirect(url_for('merchant_login'))

if __name__ == "__main__":
    app.run(debug=True)