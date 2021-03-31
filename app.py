from flask import Flask, request, render_template, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form , StringField, TextAreaField, PasswordField, BooleanField, RadioField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# configuration of Mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'nipun2002'
app.config['MYSQL_DB'] = 'dbms_blog_manage_tp1'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# initialize MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/home')
def home():
    return render_template('home.html')

# check if user is logged in 
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('UNAUTHORIZED, PLEASE LOGIN', 'danger')
            return redirect(url_for('login'))
    return wrap

# user login 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        # getting fields of form
        username = request.form['username']
        password_candidate = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # to get user by username
        result = cur.execute("SELECT * FROM login WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            print(data)
            password = data['user_password']
            
            # if sha256_crypt.verify(password_candidate, password):
            if password_candidate==password:
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('YOU ARE LOGGED IN', 'success')
                return redirect(url_for('home'))

            else:
                error = 'INVALID PASSWORD'
                return render_template('login.html', error = error)
            # close connection
            cur.close()
            
        else:
            error = 'USERNAME NOT FOUND'
            return render_template('login.html', error = error)

            

    return render_template('login.html')


# logout
@app.route('/logout')
@is_logged_in   
def logout():
    session.clear()
    flash('YOU ARE NOW LOGGED OUT', 'success')
    return redirect(url_for('login'))

@app.route('/admins_super')
@is_logged_in
def admins_super():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    results = cur.execute("SELECT * from login where isAdmin=true and isSuperAdmin=false")

    admin_users = cur.fetchall()

    if results > 0:
        return render_template('admin_users.html', admin_users = admin_users)
    else:
        msg = 'No Admin Users Found'
        return render_template('admin_users.html', msg=msg)

    # closing the connection
    cur.close()

# Article class
class AdminUserForm(Form):
    username = StringField('username', [validators.Length(min=1, max=200)])
    user_password = PasswordField('user_password', [validators.Length(min=1, max=200)])
    # is_Admin = BooleanField('is_Admin', [validators.DataRequired()])
    is_Admin = RadioField('User_Type', choices=[(1, 'Admin'),(0, 'User')])

# Article route
@app.route('/add_admin_user', methods=['GET', 'POST'])
@is_logged_in
def add_admin_user():
    form = AdminUserForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        user_password = form.user_password.data
        is_Admin = form.is_Admin.data

        # create cursors
        cur = mysql.connection.cursor()

        result = cur.execute("select username from login")
        
        result1 = list(cur.fetchall())
        tkp = []
        for i in result1:
            tkp.append(i['username'])
        if username in tkp:
            error = 'USERNAME ALREADY EXISTS'
            return render_template('add_admin_user.html', form = form, error=error)
        else:

            # print(123456, True)
            # print(1111, result1, tkp, type(result1))
            # execute

            cur.execute("INSERT INTO login(username, user_password, isAdmin) VALUES( %s, %s, %s)", (username, user_password, is_Admin))

            # commit to DB
            mysql.connection.commit()

            # close connection
            cur.close()

            flash('Admin User created successfully', 'success')

            return redirect(url_for('admins_super'))
    
    return render_template('add_admin_user.html', form = form)

# delete article
@app.route('/delete_admin_user/<string:username>', methods=['GET', 'POST'])
@is_logged_in
def delete_admin_user(username):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM login WHERE username = %s", [username])

    mysql.connection.commit()

    cur.close()

    flash('Admin User Deleted', 'success')

    return redirect(url_for('admins_super'))


if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
