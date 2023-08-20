from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Defina uma chave secreta forte em um ambiente de produção.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Modelo de dados do usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Função para verificar se a senha atende aos critérios
def is_password_valid(password):
    if len(password) < 6:
        return False
    if not re.search("[a-zA-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*]", password):
        return False
    return True
@app.route('/')
def index():
    return render_template('index.html')


# Rota de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificar se o usuário já existe
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.', 'error')
        else:
            # Verificar a validade da senha
            if not is_password_valid(password):
                flash('A senha deve ter pelo menos 6 caracteres e conter pelo menos um número, uma letra e um caractere especial, sem ser o ponto.', 'error')
            else:
                # Criar um novo usuário
                new_user = User(username=username, password=password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registro bem-sucedido.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            session['user_id'] = user.id
            flash('Login bem-sucedido.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nome de usuário ou senha incorretos.', 'error')

    return render_template('login.html')

# Rota de dashboard (requer login)
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return 'Página do Painel - Usuário Logado'
    else:
        return redirect(url_for('login'))

# Rota de logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout bem-sucedido.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
