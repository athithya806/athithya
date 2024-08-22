from flask import Flask, render_template, request, redirect, url_for, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import inspect, MetaData, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.types import Integer, String, Float
from datetime import datetime
from sqlalchemy import DateTime, Date, Integer, Float, String
import logging
from sqlalchemy import create_engine, MetaData, Table, Integer, Float, String, DateTime, Date
from flask import Flask, request, jsonify

Base = declarative_base()


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/data dashboard/dashboard.db'
app.config['SQLALCHEMY_BINDS'] = {
    'tables': 'sqlite:///C:/data dashboard/tables.db'
}

app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin' or 'user'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Ensure role is 'admin' or 'user'
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def get_table_metadata(table_name):
    """Retrieve table metadata for a given table name."""
    engine = create_engine(app.config['SQLALCHEMY_BINDS']['tables'])
    metadata = MetaData()
    metadata.reflect(bind=engine, only=[table_name])
    
    if table_name not in metadata.tables:
        raise ValueError(f"Table '{table_name}' does not exist in the database")
    
    return metadata.tables[table_name]


from datetime import datetime

from sqlalchemy.orm import sessionmaker


@app.route('/add/<table_name>', methods=['GET', 'POST'])
@login_required
def add_record(table_name):
    try:
        # Get table metadata
        table = get_table_metadata(table_name)
    except ValueError as e:
        flash(str(e))
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            engine = create_engine(app.config['SQLALCHEMY_BINDS']['tables'])
            Session = sessionmaker(bind=engine)
            session = Session()

            new_record = {}
            for column in table.columns:
                if column.name in request.form and column.name != 'id':
                    value = request.form[column.name]

                    # Convert the value to the appropriate type
                    if isinstance(column.type, Integer):
                        try:
                            value = int(value)
                        except ValueError:
                            flash(f"Invalid integer format for field {column.name}.")
                            return redirect(url_for('add_record', table_name=table_name))
                    elif isinstance(column.type, Float):
                        try:
                            value = float(value)
                        except ValueError:
                            flash(f"Invalid float format for field {column.name}.")
                            return redirect(url_for('add_record', table_name=table_name))
                    elif isinstance(column.type, String):
                        value = str(value)
                    elif isinstance(column.type, DateTime):
                        try:
                            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            logging.error(f"DateTime conversion error for field {column.name}: {value}")
                            flash(f"Invalid date-time format for field {column.name}. Expected format is 'YYYY-MM-DD HH:MM:SS'.")
                            return redirect(url_for('add_record', table_name=table_name))
                    elif isinstance(column.type, Date):
                        try:
                            value = datetime.strptime(value, '%Y-%m-%d').date()
                        except ValueError:
                            logging.error(f"Date conversion error for field {column.name}: {value}")
                            flash(f"Invalid date format for field {column.name}. Expected format is 'YYYY-MM-DD'.")
                            return redirect(url_for('add_record', table_name=table_name))

                    new_record[column.name] = value

            logging.debug(f"New record data: {new_record}")

            # Insert the record into the database
            ins = table.insert().values(new_record)
            session.execute(ins)
            session.commit()
            session.close()

            flash('Record added successfully')
            return redirect(url_for('show_table', table_name=table_name))

        except Exception as e:
            logging.error(f"Error adding record: {e}")
            flash(f"Error adding record: {e}")
            return redirect(url_for('add_record', table_name=table_name))

    columns = [col.name for col in table.columns if col.name != 'id']
    return render_template('add_record.html', table_name=table_name, columns=columns)


# Check the table schema
from sqlalchemy import create_engine, inspect

engine = create_engine('sqlite:///C:/data dashboard/tables.db')
inspector = inspect(engine)
print(inspector.get_table_names())  # Ensure 'Certifications' is listed
columns = inspector.get_columns('Certifications')
#for column in columns:
    #print(column)



@app.route('/')
@login_required
def index():
    inspector = inspect(db.get_engine(app, bind='tables'))
    tables = inspector.get_table_names()
    return render_template('index.html', tables=tables)

@app.route('/show/<table_name>', methods=['GET', 'POST'])
@login_required
def show_table(table_name):
    try:
        table = get_table_metadata(table_name)
        engine = create_engine(app.config['SQLALCHEMY_BINDS']['tables'])
        Session = sessionmaker(bind=engine)
        session = Session()
        records = session.execute(table.select()).fetchall()
        columns = [col.name for col in table.columns]
        session.close()
    except Exception as e:
        flash(f"Error retrieving records: {e}")
        return redirect(url_for('index'))

    is_admin = current_user.role == 'admin'

    return render_template('show_table.html', table_name=table_name, columns=columns, records=records, is_admin=is_admin)

@app.route('/update/<table_name>', methods=['POST'])
@login_required
def update_record(table_name):
    if current_user.role != 'admin':
        return jsonify({"success": False, "error": "Access denied"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    try:
        table = get_table_metadata(table_name)
        if not table:
            return jsonify({"success": False, "error": "Table not found"}), 404

        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        Session = sessionmaker(bind=engine)
        session = Session()

        for row in data:
            row_id = row.get('id')
            if not row_id:
                app.logger.warning("Row missing 'id': %s", row)
                continue  # Skip rows without an ID

            primary_keys = {col.name: row_id for col in table.primary_key.columns}
            update_data = {key: value for key, value in row.items() if key != 'id'}

            if not primary_keys:
                app.logger.error(f"No primary keys found for table {table_name}")
                return jsonify({"success": False, "error": "No primary keys found"}), 500

            # Generate update statement
            stmt = table.update().where(
                *[table.c[k] == v for k, v in primary_keys.items()]
            ).values(update_data)

            # Log the SQL statement
            app.logger.debug(f"Executing SQL: {str(stmt.compile(engine))}")
            app.logger.debug(f"Update data: {update_data}")

            # Execute and commit the statement
            result = session.execute(stmt)
            session.commit()

            if result.rowcount == 0:
                app.logger.warning("No rows updated for ID: %s", row_id)

        session.close()
        return jsonify({"success": True}), 200

    except Exception as e:
        app.logger.error(f"Update error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/delete/<table_name>/<int:record_id>', methods=['DELETE'])
@login_required
def delete_record(table_name, record_id):
    if current_user.role != 'admin':
        return jsonify({"success": False, "error": "Access denied"}), 403

    try:
        table = get_table_metadata(table_name)
        if not table:
            return jsonify({"success": False, "error": "Table not found"}), 404

        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        Session = sessionmaker(bind=engine)
        session = Session()

        # Construct delete statement
        stmt = table.delete().where(table.c.id == record_id)

        # Execute the delete statement
        result = session.execute(stmt)
        session.commit()

        if result.rowcount == 0:
            return jsonify({"success": False, "error": "Record not found"}), 404

        session.close()
        return jsonify({"success": True}), 200

    except Exception as e:
        app.logger.error(f"Delete error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

    
    
if __name__ == '__main__':
    app.run(debug=True)
