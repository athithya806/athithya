from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, MetaData, Table

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/HW-24/Desktop/data dashboard/dashboard.db'
db = SQLAlchemy(app)

def get_table_class(table_name):
    """Dynamically create a table class with primary key handling."""
    metadata = MetaData()
    table = Table(table_name, metadata, autoload_with=db.engine)
    
    # Check if the table has a primary key
    if not table.primary_key.columns:
        raise ValueError(f"Table '{table_name}' does not have a primary key")

    return type(table_name, (db.Model,), {
        '__table__': table,
        '__tablename__': table_name
    })

@app.route('/')
def index():
    # Retrieve table names from the database
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    return render_template('index.html', tables=tables)

@app.route('/show/<table_name>')
def show_table(table_name):
    try:
        table_class = get_table_class(table_name)
    except ValueError as e:
        return str(e), 400

    # Retrieve all records from the table
    records = table_class.query.all()
    columns = [col.name for col in table_class.__table__.columns]

    return render_template('show_table.html', table_name=table_name, columns=columns, records=records)

@app.route('/update/<table_name>', methods=['GET', 'POST'])
def update_table(table_name):
    try:
        table_class = get_table_class(table_name)
    except ValueError as e:
        return str(e), 400

    if request.method == 'POST':
        data = request.form
        columns = [col.name for col in table_class.__table__.columns]
        
        # Handle record updates
        try:
            record_id = data.get('id')  # Assuming you have an 'id' field for identifying records
            record = table_class.query.get(record_id)
            if record:
                for column in columns:
                    setattr(record, column, data.get(column))
                db.session.commit()
            else:
                # Handle case where record ID is not found
                return "Record not found", 404
        except Exception as e:
            # Handle exceptions during update
            return f"An error occurred: {str(e)}", 500
        return redirect('/')

    # Retrieve columns for the selected table
    columns = [col.name for col in table_class.__table__.columns]
    return render_template('update.html', table_name=table_name, columns=columns)

if __name__ == '__main__':
    app.run(debug=True)
