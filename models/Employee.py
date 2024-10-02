from extensions import db


class Employee(db.Model):
    __tablename__ = 'Employees'

    employee_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    ssh_key = db.Column(db.Text, nullable=True)
    embarrassing_fact = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<Employee(id={self.employee_id}, username='{self.username}')>"
