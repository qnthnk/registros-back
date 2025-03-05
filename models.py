from database import db
from datetime import datetime
import uuid



def generate_uuid():
    return str(uuid.uuid4())

class Customer(db.Model):
    __tablename__ = "customer"
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    name = db.Column(db.String, nullable=True)
    lastname_f = db.Column(db.String, nullable=True)
    lastname_m = db.Column(db.String, nullable=True)
    curp = db.Column(db.String, unique=True, nullable=False)  # Campo obligatorio
    entidad_nac = db.Column(db.String, nullable=True)
    municipio_nac = db.Column(db.String, nullable=True)
    org = db.Column(db.String, nullable=True)
    address_street = db.Column(db.String, nullable=True)
    address_number = db.Column(db.String, nullable=True)
    colonia = db.Column(db.String, nullable=True)
    postal_code = db.Column(db.String, nullable=True)
    localidad = db.Column(db.String, nullable=True)
    entidad_dir = db.Column(db.String, nullable=True)
    municipio_dir = db.Column(db.String, nullable=True)
    email = db.Column(db.String, nullable=True)
    cell_num = db.Column(db.String, nullable=True)
    instagram = db.Column(db.String, nullable=True)
    facebook = db.Column(db.String, nullable=True)
    password_hash = db.Column(db.String, nullable=True)
    url_image_self_photo = db.Column(db.String, nullable=True)
    url_image_card_front = db.Column(db.String, nullable=True)
    url_image_card_back = db.Column(db.String, nullable=True)
    tel_num = db.Column(db.String, nullable=True)
    comment = db.Column(db.String, nullable=True)
    state = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    created_by = db.Column(db.String, db.ForeignKey('user.id'), nullable=True)

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    name = db.Column(db.String, nullable=False)
    lastname = db.Column(db.String, nullable=True)
    curp = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    tel_num = db.Column(db.String, nullable=True)
    cell_num = db.Column(db.String, nullable=True)
    admin = db.Column(db.Boolean, default=False)
    terminal_id = db.Column(db.String, db.ForeignKey('terminal.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    customers = db.relationship('Customer', backref='creator', lazy=True)

class Terminal(db.Model):
    __tablename__ = "terminal"
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    name = db.Column(db.String, unique=True, nullable=False)
    responsible_id = db.Column(db.String, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

class FuelType(db.Model):
    __tablename__ = "fuel_type"
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    name = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

class Transaction(db.Model):
    __tablename__ = "transaction"
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    customer_id = db.Column(db.String, db.ForeignKey('customer.id'), nullable=False)
    terminal_id = db.Column(db.String, db.ForeignKey('terminal.id'), nullable=False)
    fuel_type_id = db.Column(db.String, db.ForeignKey('fuel_type.id'), nullable=False)
    sales_person_id = db.Column(db.String, db.ForeignKey('user.id'), nullable=False)
    quantity_liters = db.Column(db.Float, nullable=False)
    pay_amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())