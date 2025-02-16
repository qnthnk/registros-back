from flask import Blueprint, send_file, make_response, request, jsonify, render_template, current_app, Response # Blueprint para modularizar y relacionar con app
from flask_bcrypt import Bcrypt                                  # Bcrypt para encriptación
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity   # Jwt para tokens
from models import Customer                                      # importar tabla "Customer" de models
from database import db                                          # importa la db desde database.py
from datetime import timedelta                                   # importa tiempo especifico para rendimiento de token válido
from logging_config import logger                                # logger.info("console log que se ve en render")
import os                                                        # Para datos .env
from dotenv import load_dotenv                                   # Para datos .env
load_dotenv()                                                    # Para datos .env
import pandas as pd                                              # Para modificar tablas
from io import BytesIO                                           # Transformar archivos base 64
#imports para investigar contido de un html específico:
import requests
from bs4 import BeautifulSoup
#------------------------------------------------------



customer_bp = Blueprint('customer_bp', __name__)     # instanciar admin_bp desde clase Blueprint para crear las rutas.

# Inicializamos herramientas de encriptado y access token ------------------------:

bcrypt = Bcrypt()
jwt = JWTManager()

# Sistema de key base pre rutas ------------------------:

API_KEY = os.getenv('API_KEY')

def check_api_key(api_key):
    return api_key == API_KEY

@customer_bp.before_request
def authorize():
    if request.method == 'OPTIONS':
        return
    # En la lista de este if agregamos las rutas que no querramos restringir si no tienen el API_KEY embutido en Authorization en HEADERS.
    if request.path in ['/get_user/<string:curp>','/update_customer','/create_customer_minimal','/test_customer_bp']:
        return
    api_key = request.headers.get('Authorization')
    if not api_key or not check_api_key(api_key):
        return jsonify({'message': 'Unauthorized'}), 401
    
# Ruta TEST------------------------------------------------
@customer_bp.route('/test_customer_bp', methods=['GET'])
def test():
    return jsonify({'message': 'test bien sucedido','status':"Si lees esto, rutas de customer funcionan bien..."}),200

# 1. Ruta para crear un Customer con datos mínimos (requiere token)
@customer_bp.route('/create_customer_minimal', methods=['POST'])
@jwt_required()
def create_customer_minimal():
    try:
        data = request.json
        curp = data.get('curp')
        admin = data.get('admin')

        if not curp or not admin:
            return jsonify({"error": "El campo 'curp' es obligatorio. Y además tenes que ser admin"}), 400

        # Verificar si ya existe un Customer con ese curp
        if Customer.query.filter_by(curp=curp).first():
            return jsonify({"error": "Ya existe un Customer con ese curp."}), 409

        # Creamos el Customer usando el mínimo requerido
        new_customer = Customer(
            curp=curp,
            # Se pueden asignar otros campos opcionales si vienen en el JSON:
            name=data.get('name'),
            email=data.get('email')
        )

        db.session.add(new_customer)
        db.session.commit()

        customer_data = {
            "id": new_customer.id,
            "curp": new_customer.curp,
            "name": new_customer.name,
            "email": new_customer.email
        }

        return jsonify({
            "message": "Customer creado con éxito.",
            "customer": customer_data
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al crear el Customer: " + str(e)}), 500


# 2. Ruta para actualizar un Customer existente ( para admin )
@customer_bp.route('/update_customer', methods=['PUT'])
def update_customer():
    try:
        data = request.json
        curp = data.get('curp')
        if not curp:
            return jsonify({"error": "El campo 'curp' es obligatorio para identificar al Customer."}), 400

        # Buscar el Customer existente por curp
        customer = Customer.query.filter_by(curp=curp).first()
        if not customer:
            return jsonify({"error": "No existe un Customer con ese curp."}), 404

        # Actualizar campos (si se pasan en el request, sino se mantienen los previos)
        customer.name            = data.get('name', customer.name)
        customer.lastname_f      = data.get('lastname_f', customer.lastname_f)
        customer.lastname_m      = data.get('lastname_m', customer.lastname_m)
        customer.entidad_nac     = data.get('entidad_nac', customer.entidad_nac)
        customer.municipio_nac   = data.get('municipio_nac', customer.municipio_nac)
        customer.org             = data.get('org', customer.org)
        customer.address_street  = data.get('address_street', customer.address_street)
        customer.address_number  = data.get('address_number', customer.address_number)
        customer.colonia         = data.get('colonia', customer.colonia)
        customer.postal_code     = data.get('postal_code', customer.postal_code)
        customer.localidad       = data.get('localidad', customer.localidad)
        customer.entidad_dir     = data.get('entidad_dir', customer.entidad_dir)
        customer.municipio_dir   = data.get('municipio_dir', customer.municipio_dir)
        customer.email           = data.get('email', customer.email)
        customer.cell_num        = data.get('cell_num', customer.cell_num)
        customer.instagram       = data.get('instagram', customer.instagram)
        customer.facebook        = data.get('facebook', customer.facebook)
        customer.tel_num         = data.get('tel_num', customer.tel_num)
        customer.comment         = data.get('comment', customer.comment)
        customer.state           = data.get('state', customer.state)

        db.session.commit()

        updated_customer = {
            "id": customer.id,
            "curp": customer.curp,
            "name": customer.name,
            "lastname_f": customer.lastname_f,
            "lastname_m": customer.lastname_m,
            "entidad_nac": customer.entidad_nac,
            "municipio_nac": customer.municipio_nac,
            "org": customer.org,
            "address_street": customer.address_street,
            "address_number": customer.address_number,
            "colonia": customer.colonia,
            "postal_code": customer.postal_code,
            "localidad": customer.localidad,
            "entidad_dir": customer.entidad_dir,
            "municipio_dir": customer.municipio_dir,
            "email": customer.email,
            "cell_num": customer.cell_num,
            "instagram": customer.instagram,
            "facebook": customer.facebook,
            "tel_num": customer.tel_num,
            "comment": customer.comment,
            "state": customer.state,
            "created_at": customer.created_at.isoformat() if customer.created_at else None,
            "updated_at": customer.updated_at.isoformat() if customer.updated_at else None
        }

        return jsonify({
            "message": "Customer actualizado con éxito.",
            "customer": updated_customer
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al actualizar el Customer: " + str(e)}), 500
    

# RUTA PARA OBTENER UN CUSTOMER POR SU CURP
@customer_bp.route('/get_customer/<string:curp>', methods=['GET'])
def get_user(curp):
    try:
        # Buscamos al Customer por su curp (recordá que es un string)
        customer = Customer.query.filter_by(curp=curp).one()
        if customer:
            customer_data = {
                'id': customer.id,
                'name': customer.name,
                'lastname_f': customer.lastname_f,
                'lastname_m': customer.lastname_m,
                'curp': customer.curp,
                'entidad_nac': customer.entidad_nac,
                'municipio_nac': customer.municipio_nac,
                'org': customer.org,
                'address_street': customer.address_street,
                'address_number': customer.address_number,
                'colonia': customer.colonia,
                'postal_code': customer.postal_code,
                'localidad': customer.localidad,
                'entidad_dir': customer.entidad_dir,
                'municipio_dir': customer.municipio_dir,
                'email': customer.email,
                'cell_num': customer.cell_num,
                'instagram': customer.instagram,
                'facebook': customer.facebook,
                'tel_num': customer.tel_num,
                'admin': customer.admin,
                'comment': customer.comment,
                'state': customer.state,
                'created_at': customer.created_at.isoformat() if customer.created_at else None,
                'updated_at': customer.updated_at.isoformat() if customer.updated_at else None,
            }
            return jsonify(customer_data), 200
        else:
            return jsonify({"error": "No se encontró un cliente con esa CURP"}), 404
    except Exception as e:
        return jsonify({"error": "El curp proporcionado no corresponde a ninguno registrado: " + str(e)}), 500
    

# 1. Ruta para chequear existencia del Customer:
#    Esta ruta chequea que el 'curp' exista en la DB. Si existe, se genera un token (con el id como identity)
#    y se devuelve "ok": True, con un mensaje "Permitido".
@customer_bp.route('/check_customer', methods=['GET'])
def check_customer():
    try:
        data = request.json
        curp = data.get('curp')
        if not curp:
            return jsonify({"error": "El campo 'curp' es obligatorio."}), 400

        # Buscar un Customer existente con ese curp
        customer = Customer.query.filter_by(curp=curp).first()
        if not customer:
            return jsonify({"error": "No existe un Customer con ese curp. Venta no permitida."}), 404

        # Generar token con el id del customer
        expires = timedelta(minutes=60)
        token = create_access_token(identity=customer.id, expires_delta=expires)

        return jsonify({
            "ok": True,
            "message": "Permitido",
            "access_token": token
        }), 200

    except Exception as e:
        return jsonify({"error": "Error al procesar el registro: " + str(e)}), 500

# 2. Ruta para completar (actualizar) la información del Customer existente.
#    Esta ruta está protegida y utiliza el token (que se generó en la ruta anterior) para identificar al Customer.
@customer_bp.route('/complete_customer', methods=['PUT'])
@jwt_required()
def complete_customer():
    try:
        data = request.json
        current_customer_id = get_jwt_identity()
        customer = Customer.query.filter_by(id=current_customer_id).first()
        if not customer:
            return jsonify({"error": "Customer no encontrado."}), 404

        # Actualizar los campos con los datos recibidos, pisando los previos si existen.
        customer.name            = data.get('name', customer.name)
        customer.lastname_f      = data.get('lastname_f', customer.lastname_f)
        customer.lastname_m      = data.get('lastname_m', customer.lastname_m)
        customer.entidad_nac     = data.get('entidad_nac', customer.entidad_nac)
        customer.municipio_nac   = data.get('municipio_nac', customer.municipio_nac)
        customer.org             = data.get('org', customer.org)
        customer.address_street  = data.get('address_street', customer.address_street)
        customer.address_number  = data.get('address_number', customer.address_number)
        customer.colonia         = data.get('colonia', customer.colonia)
        customer.postal_code     = data.get('postal_code', customer.postal_code)
        customer.localidad       = data.get('localidad', customer.localidad)
        customer.entidad_dir     = data.get('entidad_dir', customer.entidad_dir)
        customer.municipio_dir   = data.get('municipio_dir', customer.municipio_dir)
        customer.email           = data.get('email', customer.email)
        customer.cell_num        = data.get('cell_num', customer.cell_num)
        customer.instagram       = data.get('instagram', customer.instagram)
        customer.facebook        = data.get('facebook', customer.facebook)
        customer.tel_num         = data.get('tel_num', customer.tel_num)
        customer.comment         = data.get('comment', customer.comment)
        customer.state           = data.get('state', customer.state)
        
        # Si se envía una contraseña, actualizar el password_hash
        password = data.get('password')
        if password:
            customer.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.commit()

        updated_customer = {
            "id": customer.id,
            "curp": customer.curp,
            "name": customer.name,
            "lastname_f": customer.lastname_f,
            "lastname_m": customer.lastname_m,
            "entidad_nac": customer.entidad_nac,
            "municipio_nac": customer.municipio_nac,
            "org": customer.org,
            "address_street": customer.address_street,
            "address_number": customer.address_number,
            "colonia": customer.colonia,
            "postal_code": customer.postal_code,
            "localidad": customer.localidad,
            "entidad_dir": customer.entidad_dir,
            "municipio_dir": customer.municipio_dir,
            "email": customer.email,
            "cell_num": customer.cell_num,
            "instagram": customer.instagram,
            "facebook": customer.facebook,
            "tel_num": customer.tel_num,
            "comment": customer.comment,
            "state": customer.state,
            "created_at": customer.created_at.isoformat() if customer.created_at else None,
            "updated_at": customer.updated_at.isoformat() if customer.updated_at else None
        }

        return jsonify({
            "message": "Customer actualizado con éxito.",
            "customer": updated_customer
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al actualizar el Customer: " + str(e)}), 500

# 3. Ruta de log-in para el Customer usando email y password.
#    Se verifica que el email exista, se chequea el password_hash, y si todo está ok se genera un token con el id del Customer.
@customer_bp.route('/customer_login', methods=['POST'])
def customer_login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email y password son requeridos."}), 400

        customer = Customer.query.filter_by(email=email).first()
        if not customer:
            return jsonify({"error": "Credenciales incorrectas.Email"}), 401

        if not customer.password_hash:
            return jsonify({"error": "No se ha configurado una contraseña para este Customer."}), 401

        if not bcrypt.check_password_hash(customer.password_hash, password):
            return jsonify({"error": "Credenciales incorrectas.Pass"}), 401

        expires = timedelta(minutes=30)
        token = create_access_token(identity=customer.id, expires_delta=expires)

        customer_data = {
            "id": customer.id,
            "curp": customer.curp,
            "name": customer.name,
            "email": customer.email
        }
        return jsonify({
            "access_token": token,
            "customer": customer_data
        }), 200

    except Exception as e:
        return jsonify({"error": "Error en el login del Customer: " + str(e)}), 500