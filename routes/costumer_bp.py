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
    if request.path in ['/create_customer','/get_user/<string:curp>','/update_customer','/create_customer_minimal','/test_customer_bp']:
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


# 2. Crear un customer nuevo y / o actualizarlo.
@customer_bp.route('/create_customer', methods=['POST'])
@jwt_required()
def create_customer_full():
    try:
        data_prev = request.json
        data = data_prev.customerData

        # Campo obligatorio
        curp = data.get('curp')

        if not curp:
            return jsonify({"error": "El campo 'curp' y el id son obligatorios."}), 400

        # Buscar si ya existe un Customer con ese curp
        customer = Customer.query.filter_by(curp=curp).first()

        # Seteando una variable que guarde si es una actualizacion o si es nuevo
        proceso = ""
        if not customer:
            proceso = "creado"
            # Crear nuevo Customer
            customer = Customer(
                curp = curp,
                name = data.get('name'),
                lastname_f = data.get('lastname_f'),
                lastname_m = data.get('lastname_m'),
                entidad_nac = data.get('entidad_nac'),
                municipio_nac = data.get('municipio_nac'),
                org = data.get('org'),
                address_street = data.get('address_street'),
                address_number = data.get('address_number'),
                colonia = data.get('colonia'),
                postal_code = data.get('postal_code'),
                localidad = data.get('localidad'),
                entidad_dir = data.get('entidad_dir'),
                municipio_dir = data.get('municipio_dir'),
                email = data.get('email'),
                cell_num = data.get('cell_num'),
                instagram = data.get('instagram'),
                facebook = data.get('facebook'),
                password_hash = data.get('password_hash'),
                url_image_self_photo = data.get('url_image_self_photo'),
                url_image_card_front = data.get('url_image_card_front'),
                url_image_card_back = data.get('url_image_card_back'),
                tel_num = data.get('tel_num'),
                comment = data.get('comment'),
                state = data.get('state', True),
                created_by = data_prev.creador
            )
            db.session.add(customer)
            message = "Customer creado con éxito."
        else:
            proceso = "actualizado"
            # Actualizar Customer existente: se actualizan los campos si se mandan en el request
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
            customer.password_hash   = data.get('password_hash', customer.password_hash)
            customer.url_image_self_photo = data.get('url_image_self_photo', customer.url_image_self_photo)
            customer.url_image_card_front = data.get('url_image_card_front', customer.url_image_card_front)
            customer.url_image_card_back = data.get('url_image_card_back', customer.url_image_card_back)
            customer.tel_num         = data.get('tel_num', customer.tel_num)
            customer.comment         = data.get('comment', customer.comment)
            customer.state           = data.get('state', customer.state)
            customer.created_by      = data_prev.creador
            message = "Customer actualizado con éxito."

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
            "updated_at": customer.updated_at.isoformat() if customer.updated_at else None,
            "created_by": customer.created_by
        }

        return jsonify({
            "message": message,
            "customer": updated_customer,
            "proceso": proceso
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al crear/actualizar el Customer: " + str(e)}), 500

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
                'comment': customer.comment,
                'state': customer.state,
                'created_at': customer.created_at.isoformat() if customer.created_at else None,
                'updated_at': customer.updated_at.isoformat() if customer.updated_at else None,
            }
            return jsonify({'customer_data':customer_data, 'exist':True}), 200
        else:
            return jsonify({"error": "No se encontró un cliente con esa CURP", 'exist':False}), 404
    except Exception as e:
        return jsonify({"error": "El curp proporcionado no corresponde a ninguno registrado: " + str(e), 'exist':False}), 500
    

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
def complete_customer():
    try:
        data = request.json

        # Obtenemos el customer_id del payload
        customer_id = data.get('customer_id')
        if not customer_id:
            return jsonify({"error": "El campo 'customer_id' es obligatorio."}), 400

        # Buscamos el customer usando el customer_id recibido
        customer = Customer.query.filter_by(id=customer_id).first()
        if not customer:
            return jsonify({"error": "Customer no encontrado."}), 404

        # Actualizamos los campos recibidos, manteniendo los existentes si no se mandan nuevos datos
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
        # Actualizamos el state de acuerdo al payload (false para baja, true para alta)
        customer.state           = data.get('state', customer.state)

        # Si se envía una contraseña, actualizamos el password_hash
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
    

@customer_bp.route('/users-list', methods=['GET'])
def get_customers_list():
    try:
        customers = Customer.query.all()
        customers_list = [
            {
                "id": customer.id,
                "name": customer.name,
                "lastname_f": customer.lastname_f,
                "lastname_m": customer.lastname_m,
                "curp": customer.curp,
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
                "url_image_self_photo": customer.url_image_self_photo,
                "url_image_card_front": customer.url_image_card_front,
                "url_image_card_back": customer.url_image_card_back,
                "tel_num": customer.tel_num,
                "comment": customer.comment,
                "state": customer.state,
                "created_at": customer.created_at.isoformat() if customer.created_at else None,
                "updated_at": customer.updated_at.isoformat() if customer.updated_at else None,
            }
            for customer in customers
        ]
        return jsonify({"list": customers_list}), 200
    except Exception as e:
        return jsonify({"error": f"Error al obtener la lista de clientes: {str(e)}"}), 500


@customer_bp.route('/delete_customer/<string:customer_id>', methods=['DELETE'])
def delete_customer(customer_id):
    try:
        customer = Customer.query.get(customer_id)
        if not customer:
            return jsonify({"msg": "Cliente no encontrado"}), 404

        db.session.delete(customer)
        db.session.commit()
        return jsonify({"msg": "Cliente eliminado con éxito"}), 200
    except Exception as e:
        db.session.rollback()
        print("Error al eliminar el cliente:", e)
        return jsonify({"msg": f"Error al eliminar el cliente: {str(e)}"}), 500
    
@customer_bp.route('/get_registers_list', methods=['GET'])
def get_registers_list():
    try:
        logger.info("Iniciando generación del Excel")
        # Consultar todos los registros de Customer
        customers = Customer.query.all()
        logger.info("Registros obtenidos: %s", len(customers))
        
        # Convertir los registros a una lista de diccionarios, convirtiendo las fechas a string
        data = []
        for c in customers:
            customer_data = {
                'id': c.id,
                'name': c.name,
                'lastname_f': c.lastname_f,
                'lastname_m': c.lastname_m,
                'curp': c.curp,
                'entidad_nac': c.entidad_nac,
                'municipio_nac': c.municipio_nac,
                'org': c.org,
                'address_street': c.address_street,
                'address_number': c.address_number,
                'colonia': c.colonia,
                'postal_code': c.postal_code,
                'localidad': c.localidad,
                'entidad_dir': c.entidad_dir,
                'municipio_dir': c.municipio_dir,
                'email': c.email,
                'cell_num': c.cell_num,
                'instagram': c.instagram,
                'facebook': c.facebook,
                'tel_num': c.tel_num,
                'comment': c.comment,
                'state': c.state,
                'created_at': c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else "",
                'updated_at': c.updated_at.strftime("%Y-%m-%d %H:%M:%S") if c.updated_at else ""
            }
            data.append(customer_data)
        logger.info("Datos convertidos a lista de diccionarios, total: %s", len(data))
        
        # Generar un DataFrame y escribirlo a un archivo Excel en memoria
        df = pd.DataFrame(data)
        logger.info("DataFrame generado con shape: %s", df.shape)
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Customers')
        output.seek(0)
        logger.info("Excel generado en memoria, enviando archivo")
        
        return send_file(
            output, 
            download_name="clientes.xlsx", 
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        logger.exception("Error generando el Excel")
        return jsonify({'error': 'Error al generar el Excel.'}), 500
    

@customer_bp.route('/get_registers_by_user', methods=['POST'])
def get_registers_by_user():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'error': 'Falta user_id en el cuerpo JSON.'}), 400

        logger.info("Generando Excel para user_id: %s", user_id)
        # Filtramos los customers creados por ese user
        customers = Customer.query.filter_by(created_by=user_id).all()
        logger.info("Registros obtenidos: %s", len(customers))

        # Convertir cada registro a diccionario
        data_list = []
        for c in customers:
            customer_data = {
                'id': c.id,
                'name': c.name,
                'lastname_f': c.lastname_f,
                'lastname_m': c.lastname_m,
                'curp': c.curp,
                'entidad_nac': c.entidad_nac,
                'municipio_nac': c.municipio_nac,
                'org': c.org,
                'address_street': c.address_street,
                'address_number': c.address_number,
                'colonia': c.colonia,
                'postal_code': c.postal_code,
                'localidad': c.localidad,
                'entidad_dir': c.entidad_dir,
                'municipio_dir': c.municipio_dir,
                'email': c.email,
                'cell_num': c.cell_num,
                'instagram': c.instagram,
                'facebook': c.facebook,
                'tel_num': c.tel_num,
                'comment': c.comment,
                'state': c.state,
                'created_at': c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else "",
                'updated_at': c.updated_at.strftime("%Y-%m-%d %H:%M:%S") if c.updated_at else ""
            }
            data_list.append(customer_data)
        logger.info("Datos convertidos a lista de diccionarios, total: %s", len(data_list))

        # Generar Excel en memoria
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df = pd.DataFrame(data_list)
            df.to_excel(writer, index=False, sheet_name='Customers')
        output.seek(0)
        logger.info("Excel generado en memoria, enviando archivo")

        return send_file(
            output,
            download_name="clientes_por_usuario.xlsx",
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        logger.exception("Error generando el Excel por user_id")
        return jsonify({'error': 'Error al generar el Excel.'}), 500