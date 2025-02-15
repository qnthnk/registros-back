from flask import Blueprint, send_file, make_response, request, jsonify, render_template, current_app, Response # Blueprint para modularizar y relacionar con app
from flask_bcrypt import Bcrypt                                  # Bcrypt para encriptación
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity   # Jwt para tokens
from models import User, Customer                                  # importar tabla "User" de models
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



admin_bp = Blueprint('admin', __name__)     # instanciar admin_bp desde clase Blueprint para crear las rutas.

# Inicializamos herramientas de encriptado y access token ------------------------:

bcrypt = Bcrypt()
jwt = JWTManager()

# Sistema de key base pre rutas ------------------------:

API_KEY = os.getenv('API_KEY')

def check_api_key(api_key):
    return api_key == API_KEY

@admin_bp.before_request
def authorize():
    if request.method == 'OPTIONS':
        return
    # En la lista de este if agregamos las rutas que no querramos restringir si no tienen el API_KEY embutido en Authorization en HEADERS.
    if request.path in ['/test_admin_bp','/','/correccion_campos_vacios','/descargar_positividad_corregida','/download_comments_evaluation','/all_comments_evaluation','/download_resume_csv','/create_resumes_of_all','/descargar_excel','/create_resumes', '/reportes_disponibles', '/create_user', '/login', '/users','/update_profile','/update_profile_image','/update_admin']:
        return
    api_key = request.headers.get('Authorization')
    if not api_key or not check_api_key(api_key):
        return jsonify({'message': 'Unauthorized'}), 401
    
#--------------------------------RUTAS SINGLE---------------------------------



# Ruta TEST------------------------------------------------
@admin_bp.route('/test_admin_bp', methods=['GET'])
def test():
    return jsonify({'message': 'test bien sucedido','status':"Si lees esto, tenemos que ver como manejar el timeout porque los archivos llegan..."}),200

# RUTA DOCUMENTACION
@admin_bp.route('/', methods=['GET'])
def show_hello_world():
         return render_template('instructions.html')

# CREAR USUARIO
@admin_bp.route('/create_user', methods=['POST'])
def create_user():
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        name = request.json.get('name')
        curp = request.json.get('curp')  # Campo requerido
        first_pass = request.json.get('first_pass')  # Nuevo campo

        # Validar campos requeridos
        if not email or not password or not name or not curp:
            return jsonify({'error': 'Email, password, name y curp son requeridos.'}), 400

        # Verificar si el email ya existe
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'El email ya existe.'}), 409

        # Comprobar la clave especial de admin desde el .env
        admin_key = os.getenv('ADMIN_FIRST_PASS_KEY')
        admin = False
        if first_pass and first_pass == admin_key:
            admin = True

        # Generar el hash de la contraseña
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Crear el nuevo usuario
        new_user = User(
            email=email,
            password_hash=password_hash,
            name=name,
            curp=curp,
            admin=admin
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'message': 'Usuario creado con éxito.',
            'user_created': {
                'id': new_user.id,
                'name': new_user.name,
                'email': new_user.email,
                'curp': new_user.curp,
                'admin': new_user.admin
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error en la creación del usuario: ' + str(e)}), 500

# LOGIN (CON TOKEN)
@admin_bp.route('/login', methods=['POST'])
def get_token():
    try:
        email = request.json.get('email')
        password = request.json.get('password')

        if not email or not password:
            return jsonify({'error': 'Email y password son requeridos.'}), 400

        login_user = User.query.filter_by(email=email).one()  # Si no se encuentra, lanza excepción

        if bcrypt.check_password_hash(login_user.password_hash, password):
            expires = timedelta(minutes=30)
            # Usamos el id del usuario (UUID) como identity para el token
            access_token = create_access_token(identity=login_user.id, expires_delta=expires)
            return jsonify({
                'access_token': access_token,
                'id': login_user.id,
                'name': login_user.name,
                'curp': login_user.curp,
                'email': login_user.email,
                'admin': login_user.admin
            }), 200
        else:
            return jsonify({"error": "Contraseña incorrecta"}), 401

    except Exception as e:
        return jsonify({"error": "El email proporcionado no corresponde a ninguno registrado: " + str(e)}), 500

# MOSTRAR TODOS LOS USUARIOS (ruta protegida con JWT)
@admin_bp.route('/users', methods=['GET'])
@jwt_required()
def show_users():
    try:
        current_user_id = get_jwt_identity()  # Ahora este valor es el id (UUID)
        # Opcionalmente, se puede verificar que el usuario del token sea admin
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'name': user.name,
                'curp': user.curp,
                'email': user.email,
                'admin': user.admin
            })
        return jsonify({"lista_usuarios": user_list, 'cantidad': len(user_list)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ACTUALIZAR PERFIL (ruta opcional, no utiliza token en este ejemplo)
@admin_bp.route('/update_profile', methods=['PUT'])
def update_profile():
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        name = request.json.get('name')
        curp = request.json.get('curp')

        if not email or not password or not name or not curp:
            return jsonify({"error": "Email, password, name y curp son obligatorios"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        user.name = name
        user.curp = curp
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        return jsonify({"message": "Usuario actualizado con éxito"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error al actualizar el usuario: {str(e)}"}), 500

 
# RUTA PARA ACTUALIZAR EL ESTADO ADMIN DE UN USUARIO
@admin_bp.route('/update_admin', methods=['PUT'])
def update_admin():
    email = request.json.get('email')
    admin_value = request.json.get('admin')  # Aunque no se utiliza, se valida que venga
    if email is None or admin_value is None:
        return jsonify({"error": "El email y la situación admin son obligatorios"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Togleamos (invertimos) el estado actual
    user.admin = not user.admin

    try:
        db.session.commit()
        return jsonify({
            "message": f"Estado admin de {email} ahora es {'admin' if user.admin else 'no admin'}",
            "admin": user.admin
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error al actualizar el estado admin: {str(e)}"}), 500


# RUTA PARA OBTENER UN CUSTOMER POR SU CURP
@admin_bp.route('/get_user/<string:curp>', methods=['GET'])
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