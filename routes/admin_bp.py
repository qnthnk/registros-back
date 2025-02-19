from flask import Blueprint, send_file, make_response, request, jsonify, render_template, current_app, Response # Blueprint para modularizar y relacionar con app
from flask_bcrypt import Bcrypt                                  # Bcrypt para encriptación
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity   # Jwt para tokens
from models import User, Terminal                                  # importar tabla "User" de models
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
        terminal_id = request.json.get('terminal_id')  # Opcional
        first_pass = request.json.get('first_pass')  # Nuevo campo opcional

        # Validar campos requeridos
        if not email or not password or not name or not curp:
            return jsonify({'error': 'Email, password, name y curp son requeridos.'}), 400

        # Verificar si el email ya existe
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'El email ya existe.'}), 409

        # Validar la existencia del terminal_id. Si no existe, lo dejamos como None.
        if terminal_id:
            terminal = Terminal.query.filter_by(id=terminal_id).first()
            if not terminal:
                terminal_id = None

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
            admin=admin,
            terminal_id=terminal_id  # Se asigna el terminal_id si existe, o None en caso contrario.
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
                'admin': new_user.admin,
                'terminal_id': new_user.terminal_id
            },
            'success':True
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error en la creación del usuario: ' + str(e), 'success':False}), 500

# ELIMINAR USUARIO
@admin_bp.route('/users/<string:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)

    if not user:
        return jsonify({'msg': 'Usuario no encontrado', 'success': False}), 404
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'msg': 'Usuario eliminado', 'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'msg': 'Error al eliminar el usuario', 'success': False}), 500


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
            expires = timedelta(hours=9)
            # Usamos el id del usuario (UUID) como identity para el token
            access_token = create_access_token(identity=login_user.id, expires_delta=expires)
            return jsonify({
                'access_token': access_token,
                'id': login_user.id,
                'name': login_user.name,
                'curp': login_user.curp,
                'email': login_user.email,
                'admin': login_user.admin,
                'terminal_id': login_user.terminal_id
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
        terminal_id = request.json.get('terminal_id')  # Opcional

        if not email or not name or not curp:
            return jsonify({"error": "Email, terminal, name y curp son obligatorios"}), 400
        
        # Validar la existencia del terminal_id. Si no existe, lo dejamos como None.
        if terminal_id:
            terminal = Terminal.query.filter_by(id=terminal_id).first()
            if not terminal:
                terminal_id = None

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        user.name = name
        user.curp = curp
        user.terminal_id = terminal_id
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        return jsonify({"message": "Usuario actualizado con éxito"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error al actualizar el usuario: {str(e)}"}), 500

 
# RUTA PARA ACTUALIZAR EL ESTADO ADMIN DE UN USUARIO
