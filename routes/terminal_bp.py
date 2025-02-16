from flask import Blueprint, send_file, make_response, request, jsonify, render_template, current_app, Response # Blueprint para modularizar y relacionar con app
from flask_bcrypt import Bcrypt                                  # Bcrypt para encriptación
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity   # Jwt para tokens
from models import Terminal                                     # importar tabla "Customer" de models
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



terminal_bp = Blueprint('terminal_bp', __name__)     # instanciar admin_bp desde clase Blueprint para crear las rutas.

# Inicializamos herramientas de encriptado y access token ------------------------:

bcrypt = Bcrypt()
jwt = JWTManager()

# Sistema de key base pre rutas ------------------------:

API_KEY = os.getenv('API_KEY')

def check_api_key(api_key):
    return api_key == API_KEY

@terminal_bp.before_request
def authorize():
    if request.method == 'OPTIONS':
        return
    # En la lista de este if agregamos las rutas que no querramos restringir si no tienen el API_KEY embutido en Authorization en HEADERS.
    if request.path in ['/terminals','/delete_terminal/<string:terminal_id>','/terminal_bp','/test_terminal_bp']:
        return
    api_key = request.headers.get('Authorization')
    if not api_key or not check_api_key(api_key):
        return jsonify({'message': 'Unauthorized'}), 401
    
# Ruta TEST------------------------------------------------
@terminal_bp.route('/test_terminal_bp', methods=['GET'])
def test():
    return jsonify({'message': 'test bien sucedido','status':"Si lees esto, rutas de terminal funcionan bien..."}),200

# Ruta para crear una nueva Terminal
@terminal_bp.route('/terminal_bp', methods=['POST'])
@jwt_required()
def create_terminal():
    try:
        data = request.json
        responsible_id = data.get('responsible_id')
        address = data.get('address')

        if not responsible_id or not address:
            return jsonify({"error": "Los campos 'responsible_id' y 'address' son obligatorios."}), 400

        new_terminal = Terminal(
            responsible_id=responsible_id,
            address=address
        )

        db.session.add(new_terminal)
        db.session.commit()

        terminal_data = {
            "id": new_terminal.id,
            "responsible_id": new_terminal.responsible_id,
            "address": new_terminal.address,
            "created_at": new_terminal.created_at.isoformat() if new_terminal.created_at else None,
            "updated_at": new_terminal.updated_at.isoformat() if new_terminal.updated_at else None
        }

        return jsonify({
            "message": "Terminal creada con éxito.",
            "terminal": terminal_data
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al crear la Terminal: " + str(e)}), 500

# Ruta para eliminar una Terminal
@terminal_bp.route('/delete_terminal/<string:terminal_id>', methods=['DELETE'])
@jwt_required()
def delete_terminal(terminal_id):
    try:
        terminal = Terminal.query.get(terminal_id)
        if not terminal:
            return jsonify({"error": "Terminal no encontrada."}), 404

        db.session.delete(terminal)
        db.session.commit()

        return jsonify({"message": "Terminal eliminada con éxito."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al eliminar la Terminal: " + str(e)}), 500

# Ruta para obtener la lista de todas las Terminales
@terminal_bp.route('/terminals', methods=['GET'])
@jwt_required()
def list_terminals():
    try:
        terminals = Terminal.query.all()
        terminal_list = []
        for t in terminals:
            terminal_list.append({
                "id": t.id,
                "responsible_id": t.responsible_id,
                "address": t.address,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None
            })

        return jsonify({
            "terminals": terminal_list,
            "count": len(terminal_list)
        }), 200

    except Exception as e:
        return jsonify({"error": "Error al obtener las terminales: " + str(e)}), 500
