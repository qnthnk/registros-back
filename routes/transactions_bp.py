from flask import Blueprint, send_file, make_response, request, jsonify, render_template, current_app, Response # Blueprint para modularizar y relacionar con app
from flask_bcrypt import Bcrypt                                  # Bcrypt para encriptación
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity   # Jwt para tokens
from models import Customer, Transaction, User                   # importar tabla "Customer" de models
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



transactions_bp = Blueprint('transactions_bp', __name__)     # instanciar admin_bp desde clase Blueprint para crear las rutas.

# Inicializamos herramientas de encriptado y access token ------------------------:

bcrypt = Bcrypt()
jwt = JWTManager()

# Sistema de key base pre rutas ------------------------:

API_KEY = os.getenv('API_KEY')

def check_api_key(api_key):
    return api_key == API_KEY

@transactions_bp.before_request
def authorize():
    if request.method == 'OPTIONS':
        return
    # En la lista de este if agregamos las rutas que no querramos restringir si no tienen el API_KEY embutido en Authorization en HEADERS.
    if request.path in ['/get_transactions','/test_transactions_bp','/generate_transaction']:
        return
    api_key = request.headers.get('Authorization')
    if not api_key or not check_api_key(api_key):
        return jsonify({'message': 'Unauthorized'}), 401
    
# Ruta TEST------------------------------------------------
@transactions_bp.route('/test_transactions_bp', methods=['GET'])
def test():
    return jsonify({'message': 'test bien sucedido','status':"Si lees esto, rutas de transactions funcionan bien..."}),200


@transactions_bp.route('/pre_transaction_check', methods=['POST'])
def pre_transaction_check():
    try:
        data = request.json
        
        # Validamos que venga el curp del Customer
        customer_curp = data.get('curp')
        if not customer_curp:
            return jsonify({"error": "El campo 'curp' es obligatorio."}), 400
        
        # Validamos que venga el id del User
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({"error": "El campo 'user_id' es obligatorio."}), 400

        # Buscamos el Customer usando el curp
        customer = Customer.query.filter_by(curp=customer_curp).first()
        if not customer:
            return jsonify({"error": "No existe un Customer con ese curp. Venta no permitida."}), 404

        # Buscamos el User usando el id
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({"error": "No existe un User con ese id. Venta no permitida."}), 404

        # Generamos token usando solo el id del User como identidad
        expires = timedelta(minutes=60)
        token = create_access_token(identity=customer.id, expires_delta=expires)

        return jsonify({
            "ok": True,
            "message": "Permitido",
            "access_token": token
        }), 200

    except Exception as e:
        return jsonify({"error": "Error al procesar el registro: " + str(e)}), 500

# 2 - Generar transaccion nueva >
@transactions_bp.route('/generate_transaction', methods=['POST'])
@jwt_required()
def generate_transaction():
    try:
        data = request.get_json()
        # Che, asegurate que mandás todos los campos obligatorios
        required_fields = ['terminal_id', 'fuel_type_id', 'sales_person_id', 'quantity_liters', 'pay_amount']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"El campo '{field}' es obligatorio."}), 400

        # Tomamos el customer_id del token que mandamos en /check_customer
        customer_id = get_jwt_identity()

        # Creamos la nueva transaction, como si armáramos una jugada maestra
        new_transaction = Transaction(
            customer_id=customer_id,
            terminal_id=data['terminal_id'],
            fuel_type_id=data['fuel_type_id'],
            sales_person_id=data['sales_person_id'],
            quantity_liters=data['quantity_liters'],
            pay_amount=data['pay_amount']
        )

        db.session.add(new_transaction)
        db.session.commit()

        return jsonify({"ok": True, "message": "Transaction generada correctamente."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al generar la transaction: " + str(e)}), 500
    


@transactions_bp.route('/get_transactions', methods=['GET'])
def get_transactions():
    try:
        transactions = Transaction.query.all()
        transactions_data = []
        for transaction in transactions:
            transactions_data.append({
                "customer_id": transaction.customer_id,
                "terminal_id": transaction.terminal_id,
                "fuel_type_id": transaction.fuel_type_id,
                "sales_person_id": transaction.sales_person_id,
                "quantity_liters": transaction.quantity_liters,
                "pay_amount": transaction.pay_amount,
                "created_at": transaction.created_at.isoformat() if transaction.created_at else None
            })
        return jsonify({"ok": True, "transactions": transactions_data}), 200
    except Exception as e:
        return jsonify({"error": "Error al recuperar transactions: " + str(e)}), 500