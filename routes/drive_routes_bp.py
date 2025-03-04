import os
import json
import tempfile
import threading
from flask import Blueprint, request, jsonify
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# Crear el blueprint para la ruta de Google Drive
drive_routes_bp = Blueprint('drive_routes_bp', __name__)

# Obtener los datos del .env
GOOGLE_DRIVE_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
service_account_info_str = os.getenv('GOOGLE_SERVICE_ACCOUNT_INFO')
if not service_account_info_str:
    raise Exception("La variable de entorno GOOGLE_SERVICE_ACCOUNT_INFO no está definida.")
service_account_info = json.loads(service_account_info_str)

SCOPES = ['https://www.googleapis.com/auth/drive.file']

# Crear el objeto de credenciales desde el dict obtenido del .env
credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=SCOPES)

def delayed_remove(path, delay=2):
    """
    Intenta eliminar el archivo después de 'delay' segundos.
    """
    def remove_file():
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"Archivo temporal {path} eliminado exitosamente.")
        except Exception as e:
            print(f"Error al eliminar archivo temporal en eliminación diferida: {e}")
    timer = threading.Timer(delay, remove_file)
    timer.start()

@drive_routes_bp.route('/upload-image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Crear un archivo temporal usando tempfile
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1])
        temp_file_name = temp_file.name
        file.save(temp_file_name)
        temp_file.close()
    except Exception as e:
        return jsonify({'error': f'Error creando archivo temporal: {str(e)}'}), 500

    try:
        drive_service = build('drive', 'v3', credentials=credentials)

        file_metadata = {
            'name': file.filename,
            'parents': [GOOGLE_DRIVE_FOLDER_ID]
        }
        media = MediaFileUpload(temp_file_name, mimetype=file.mimetype)

        uploaded_file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()

        file_id = uploaded_file.get('id')

        drive_service.permissions().create(
            fileId=file_id,
            body={
                'role': 'reader',
                'type': 'anyone'
            }
        ).execute()

        file_url = f"https://drive.google.com/uc?id={file_id}"

        # Eliminar el archivo temporal de forma diferida
        delayed_remove(temp_file_name, delay=2)

        return jsonify({'url': file_url})
    except Exception as e:
        delayed_remove(temp_file_name, delay=2)
        return jsonify({'error': str(e)}), 500
