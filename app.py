import os # para saber la ruta absoluta de la db si no la encontramos
from flask_bcrypt import Bcrypt  # para encriptar y comparar
from flask import Flask, request, jsonify # Para endpoints
from flask_sqlalchemy import SQLAlchemy  # Para rutas
from flask_jwt_extended import  JWTManager
from routes.admin_bp import admin_bp                       # Acá importamos rutas admin
from routes.public_bp import public_bp                     # Acá importamos rutas public
from routes.costumer_bp import customer_bp
from routes.clasifica_comentarios_individuales_bp import clasifica_comentarios_individuales_bp
from routes.terminal_bp import terminal_bp
from routes.transactions_bp import transactions_bp
from database import db                             # Acá importamos la base de datos inicializada
from flask_cors import CORS                         # Permisos de consumo
from extensions import init_extensions              # Necesario para que funcione el executor en varios archivos en simultaneo
from models import User, Terminal, Customer                           # Importamos el modelo para TodosLosReportes
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

# Inicializa los extensiones
init_extensions(app)

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True,allow_headers=["Content-Type", "Authorization"])

# ENCRIPTACION JWT y BCRYPT-------

app.config["JWT_SECRET_KEY"] = "valor-variable"  # clave secreta para firmar los tokens.( y a futuro va en un archivo .env)
jwt = JWTManager(app)  # isntanciamos jwt de JWTManager utilizando app para tener las herramientas de encriptacion.
bcrypt = Bcrypt(app)   # para encriptar password


# REGISTRAR BLUEPRINTS ( POSIBILIDAD DE UTILIZAR EL ENTORNO DE LA app EN OTROS ARCHIVOS Y GENERAR RUTAS EN LOS MISMOS )


app.register_blueprint(admin_bp)  # poder registrarlo como un blueprint ( parte del app )
                                                       # y si queremos podemos darle toda un path base como en el ejemplo '/admin'

app.register_blueprint(public_bp, url_prefix='/public')  # blueprint public_bp


app.register_blueprint(clasifica_comentarios_individuales_bp, url_prefix='/') # contiene ejemplos de executor y openai

app.register_blueprint(customer_bp, url_prefix='/')

app.register_blueprint(terminal_bp, url_prefix='/')

app.register_blueprint(transactions_bp, url_prefix='/')


# DATABASE---------------
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'mydatabase.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'


print(f"Ruta de la base de datos: {db_path}")


if not os.path.exists(os.path.dirname(db_path)): # Nos aseguramos que se cree carpeta instance automatico para poder tener mydatabase.db dentro.
    os.makedirs(os.path.dirname(db_path))



def cargar_datos_iniciales():
    # 1. Si no hay usuarios, crear el usuario responsable, la terminal y un usuario asociado a ella
    if User.query.count() == 0:
        # Crear el usuario responsable (sin terminal asignada)
        responsable_email = os.getenv('RESPONSABLE_EMAIL', 'responsable@example.com')
        responsable_name = os.getenv('RESPONSABLE_NAME', 'Responsable')
        responsable_password = os.getenv('RESPONSABLE_PASSWORD', '12345678')
        responsable_curp = os.getenv('RESPONSABLE_CURP', 'RESPONSABLECURP')
        responsable_admin = os.getenv('RESPONSABLE_ADMIN', 'True') == 'True'

        password_hash = bcrypt.generate_password_hash(responsable_password).decode('utf-8')
        responsable = User(
            email=responsable_email,
            name=responsable_name,
            password_hash=password_hash,
            curp=responsable_curp,
            admin=responsable_admin,
            terminal_id=None  # Aún no tiene terminal asignada
        )
        db.session.add(responsable)
        db.session.commit()  # Commit para obtener el id del usuario

        # Crear una Terminal usando el id del usuario responsable
        terminal_address = os.getenv('TERMINAL_ADDRESS', 'Dirección de Terminal por defecto')
        nueva_terminal = Terminal(
            responsible_id=responsable.id,
            address=terminal_address
        )
        db.session.add(nueva_terminal)
        db.session.commit()  # Commit para obtener el id de la terminal

        # Crear un usuario asociado a la terminal recién creada
        usuario_email = os.getenv('TERMINAL_USER_EMAIL', 'terminaluser@example.com')
        usuario_name = os.getenv('TERMINAL_USER_NAME', 'Usuario Terminal')
        usuario_password = os.getenv('TERMINAL_USER_PASSWORD', '12345678')
        usuario_curp = os.getenv('TERMINAL_USER_CURP', 'TERMINALUSERCURP')
        usuario_admin = os.getenv('TERMINAL_USER_ADMIN', 'False') == 'True'

        password_hash_terminal = bcrypt.generate_password_hash(usuario_password).decode('utf-8')
        usuario_terminal = User(
            email=usuario_email,
            name=usuario_name,
            password_hash=password_hash_terminal,
            curp=usuario_curp,
            admin=usuario_admin,
            terminal_id=nueva_terminal.id
        )
        db.session.add(usuario_terminal)
        db.session.commit()

        print("Datos iniciales cargados: Usuario responsable, Terminal y usuario asociado a la terminal creados.")

    # 2. Crear un Customer si no existe ninguno
    if Customer.query.count() == 0:
        customer_name = os.getenv('CUSTOMER_NAME', 'Cliente Ejemplo')
        customer_email = os.getenv('CUSTOMER_EMAIL', 'cliente@test.com')
        # El curp del customer debe ser SGSO750909HDFNNS05 sí o sí
        customer_curp = os.getenv('CUSTOMER_CURP', 'SGSO750909HDFNNS05')

        nuevo_customer = Customer(
            name=customer_name,
            email=customer_email,
            curp=customer_curp
        )
        db.session.add(nuevo_customer)
        db.session.commit()

        print("Customer inicial cargado correctamente.")

with app.app_context():
    db.init_app(app)
    db.create_all() # Nos aseguramos que este corriendo en el contexto del proyecto.
    cargar_datos_iniciales()
# -----------------------

# AL FINAL ( detecta que encendimos el servidor desde terminal y nos da detalles de los errores )
if __name__ == '__main__':
    app.run()

# EJECUTO CON : Si es la primera vez en tu pc crea el entorno virtual e instala dependencias:

#                 python -m venv myenv
#                 pip install -r requirements.txt

#               Lo siguiente siempre para activar el entorno e iniciar el servidor:

#                 myenv\Scripts\activate       
#                 waitress-serve --port=5000 app:app