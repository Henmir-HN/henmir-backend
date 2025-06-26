import os
import mysql.connector
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import time
from datetime import datetime, timedelta # Se añade timedelta para la expiración del JWT
import jwt # Se añade la librería JWT

# --- CONFIGURACIÓN INICIAL ---
load_dotenv()
app = Flask(__name__)
CORS(app) 
bcrypt = Bcrypt(app)

# Configuración de la clave secreta para JWT
# ¡IMPORTANTE! Asegúrate de que esta variable esté definida en tu archivo .env
# Usa un valor largo y aleatorio, generado con python -c "import secrets; print(secrets.token_hex(32))"
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') 
app.config['JWT_ALGORITHM'] = 'HS256' # Algoritmo para firmar el JWT

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': os.getenv('DB_PORT')
}
GSHEET_API_URL = os.getenv('GSHEET_API_URL')

def get_db_connection():
    """
    Establece una conexión con la base de datos MySQL.
    Los detalles de conexión se obtienen de las variables de entorno.
    """
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        print(f"Error de conexión a la base de datos: {err}")
        return None

# --- DECORADOR PARA RUTAS PROTEGIDAS CON JWT (NUEVO) ---
from functools import wraps

def token_required(f):
    """
    Decorador para verificar la validez de un JWT en las rutas protegidas.
    Busca el token en el encabezado 'Authorization' (Bearer Token).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Obtener el token del encabezado de autorización
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({"error": "Token de autenticación es requerido!"}), 401 # Unauthorized

        try:
            # Decodificar el token usando la clave secreta
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
            # Aquí podrías opcionalmente cargar el usuario de la BD si necesitaras
            # información específica del admin para la lógica de la función protegida.
            # Por ejemplo: current_user = User.query.filter_by(id=data['admin_id']).first()
        except jwt.ExpiredSignatureError:
            # El token ha expirado
            return jsonify({"error": "Token de autenticación ha expirado."}), 401
        except jwt.InvalidTokenError:
            # El token es inválido (firma incorrecta, etc.)
            return jsonify({"error": "Token de autenticación inválido."}), 401
        except Exception as e:
            # Otros errores inesperados durante la decodificación
            return jsonify({"error": f"Error inesperado al decodificar token: {str(e)}"}), 401

        # Si el token es válido, ejecutar la función original de la ruta
        return f(*args, **kwargs)
    return decorated

# --- RUTAS DE LA API ---

@app.route('/')
def index():
    """Ruta de inicio para verificar que la API está funcionando."""
    return "API del Portal de Empleos Henmir funcionando correctamente."

@app.route('/public-data', methods=['GET'])
def get_public_data():
    """
    Obtiene los datos públicos del portal (vacantes activas, posts recientes, contenido web).
    No requiere autenticación.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    
    # Obtener vacantes activas
    cursor.execute("SELECT * FROM vacancies WHERE estado = 'activa' ORDER BY created_at DESC")
    vacantes = cursor.fetchall()
    
    # Obtener los 3 posts más recientes para la página de inicio
    cursor.execute("SELECT * FROM posts ORDER BY created_at DESC LIMIT 3")
    posts = cursor.fetchall()
    
    # Obtener configuración del contenido web (misión, visión, imágenes hero)
    cursor.execute("SELECT config_key, config_value FROM web_config")
    config_rows = cursor.fetchall()
    web_content = {row['config_key']: row['config_value'] for row in config_rows}
    
    conn.close()

    # Formatear fechas para que sean amigables con JavaScript
    for item in vacantes + posts:
        if item.get('created_at') and isinstance(item.get('created_at'), datetime):
            item['created_at'] = item['created_at'].strftime('%Y-%m-%d')
    
    return jsonify({
        "vacancies": vacantes,
        "posts": posts,
        "webContent": web_content
    })

@app.route('/profile/<string:identity_number>', methods=['GET'])
def get_user_profile(identity_number):
    """
    Obtiene el perfil de un candidato desde una fuente de datos secundaria (Google Sheet API).
    Según la especificación del usuario, no requiere autenticación en el backend.
    """
    if not GSHEET_API_URL:
        return jsonify({"error": "La conexión a la fuente de datos secundaria no está configurada."}), 500
    try:
        # Parámetros para la solicitud a la Google Sheet API
        params = {'action': 'getProfileByIdentity', 'identity': identity_number}
        # Realizar la solicitud GET a la API externa
        response = requests.get(GSHEET_API_URL, params=params, timeout=15)
        response.raise_for_status() # Lanza un error para códigos de estado HTTP 4xx/5xx
        gsheet_data = response.json() # Parsear la respuesta JSON
        
        if gsheet_data.get('success'):
            return jsonify(gsheet_data.get('data'))
        else:
            return jsonify({"error": gsheet_data.get('error', 'Usuario no encontrado')}), 404
    except requests.exceptions.RequestException as e:
        # Capturar errores de red o de la solicitud HTTP
        return jsonify({"error": f"No se pudo consultar la fuente de datos secundaria: {str(e)}"}), 503

@app.route('/login', methods=['POST'])
def login():
    """
    Maneja el inicio de sesión de los administradores y genera un JWT.
    """
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email y contraseña son requeridos"}), 400
    
    email = data['email']
    password = data['password']
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión con la base de datos"}), 500
    
    cursor = conn.cursor(dictionary=True)
    # Buscar el usuario administrador por email
    cursor.execute("SELECT id, nombre, email, password_hash, role FROM users WHERE email = %s AND role = 'admin'", (email,))
    admin = cursor.fetchone()
    conn.close()
    
    # Verificar contraseña usando bcrypt
    if admin and bcrypt.check_password_hash(admin['password_hash'], password):
        # Generar JWT (JSON Web Token) al inicio de sesión exitoso (NUEVO)
        # El token contendrá información básica y una fecha de expiración
        payload = {
            'admin_id': admin['id'],  # Usar el ID del admin desde la tabla 'users'
            'email': admin['email'],
            'role': admin['role'],
            'exp': datetime.utcnow() + timedelta(minutes=60) # Token válido por 60 minutos
        }
        # Codificar el payload en un token JWT usando la clave secreta
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

        return jsonify({
            "message": "Login de administrador exitoso", 
            "admin": {"nombre": admin['nombre'], "email": admin['email']},
            "token": token # Devolver el token al frontend para su uso en futuras peticiones
        })
    else:
        return jsonify({"error": "Credenciales de administrador inválidas"}), 401

@app.route('/vacancies', methods=['GET', 'POST'])
def manage_vacancies():
    """
    Gestiona las operaciones GET y POST para vacantes.
    El método POST está protegido por JWT.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    
    if request.method == 'GET':
        # Obtener todas las vacantes (accesible públicamente)
        cursor.execute("SELECT * FROM vacancies ORDER BY created_at DESC")
        results = cursor.fetchall()
        for item in results:
            if item.get('created_at') and isinstance(item.get('created_at'), datetime): item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            if item.get('updated_at') and isinstance(item.get('updated_at'), datetime): item['updated_at'] = item['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
        conn.close()
        return jsonify(results)

    if request.method == 'POST':
        # Proteger la operación POST con el decorador token_required (NUEVO)
        @token_required
        def _create_vacancy():
            data = request.get_json()
            if not data or not data.get('puesto') or not data.get('ciudad'):
                conn.close()
                return jsonify({"error": "Puesto y ciudad son requeridos"}), 400
            
            vacancy_id = f"VAC-{int(time.time() * 1000)}"
            query = "INSERT INTO vacancies (vacancy_id, puesto, empresa, ciudad, descripcion, requisitos, salario, estado) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            values = (vacancy_id, data.get('puesto'), data.get('empresa', ''), data.get('ciudad'), data.get('descripcion', ''), data.get('requisitos', ''), data.get('salario', ''), 'activa')
            cursor.execute(query, values)
            conn.commit()
            conn.close()
            return jsonify({"message": "Vacante creada con éxito", "vacancy_id": vacancy_id}), 201
        
        return _create_vacancy() # Llama a la función interna _create_vacancy, que está decorada

@app.route('/vacancies/<string:vacancy_id>', methods=['DELETE'])
@token_required # Protegemos esta ruta completa
def delete_vacancy(vacancy_id):
    """
    Elimina una vacante específica. Protegido por JWT.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vacancies WHERE vacancy_id = %s", (vacancy_id,))
    conn.commit()
    conn.close()
    if cursor.rowcount > 0:
        return jsonify({"message": "Vacante eliminada"}), 200
    else:
        return jsonify({"error": "Vacante no encontrada"}), 404

@app.route('/posts', methods=['GET', 'POST'])
def manage_posts():
    """
    Gestiona las operaciones GET y POST para posts.
    El método POST está protegido por JWT.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    
    if request.method == 'GET':
        # Obtener todos los posts (accesible públicamente)
        cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
        results = cursor.fetchall()
        for item in results:
            if item.get('created_at') and isinstance(item.get('created_at'), datetime): item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        conn.close()
        return jsonify(results)

    if request.method == 'POST':
        # Proteger la operación POST con el decorador token_required (NUEVO)
        @token_required
        def _create_post():
            data = request.get_json()
            if not data or not data.get('titulo'):
                conn.close()
                return jsonify({"error": "El título es requerido"}), 400
            
            post_id = f"POST-{int(time.time() * 1000)}"
            query = "INSERT INTO posts (post_id, titulo, contenido, url_imagen) VALUES (%s, %s, %s, %s)"
            values = (post_id, data.get('titulo'), data.get('contenido', ''), data.get('url_imagen', ''))
            cursor.execute(query, values)
            conn.commit()
            conn.close()
            return jsonify({"message": "Post creado con éxito", "post_id": post_id}), 201
        
        return _create_post() # Llama a la función interna _create_post, que está decorada

@app.route('/posts/<string:post_id>', methods=['DELETE'])
@token_required # Protegemos esta ruta completa
def delete_post(post_id):
    """
    Elimina un post específico. Protegido por JWT.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor()
    cursor.execute("DELETE FROM posts WHERE post_id = %s", (post_id,))
    conn.commit()
    conn.close()
    if cursor.rowcount > 0:
        return jsonify({"message": "Post eliminado"}), 200
    else:
        return jsonify({"error": "Post no encontrado"}), 404

# =======================================================
# --- RUTA PARA GESTIONAR CONTENIDO WEB (AHORA PROTEGIDA) ---
# =======================================================
@app.route('/web-config', methods=['POST'])
@token_required # Protegemos esta ruta completa
def update_web_config():
    """
    Actualiza el contenido de la configuración web (misión, visión, imágenes hero).
    Protegida por JWT.
    """
    data = request.get_json()
    if not data or 'updates' not in data or not isinstance(data['updates'], list):
        return jsonify({"error": "Formato de datos incorrecto. Se esperaba una lista de 'updates'."}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor()
    
    try:
        for update in data['updates']:
            key = update.get('key')
            value = update.get('value')
            if key:
                # Esta consulta SQL hace un "UPSERT": inserta si la clave no existe, o actualiza si ya existe.
                query = "INSERT INTO web_config (config_key, config_value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE config_value = %s"
                cursor.execute(query, (key, value, value))
        
        conn.commit()
        conn.close()
        return jsonify({"message": "Contenido web actualizado con éxito."}), 200
    except mysql.connector.Error as err:
        conn.close()
        return jsonify({"error": f"Error en la base de datos: {err}"}), 500


# --- PUNTO DE ENTRADA DE LA APLICACIÓN ---
if __name__ == '__main__':
    # Genera una clave secreta fuerte si no existe para desarrollo.
    # EN PRODUCCIÓN, SIEMPRE USA OS.URANDOM O UNA GENERACIÓN EXTERNA SEGURA.
    if app.config['SECRET_KEY'] is None:
        print("ADVERTENCIA: SECRET_KEY no está configurada en .env. Usando una clave temporal.")
        print("Esto NO es seguro para producción. Define SECRET_KEY en tu archivo .env")
        app.config['SECRET_KEY'] = os.urandom(24).hex() # Genera una clave aleatoria temporal
    
    app.run(debug=True, port=5001)
