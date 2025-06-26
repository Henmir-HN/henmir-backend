import os
import mysql.connector
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS # Mantenemos esta importación, ya que Flask-CORS maneja otras partes de la negociación CORS como los preflight requests.
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import time
from datetime import datetime, timedelta
import jwt 
import logging # ¡NUEVO! Importamos la librería de logging

# --- CONFIGURACIÓN INICIAL ---

# ¡NUEVO! Configuramos el logging para que los mensajes aparezcan en los logs de Render
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Iniciando aplicación Flask Henmir Backend...")

load_dotenv() # Carga las variables de entorno del archivo .env local
app = Flask(__name__)

# Configuración de CORS
FRONTEND_URL = os.getenv('FRONTEND_URL') # Esta variable se define en Render.com

if FRONTEND_URL:
    # ¡NUEVO! Logueamos la URL que se está detectando para CORS
    logging.info(f"FRONTEND_URL detectada: {FRONTEND_URL}. Configurando CORS para esta URL.")
    # Inicializamos Flask-CORS con la URL específica. supports_credentials es importante para JWT.
    CORS(app, origins=[FRONTEND_URL], supports_credentials=True) 
else:
    # ¡NUEVO! Logueamos que no se detectó FRONTEND_URL
    logging.warning("FRONTEND_URL NO detectada en las variables de entorno. Permitiendo CORS para todas las origenes (MODO DESARROLLO).")
    # Para desarrollo local, permitimos todas las origenes.
    CORS(app, supports_credentials=True) 

bcrypt = Bcrypt(app)

# Configuración de la clave secreta para JWT
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') 
app.config['JWT_ALGORITHM'] = 'HS256' 

# Configuración para la API de Gemini (desde .env del backend)
app.config['GEMINI_API_KEY'] = os.getenv('GEMINI_API_KEY')

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': os.getenv('DB_PORT')
}
GSHEET_API_URL = os.getenv('GSHEET_API_URL')
GEMINI_API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def get_db_connection():
    """
    Establece una conexión con la base de datos MySQL.
    Los detalles de conexión se obtienen de las variables de entorno.
    """
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        logging.error(f"Error de conexión a la base de datos: {err}") # ¡NUEVO! Logueamos errores de DB
        return None

# --- DECORADOR PARA RUTAS PROTEGIDAS CON JWT ---
from functools import wraps

def token_required(f):
    """
    Decorador para verificar la validez de un JWT en las rutas protegidas.
    Busca el token en el encabezado 'Authorization' (Bearer Token).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            logging.warning("Acceso no autorizado: Token de autenticación requerido.") # ¡NUEVO!
            return jsonify({"error": "Token de autenticación es requerido!"}), 401 

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
        except jwt.ExpiredSignatureError:
            logging.warning("Acceso no autorizado: Token de autenticación ha expirado.") # ¡NUEVO!
            return jsonify({"error": "Token de autenticación ha expirado."}), 401
        except jwt.InvalidTokenError:
            logging.warning("Acceso no autorizado: Token de autenticación inválido.") # ¡NUEVO!
            return jsonify({"error": "Token de autenticación inválido."}), 401
        except Exception as e:
            logging.error(f"Error inesperado al decodificar token: {str(e)}") # ¡NUEVO!
            return jsonify({"error": f"Error inesperado al decodificar token: {str(e)}"}), 401

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
    
    # Obtener configuración del contenido web (misión, visión, imágenes hero, y AHORA contacto)
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
        logging.error("GSHEET_API_URL no configurada.") # ¡NUEVO!
        return jsonify({"error": "La conexión a la fuente de datos secundaria no está configurada."}), 500
    try:
        params = {'action': 'getProfileByIdentity', 'identity': identity_number}
        response = requests.get(GSHEET_API_URL, params=params, timeout=15)
        response.raise_for_status() 
        gsheet_data = response.json() 
        
        if gsheet_data.get('success'):
            return jsonify(gsheet_data.get('data'))
        else:
            logging.warning(f"Perfil de usuario no encontrado para identidad: {identity_number}. Error: {gsheet_data.get('error', 'Desconocido')}") # ¡NUEVO!
            return jsonify({"error": gsheet_data.get('error', 'Usuario no encontrado')}), 404
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al consultar Google Sheet API: {str(e)}") # ¡NUEVO!
        return jsonify({"error": f"No se pudo consultar la fuente de datos secundaria: {str(e)}"}), 503

@app.route('/login', methods=['POST'])
def login():
    """
    Maneja el inicio de sesión de los administradores y genera un JWT.
    """
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        logging.warning("Intento de login con credenciales incompletas.") # ¡NUEVO!
        return jsonify({"error": "Email y contraseña son requeridos"}), 400
    
    email = data['email']
    password = data['password']
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión con la base de datos"}), 500
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email, password_hash, role FROM users WHERE email = %s AND role = 'admin'", (email,))
    admin = cursor.fetchone()
    conn.close()
    
    if admin and bcrypt.check_password_hash(admin['password_hash'], password):
        payload = {
            'admin_id': admin['id'],  
            'email': admin['email'],
            'role': admin['role'],
            'exp': datetime.utcnow() + timedelta(minutes=60) 
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])
        logging.info(f"Login de administrador exitoso para: {email}") # ¡NUEVO!
        return jsonify({
            "message": "Login de administrador exitoso", 
            "admin": {"nombre": admin['nombre'], "email": admin['email']},
            "token": token 
        })
    else:
        logging.warning(f"Intento de login fallido para: {email}") # ¡NUEVO!
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
        cursor.execute("SELECT * FROM vacancies ORDER BY created_at DESC")
        results = cursor.fetchall()
        for item in results:
            if item.get('created_at') and isinstance(item.get('created_at'), datetime): item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            if item.get('updated_at') and isinstance(item.get('updated_at'), datetime): item['updated_at'] = item['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
        conn.close()
        return jsonify(results)

    if request.method == 'POST':
        @token_required
        def _create_vacancy():
            data = request.get_json()
            if not data or not data.get('puesto') or not data.get('ciudad'):
                conn.close()
                logging.warning("Intento de crear vacante con datos incompletos.") # ¡NUEVO!
                return jsonify({"error": "Puesto y ciudad son requeridos"}), 400
            
            vacancy_id = f"VAC-{int(time.time() * 1000)}"
            query = "INSERT INTO vacancies (vacancy_id, puesto, empresa, ciudad, descripcion, requisitos, salario, estado) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            values = (vacancy_id, data.get('puesto'), data.get('empresa', ''), data.get('ciudad'), data.get('descripcion', ''), data.get('requisitos', ''), data.get('salario', ''), 'activa')
            cursor.execute(query, values)
            conn.commit()
            conn.close()
            logging.info(f"Vacante creada con éxito: {vacancy_id}") # ¡NUEVO!
            return jsonify({"message": "Vacante creada con éxito", "vacancy_id": vacancy_id}), 201
        
        return _create_vacancy()

@app.route('/vacancies/<string:vacancy_id>', methods=['DELETE'])
@token_required 
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
        logging.info(f"Vacante eliminada: {vacancy_id}") # ¡NUEVO!
        return jsonify({"message": "Vacante eliminada"}), 200
    else:
        logging.warning(f"Intento de eliminar vacante no encontrada: {vacancy_id}") # ¡NUEVO!
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
        cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
        results = cursor.fetchall()
        for item in results:
            if item.get('created_at') and isinstance(item.get('created_at'), datetime): item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        conn.close()
        return jsonify(results)

    if request.method == 'POST':
        @token_required
        def _create_post():
            data = request.get_json()
            if not data or not data.get('titulo'):
                conn.close()
                logging.warning("Intento de crear post con datos incompletos.") # ¡NUEVO!
                return jsonify({"error": "El título es requerido"}), 400
            
            post_id = f"POST-{int(time.time() * 1000)}"
            query = "INSERT INTO posts (post_id, titulo, contenido, url_imagen) VALUES (%s, %s, %s, %s)"
            values = (post_id, data.get('titulo'), data.get('contenido', ''), data.get('url_imagen', ''))
            cursor.execute(query, values)
            conn.commit()
            conn.close()
            logging.info(f"Post creado con éxito: {post_id}") # ¡NUEVO!
            return jsonify({"message": "Post creado con éxito", "post_id": post_id}), 201
        
        return _create_post()

@app.route('/posts/<string:post_id>', methods=['DELETE'])
@token_required 
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
        logging.info(f"Post eliminado: {post_id}") # ¡NUEVO!
        return jsonify({"message": "Post eliminado"}), 200
    else:
        logging.warning(f"Intento de eliminar post no encontrado: {post_id}") # ¡NUEVO!
        return jsonify({"error": "Post no encontrado"}), 404

@app.route('/web-config', methods=['POST'])
@token_required 
def update_web_config():
    """
    Actualiza el contenido de la configuración web (misión, visión, imágenes hero, contacto).
    Protegida por JWT.
    """
    data = request.get_json()
    if not data or 'updates' not in data or not isinstance(data['updates'], list):
        logging.warning("Intento de actualizar web-config con formato de datos incorrecto.") # ¡NUEVO!
        return jsonify({"error": "Formato de datos incorrecto. Se esperaba una lista de 'updates'."}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor()
    
    try:
        for update in data['updates']:
            key = update.get('key')
            value = update.get('value')
            if key:
                query = "INSERT INTO web_config (config_key, config_value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE config_value = %s"
                cursor.execute(query, (key, value, value))
        
        conn.commit()
        conn.close()
        logging.info("Contenido web actualizado con éxito.") # ¡NUEVO!
        return jsonify({"message": "Contenido web actualizado con éxito."}), 200
    except mysql.connector.Error as err:
        logging.error(f"Error en la base de datos al actualizar web-config: {err}") # ¡NUEVO!
        conn.close()
        return jsonify({"error": f"Error en la base de datos: {err}"}), 500

@app.route('/chat/gemini', methods=['POST'])
def chat_with_gemini():
    """
    Proxy para la API de Google Gemini. Recibe el historial de chat del frontend,
    lo envía a Gemini usando la clave API del backend, y devuelve la respuesta.
    No requiere autenticación.
    """
    user_request_data = request.get_json()
    chat_contents = user_request_data.get('contents')

    if not chat_contents:
        logging.warning("Chatbot: No hay contenido de chat proporcionado.") # ¡NUEVO!
        return jsonify({"error": "No hay contenido de chat proporcionado."}), 400

    gemini_api_key = app.config.get('GEMINI_API_KEY')
    if not gemini_api_key:
        logging.error("Chatbot: La clave API de Gemini no está configurada en el servidor.") # ¡NUEVO!
        return jsonify({"error": "La clave API de Gemini no está configurada en el servidor (en las variables de entorno de Render)."}), 500

    try:
        gemini_payload = {
            "contents": chat_contents
        }
        
        gemini_headers = {
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            f"{GEMINI_API_BASE_URL}?key={gemini_api_key}", 
            json=gemini_payload,
            headers=gemini_headers,
            timeout=30 
        )
        response.raise_for_status() 

        gemini_response_data = response.json()
        logging.info("Chatbot: Respuesta de Gemini recibida con éxito.") # ¡NUEVO!
        return jsonify(gemini_response_data), 200

    except requests.exceptions.RequestException as e:
        logging.error(f"Chatbot: Error al llamar a la API de Gemini: {e}") # ¡NUEVO!
        return jsonify({"error": f"Error de comunicación con el asistente de IA: {str(e)}"}), 500
    except Exception as e:
        logging.error(f"Chatbot: Error inesperado en el proxy de Gemini: {e}") # ¡NUEVO!
        return jsonify({"error": "Ocurrió un error inesperado en el servidor al procesar el chat."}), 500

# ¡NUEVO! Este decorador se ejecuta DESPUÉS de cada solicitud
@app.after_request
def add_cors_headers(response):
    # Verificamos si FRONTEND_URL está definida en las variables de entorno de Render
    if FRONTEND_URL:
        # Esto asegura que la cabecera 'Access-Control-Allow-Origin' se establezca
        # con la URL exacta de tu frontend en GitHub Pages.
        response.headers['Access-Control-Allow-Origin'] = FRONTEND_URL
        logging.info(f"CORS: Cabecera 'Access-Control-Allow-Origin' establecida a: {FRONTEND_URL}")
    else:
        # En modo de desarrollo local (si FRONTEND_URL no está establecida), permitimos todas las origenes.
        response.headers['Access-Control-Allow-Origin'] = "*"
        logging.warning("CORS: FRONTEND_URL no está definida. Cabecera 'Access-Control-Allow-Origin' establecida a '*'.")

    # Configuramos los métodos HTTP permitidos
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    # Configuramos las cabeceras personalizadas que el frontend puede enviar (importante para 'Authorization')
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    # Esto es crucial si tu frontend envía cookies o tokens de autenticación
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

# --- PUNTO DE ENTRADA DE LA APLICACIÓN ---
if __name__ == '__main__':
    # Advertencias para desarrollo local si las claves no están definidas
    # En producción, estas variables se establecerán en Render.com
    if app.config['SECRET_KEY'] is None:
        logging.warning("ADVERTENCIA: SECRET_KEY no está configurada en .env. Esto NO es seguro para producción.")
    
    if app.config['GEMINI_API_KEY'] is None:
        logging.warning("ADVERTENCIA: GEMINI_API_KEY no está configurada en .env.")
        logging.warning("El chatbot de Gemini no funcionará correctamente sin ella en este entorno.")
    
    # Esta línea es para ejecutar en desarrollo local con `python app.py`.
    # En Render, Gunicorn ejecutará la aplicación usando el Procfile, que NO usa debug=True.
    app.run(port=5001)
