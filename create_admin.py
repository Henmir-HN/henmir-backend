from flask import Flask
from flask_bcrypt import Bcrypt

# Este script es solo para usar una vez y generar el hash.
app = Flask(__name__)
bcrypt = Bcrypt(app)

# --- CONFIGURA TU CONTRASEÑA AQUÍ ---
password_del_admin = 'admin123'  # <-- Elige una contraseña para tu admin

# Genera el hash
hashed_password = bcrypt.generate_password_hash(password_del_admin).decode('utf-8')

# Imprime el hash y la consulta SQL que debes ejecutar
print("\n--- COPIA Y PEGA ESTE HASH EN TU BASE DE DATOS ---\n")
print("HASH GENERADO:")
print(hashed_password)
print("\n--- EJECUTA ESTA INSTRUCCIÓN SQL EN DBEAVER ---\n")
sql_instruction = f"""
INSERT INTO users (user_id, nombre, email, password_hash, role) 
VALUES ('admin_henmir', 'Admin Principal', 'admin@henmir.com', '{hashed_password}', 'admin');
"""
print(sql_instruction)

