from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from pymongo import MongoClient
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura_para_sesiones'

# Conexión a MongoDB Atlas
MONGO_URI = "mongodb+srv://angeldhv12_db_user:qvCnSeFJM8FKn3R@cluster0.nxe45ut.mongodb.net/"
client = MongoClient(MONGO_URI)

# 1. Definición de Bases de Datos
users_db = client["USERS_DB"]
inscriptions_db = client["INSCRIPTIONS_DB"]
biometrics_db = client["BIOMETRICS_DB"]

# 2. Definición de Colecciones
alumnos_collection = users_db["alumnos"]
profesores_collection = users_db["profesores"]
registros_collection = inscriptions_db["registros"]
documentos_collection = biometrics_db["documentos"]
patrones_collection = biometrics_db["patrones"]

# --- RUTAS PÚBLICAS ---
@app.route("/")
def index():
    return render_template("index.html")

# API de Registro con Usuario y Contraseña Cifrada
@app.route("/api/registrar", methods=["POST"])
def registrar():
    data = request.json
    id_alumno = data.get("id_alumno")
    password_plana = data.get("password")
    nombre = data.get("nombre")
    apellido = data.get("apellido")
    carrera = data.get("carrera")
    taller = data.get("taller")

    fecha_hoy = datetime.now().strftime("%d/%m/%Y")

    try:
        # Cifrar contraseña por seguridad
        password_segura = generate_password_hash(password_plana)

        # 1. Guardar en USERS_DB -> alumnos
        alumnos_collection.update_one(
            {"_id": id_alumno},
            {
                "$set": {
                    "password": password_segura,
                    "nombre": nombre,
                    "apellido": apellido,
                    "carrera": carrera,
                    "rol": "Alumno"
                },
                "$addToSet": {
                    "talleres_activos": taller
                }
            },
            upsert=True
        )

        # 2. Guardar en INSCRIPTIONS_DB -> registros
        registros_collection.insert_one({
            "id_alumno": id_alumno,
            "taller": taller,
            "fecha_inscripcion": fecha_hoy,
            "estado": "activo"
        })

        return jsonify({"status": "ok", "message": "Alumno registrado con éxito."}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- SISTEMA DE LOGIN ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario_id = request.form.get("usuario")
        password_plana = request.form.get("password")

        # Validar Administrador General de prueba
        if usuario_id == "admin" and password_plana == "admin123":
            session["user"] = "Administrador"
            session["rol"] = "Administrador"
            return redirect(url_for("admin_dashboard"))

        # Buscar en Alumnos
        alumno = alumnos_collection.find_one({"_id": usuario_id})
        if alumno and check_password_hash(alumno["password"], password_plana):
            session["user"] = usuario_id
            session["rol"] = "Alumno"
            return redirect(url_for("alumno_dashboard"))

        # Buscar en Profesores
        profesor = profesores_collection.find_one({"_id": usuario_id})
        if profesor and check_password_hash(profesor["password"], password_plana):
            session["user"] = usuario_id
            session["rol"] = "Profesor"
            return redirect(url_for("profesor_dashboard"))

        return render_template("login.html", error="Usuario o contraseña incorrectos")

    return render_template("login.html")

# --- VISTAS PROTEGIDAS POR ROL ---
@app.route("/admin")
def admin_dashboard():
    if session.get("rol") != "Administrador":
        return redirect(url_for("login"))

    lista_alumnos = list(alumnos_collection.find())
    lista_registros = list(registros_collection.find())
    return render_template("admin_dashboard.html", alumnos=lista_alumnos, registros=lista_registros)

@app.route("/profesor")
def profesor_dashboard():
    if session.get("rol") != "Profesor":
        return redirect(url_for("login"))
    return render_template("profesor_dashboard.html")

@app.route("/alumno")
def alumno_dashboard():
    if session.get("rol") != "Alumno":
        return redirect(url_for("login"))

    user_id = session.get("user")
    datos_alumno = alumnos_collection.find_one({"_id": user_id})
    return render_template("alumno_dashboard.html", alumno=datos_alumno)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
