# 🚀 Inicio Rápido - API de Usuarios

## ⚡ En 3 Pasos

### 1️⃣ Instalar Dependencias

```bash
pip install flask flask-cors
```

### 2️⃣ Ejecutar la API

```bash
python run_users_api.py
```

### 3️⃣ Probar

Abre tu navegador en: **http://localhost:5000**

O usa curl:

```bash
# Ver todos los usuarios
curl http://localhost:5000/api/users

# Ver solo nombres de usuarios
curl http://localhost:5000/api/users?format=simple

# Ver usuarios conectados
curl http://localhost:5000/api/users/logged

# Info del sistema
curl http://localhost:5000/api/system
```

---

## 📖 Documentación Completa

Para más información, consulta [API_USERS_GUIDE.md](API_USERS_GUIDE.md)

---

## 🛠️ Comandos Útiles

```bash
# Cambiar puerto
python run_users_api.py --port 8080

# Modo debug
python run_users_api.py --debug

# Solo localhost
python run_users_api.py --host 127.0.0.1
```

---

## 🌐 Endpoints Principales

| Endpoint | Descripción |
|----------|-------------|
| `GET /` | Info de la API |
| `GET /api/users` | Lista todos los usuarios |
| `GET /api/users/current` | Usuario actual |
| `GET /api/users/logged` | Usuarios conectados |
| `GET /api/users/<user>` | Info de un usuario |
| `GET /api/system` | Info del sistema |
| `GET /api/report` | Reporte completo |

---

**✨ ¡Eso es todo! La API está lista para usar.**
