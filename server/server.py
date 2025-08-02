from flask import Flask, request

app = Flask(__name__)

@app.route("/log", methods=["POST"])
def log():
    data = request.get_json()
    print(f"📥 Log recibido: {data}")
    # Aquí podrías guardar en base de datos o archivo
    return {"status": "ok"}, 200

if __name__ == "__main__":
    app.run(port=5000)
