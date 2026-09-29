from flask import Flask, request
app = Flask(__name__)

@app.post("/key")
def key():
    print("Received:", request.form.to_dict())
    return "ok"

app.run(host="0.0.0.0", port=5000)