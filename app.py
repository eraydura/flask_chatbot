from flask import Flask, render_template,request,jsonify

from chat import get_response
from flask_cors import CORS
import os 
os.system('python3 train.py')

app=Flask(__name__)

CORS(app)

# CORS Headers 
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,true')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.get("/")

def index_get():
    return render_template("base.html")

@app.post("/predict")
def predict():
    text = request.get_json().get("message")
    response= get_response(text)
    message={"answer": response}
    return jsonify(message)

if __name__ =="__main__":
    app.run(debug=True)
