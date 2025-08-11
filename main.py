from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import uvicorn

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # required for session

FASTAPI_URL = "http://localhost:8000"

@app.route('/')
def home():
    print("Hello.......")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {
            "username": request.form['username'],
            "password": request.form['password']
        }
        try:
            response = requests.post(f"{FASTAPI_URL}/login", data=data)
            if response.status_code == 200:
                token_data = response.json()
                session['access_token'] = token_data['access_token']
                payload = decode_jwt(token_data['access_token'])
                session['username'] = payload['sub']
                session['role'] = payload['role']
                return redirect(url_for('projects'))
            else:
                flash("Invalid credentials. Try again or register.")
        except Exception as e:
            flash("Server error: " + str(e))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        payload = {
            "username": request.form['username'],
            "password": request.form['password'],
            "role": request.form['role']
        }
        try:
            response = requests.post(f"{FASTAPI_URL}/register", json=payload)
            if response.status_code == 200:
                flash("Registration successful. Please log in.")
                return redirect(url_for('login'))
            else:
                flash("User already exists or error occurred.")
        except Exception as e:
            flash("Server error: " + str(e))
    return render_template('register.html')

@app.route('/projects')
def projects():
    token = session.get('access_token')
    if not token:
        return redirect(url_for('login'))

    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{FASTAPI_URL}/projects", headers=headers)
        if response.status_code == 200:
            projects = response.json()
            return render_template('projects.html', projects=projects, role=session.get("role"))
        else:
            flash("Error fetching projects.")
    except Exception as e:
        flash("Server error: " + str(e))
    return redirect(url_for('login'))

@app.route('/create_project', methods=['POST'])
def create_project():
    if session.get("role") != "admin":
        flash("Unauthorized")
        return redirect(url_for("projects"))

    token = session.get('access_token')
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": request.form['name'],
        "description": request.form['description']
    }

    response = requests.post(f"{FASTAPI_URL}/projects", headers=headers, json=payload)
    if response.status_code == 200:
        flash("Project created successfully.")
    else:
        flash("Failed to create project.")
    return redirect(url_for('projects'))

@app.route('/delete_project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    if session.get("role") != "admin":
        flash("Unauthorized")
        return redirect(url_for("projects"))

    token = session.get('access_token')
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(f"{FASTAPI_URL}/projects/{project_id}", headers=headers)
    if response.status_code == 200:
        flash("Project deleted.")
    else:
        flash("Failed to delete project.")
    return redirect(url_for('projects'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Helper function to decode JWT (without verifying signature)
import base64
import json

def decode_jwt(token):
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())

if __name__ == "__main__":
    # uvicorn.run("main:app", host="localhost", port=8000, reload=True)
    app.run(debug=True)
