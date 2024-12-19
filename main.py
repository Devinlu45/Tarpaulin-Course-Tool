import os
from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
from werkzeug.utils import secure_filename
import io

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
PHOTO_BUCKET = 'restapi451'
app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

LODGINGS = "lodgings"

# Update the values of the following 3 variables
CLIENT_ID = 'VlT3Y6Jhb8tNH7L4DigniYrEjxuclzNo'
CLIENT_SECRET = 'W0UodJ4cwlZlVgDh0gRo72EAW2RnwucKlBbxiK7ELl-H-gEhbTtJO6nPUI0TOgEn'
DOMAIN = 'dev-c1yg28u8fiehmvh4.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience='https://dev-c1yg28u8fiehmvh4.us.auth0.com/api/v2/',
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users/login to use this API"    
        
# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token


@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if "username" not in content or "password" not in content:
        return jsonify({"Error": "The request body is invalid"} ), 400
    username = content["username"]
    password = content["password"]
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'audience': 'https://dev-c1yg28u8fiehmvh4.us.auth0.com/api/v2/'
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    response = requests.post(url, json=body, headers=headers)
    if response.status_code == 200:
        token = response.json().get('access_token')
        return jsonify({"token": token}), 200
    return jsonify({"Error":  "Unauthorized"}), 401


@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        payload = verify_jwt(request) 
        sub = payload.get("sub")
        query_1 = client.query(kind= "users")
        query_1.add_filter("sub", "=", sub)
        user = list(query_1.fetch())
        if user[0].get("role") != "admin":
            return jsonify({"Error": "You don't have permission on this resource"} ), 403
    except Exception as e:
        return jsonify({"Error": "Unauthorized"}), 401
    query_for_user = client.query(kind="users")
    users = list(query_for_user.fetch())
    response = []
    for a in users:
        response.append({
            "id": a.key.id,
            "role": a["role"],
            "sub": a["sub"]
        })
    return jsonify(response), 200

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
    except Exception as e:
        return jsonify({"Error":  "Unauthorized"} ), 401
    a = client.get(client.key("users", user_id))
    if payload.get('role') != 'admin' and payload.get('sub') != a["sub"]:
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    response = {
        "id": a.key.id,
        "role": a["role"],
        "sub": a["sub"],
    }
    if a["role"] == "instructor":
        response["courses"] = [
            f"https://portfolio-project-443823.wl.r.appspot.com/courses/{id}" for id in a.get("courses", [])
        ]
    elif a["role"] == "student":
        response["courses"] = [
            f"https://portfolio-project-443823.wl.r.appspot.com/courses/{id}" for id in a.get("courses", [])
        ]
    return jsonify(response), 200

@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def update_user_avatar(user_id):
    if 'file' not in request.files:
        return jsonify({"Error": "The request body is invalid"}), 400

    file_obj = request.files['file']
    filename = secure_filename(file_obj .filename)
    if 'file' in request.form:
        file = request.form['file']
    user_key = client.key("users", user_id)
    user = client.get(user_key)
    if not user:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob = bucket.blob(filename.filename)
    file_obj .seek(0) 
    blob.upload_from_file(file_obj)
    return jsonify({"avatar_url": blob.public_url}), 200

@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_user_avatar(user_id):
    payload = verify_jwt(request)
    requester_sub = payload.get('sub')
    user = client.get(client.key("users", user_id))
    if requester_sub != user["sub"]:
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob_name = f"avatars/{user_id}.png"
    blob = bucket.blob(blob_name)
    if not blob.exists():
        return jsonify({"Error": "Not found"}), 404
    avatar_data = blob.download_as_bytes()
    return avatar_data, 200, {
        'Content-Type': 'image/png',
        'Content-Disposition': f'inline; filename="{user_id}.png"'
    }

@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_user_avatar(user_id):
    payload = verify_jwt(request)
    requester_sub = payload.get('sub')
    user = client.get(client.key("users", user_id))
    if requester_sub != user["sub"]:
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob_name = f"avatars/{user_id}.png"
    blob = bucket.blob(blob_name)
    if not blob.exists():
        return jsonify({"Error": "Not found"}), 404
    blob.delete()
    return '', 204

@app.route('/courses', methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
    except Exception as e:
        return jsonify({"Error": "Unauthorized"}), 401
    sub_1 = payload.get("sub")
    query_1 = client.query(kind="users")
    query_1.add_filter("sub", "=", sub_1)
    results = list(query_1.fetch())
    if results[0].get("role") != "admin":
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    content = request.get_json()
    required_fields = ["subject", "number", "title", "term", "instructor_id"]
    if any(field not in content for field in required_fields):
        return jsonify({"Error": "The request body is invalid"} ), 400
    instructor = client.get(client.key("users", content["instructor_id"]))
    if instructor.get("role") != "instructor":
        return jsonify({"Error": "The request body is invalid"} ), 400
    new_course = datastore.Entity(key=client.key("courses"))
    new_course.update({
        "subject": content["subject"],
        "number": content["number"],
        "title": content["title"],
        "term": content["term"],
        "instructor_id": content["instructor_id"],
    })
    client.put(new_course)
    response = {
        "id": new_course.key.id,
        "subject": new_course["subject"],
        "number": new_course["number"],
        "title": new_course["title"],
        "term": new_course["term"],
        "instructor_id": new_course["instructor_id"],
        "self": f"https://portfolio-project-443823.wl.r.appspot.com/courses/{new_course.key.id}"
    }
    return jsonify(response), 201

@app.route('/courses', methods=['GET'])
def get_all_courses():
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 3))
    query = client.query(kind="courses")
    query.order = ["subject"] 
    courses = list(query.fetch(offset=offset, limit=limit))
    response_courses = []
    for course in courses:
        response_courses.append({
            "id": course.key.id,
            "subject": course["subject"],
            "number": course["number"],
            "title": course["title"],
            "term": course["term"],
            "instructor_id": course["instructor_id"],
            "self": f"https://portfolio-project-443823.wl.r.appspot.com/courses/{course.key.id}"
        })
    next_link = None
    if len(courses) == limit:
        next_offset = offset + limit
        next_link = f"https://portfolio-project-443823.wl.r.appspot.com/courses?limit={limit}&offset={next_offset}"
    response = {
        "courses": response_courses
    }
    if next_link:
        response["next"] = next_link
    return jsonify(response), 200

@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course = client.get(client.key("courses", course_id))
    if not course:
        return jsonify({"Error": "Not found"}), 404
    response = {
        "id": course.key.id,
        "subject": course["subject"],
        "number": course["number"],
        "title": course["title"],
        "term": course["term"],
        "instructor_id": course["instructor_id"],
        "self": f"https://portfolio-project-443823.wl.r.appspot.com/courses/{course.key.id}"
    }
    return jsonify(response), 200

@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    payload = verify_jwt(request) 
    sub = payload.get("sub")
    query_1 = client.query(kind= "users")
    query_1.add_filter("sub", "=", sub)
    user = list(query_1.fetch())
    if user[0].get("role") != "admin":
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    course = client.get(client.key("courses", course_id))
    if not course:
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    content = request.get_json()
    if "instructor_id" in content:
        instructor_id = content["instructor_id"]
        instructor_key = client.key("users", instructor_id)
        instructor = client.get(instructor_key)

        if instructor.get("role") != "instructor":
            return jsonify({"Error": "The request body is invalid"} ), 400
        course["instructor_id"] = instructor_id
    if "subject" in content:
        course["subject"] = content["subject"]
    if "number" in content:
        course["number"] = content["number"]
    if "title" in content:
        course["title"] = content["title"]
    if "term" in content:
        course["term"] = content["term"]
    client.put(course)
    response = {
        "id": course.key.id,
        "subject": course["subject"],
        "number": course["number"],
        "title": course["title"],
        "term": course["term"],
        "instructor_id": course["instructor_id"],
        "self": f"https://portfolio-project-443823.wl.r.appspot.com/courses/{course.key.id}"
    }
    return jsonify(response), 200

@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    payload = verify_jwt(request) 
    sub = payload.get("sub")
    query_1 = client.query(kind= "users")
    query_1.add_filter("sub", "=", sub)
    user = list(query_1.fetch())
    if user[0].get("role") != "admin":
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    course = client.get(client.key("courses", course_id))
    if not course:
        return jsonify({"Error": "You don't have permission on this resource"} ), 403
    query = client.query(kind="enrollments")
    query.add_filter("course_id", "=", course_id)
    enrollments = list(query.fetch())
    for enrollment in enrollments:
        client.delete(enrollment.key)
    client.delete(client.key("courses", course_id))
    return '', 204

@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify({"Error": "Unauthorized"}), 401

    # Check if the course exists
    course = client.get(client.key("courses", course_id))
    if not course:
        return jsonify({"Error": "The course does not exist"}), 403

    # Verify user role
    user_sub = payload.get("sub")
    query = client.query(kind="users")
    query.add_filter("sub", "=", user_sub)
    user = list(query.fetch())
    if not user or user[0]["role"] not in ["admin", "instructor"]:
        return jsonify({"Error": "You do not have permission to update enrollments"}), 403
    if user[0]["role"] == "instructor" and course["instructor_id"] != user[0].key.id:
        return jsonify({"Error": "You do not have permission to update enrollments"}), 403

    # Parse and validate request body
    body = request.get_json()
    add = body.get("add", [])
    remove = body.get("remove", [])
    if set(add).intersection(set(remove)):
        return jsonify({"Error": "Enrollment data is invalid"}), 409

    # Validate student IDs
    all_students = [student.key.id for student in client.query(kind="users").add_filter("role", "=", "student").fetch()]
    if not set(add).issubset(all_students) or not set(remove).issubset(all_students):
        return jsonify({"Error": "Enrollment data is invalid"}), 409

    # Update enrollment
    for student_id in add:
        enrollment_key = client.key("enrollments", f"{course_id}_{student_id}")
        enrollment = client.get(enrollment_key)
        if not enrollment:
            new_enrollment = datastore.Entity(key=enrollment_key)
            new_enrollment.update({"course_id": course_id, "student_id": student_id})
            client.put(new_enrollment)

    for student_id in remove:
        enrollment_key = client.key("enrollments", f"{course_id}_{student_id}")
        enrollment = client.get(enrollment_key)
        if enrollment:
            client.delete(enrollment.key)

    return '', 200

@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify({"Error": "Unauthorized"}), 401

    # Check if the course exists
    course = client.get(client.key("courses", course_id))
    if not course:
        return jsonify({"Error": "The course does not exist"}), 403

    # Verify user role
    user_sub = payload.get("sub")
    query = client.query(kind="users")
    query.add_filter("sub", "=", user_sub)
    user = list(query.fetch())
    if not user or user[0]["role"] not in ["admin", "instructor"]:
        return jsonify({"Error": "You do not have permission to view enrollments"}), 403
    if user[0]["role"] == "instructor" and course["instructor_id"] != user[0].key.id:
        return jsonify({"Error": "You do not have permission to view enrollments"}), 403

    # Fetch enrolled students
    query = client.query(kind="enrollments")
    query.add_filter("course_id", "=", course_id)
    enrollments = list(query.fetch())
    student_ids = [enrollment["student_id"] for enrollment in enrollments]

    return jsonify(student_ids), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

