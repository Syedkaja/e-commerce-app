import re
import sys
import uuid
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template, request

from pony.orm import commit, db_session, select
from pony.orm.core import TransactionIntegrityError

sys.path.insert(0, "..")

user_blueprint = Blueprint("user_blueprint", __name__)


@user_blueprint.route("/user/all", methods=["GET"])
@db_session
def get_all_users():
    to_return = []
    users = User.select()
    for user in users:
        to_return.append(
            user.to_dict(exclude=["password", "pwd_rst_code", "auth_token", "events"])
        )
    if not to_return:
        return jsonify({"success": False, "users": []})
    return jsonify({"success": True, "users": to_return})


@user_blueprint.route("/user/create", methods=["POST"])
@db_session
def create_user():
    req_json = request.get_json()
    if "username" not in req_json or "email" not in req_json or "role" not in req_json:
        return jsonify({"success": False, "msg": "One or more fields are missing"})
    if not re.match(r"[^@]+@[^@]+\.[^@]+", req_json["email"]):
        return jsonify({"success": False, "msg": "email id is not valid"})
    if "firstname" not in req_json or not req_json["firstname"]:
        return jsonify({"success": False, "msg": "One or more fields missing"})
    if "lastname" not in req_json or not req_json["lastname"]:
        return jsonify({"success": False, "msg": "One or more fields missing"})

    hashed_salted_default_password, msg = get_hashed_salted_default_password()
    if not hashed_salted_default_password:
        return jsonify({"success": False, "msg": msg})

    user = User.get(username=req_json["username"])
    if user:
        return jsonify({"success": False, "msg": "Username already exists"})

    user = User.get(email=req_json["email"])
    if user:
        return jsonify({"success": False, "msg": "Email already exists"})

    is_new_role = req_json["is_new_role"]
    if is_new_role:
        role_name = req_json["role"]
        feature_permissions = req_json["feature_permissions"]
        stack_permissions = req_json["stack_permissions"]
        try:
            created_role = Role(name=role_name)
            commit()
            for feature_permission in feature_permissions:
                created_role.feature_permissions.add(
                    FeaturePermission.get(id=feature_permission)
                )
            for stack_permission in stack_permissions:
                created_role.stack_permissions.add(Stack.get(id=stack_permission))
            commit()
            role_id = created_role.id
        except TransactionIntegrityError:
            return jsonify({"success": False, "msg": "Role name already exists"})
        except Exception as e:
            print(e)
            return jsonify({"success": False, "msg": "Server error. Please try again"})
    else:
        role_id = req_json["role"]["id"]

    user_dict = {
        "username": req_json["username"],
        "email": req_json["email"],
        "password": hashed_salted_default_password,
        "auth_token": generate_jwt(req_json["username"]),
        "role": role_id,
        "firstname": req_json["firstname"],
        "lastname": req_json["lastname"],
    }
    user = User(**user_dict)
    commit()

    try:
        app = current_app._get_current_object()
        sendmail = SendMail(app)
    except Exception as e:
        print(e)
        return jsonify({"success": False, "msg": "Unable to send mail"})
    process_spawn = Process(
        target=sendmail.send_mail,
        args=(
            "Welcome to Trolley Management System (TMS)",
            ("ZASTI Admin", "admin@zasti.ai"),
            [user.email],
            render_template(
                "user_created_mail_content.txt",
                name=user.firstname,
                role=user.role.name,
                username=user.username,
                password="Welcome1@",
            ),
            render_template(
                "user_created_mail_content.html",
                name=user.firstname,
                role=user.role.name,
                username=user.username,
                password="Welcome1@",
            ),
        ),
    )
    process_spawn.start()

    return jsonify({"success": True})


@user_blueprint.route("/user/<user_id>", methods=["GET"])
@db_session
def get_single_user(user_id):
    user = User[user_id]
    if not user:
        return jsonify({"success": False})
    return jsonify({"success": True, "user": user.dictionary()})


@user_blueprint.route("/user/<user_id>/update", methods=["POST"])
@db_session
def update_user(user_id):
    req_json = request.get_json()
    user = User[user_id]
    if not user:
        return jsonify({"success": False, "msg": "user does not exists"})

    user_dict = {}
    if "firstname" in req_json:
        user_dict["firstname"] = req_json["firstname"]
    if "lastname" in req_json:
        user_dict["lastname"] = req_json["lastname"]
    if "role" in req_json:
        is_new_role = req_json["is_new_role"]
        if is_new_role:
            role_name = req_json["role"]
            feature_permissions = req_json["feature_permissions"]
            stack_permissions = req_json["stack_permissions"]
            try:
                created_role = Role(name=role_name)
                commit()
                for feature_permission in feature_permissions:
                    created_role.feature_permissions.add(
                        FeaturePermission.get(id=feature_permission)
                    )
                for stack_permission in stack_permissions:
                    created_role.stack_permissions.add(Stack.get(id=stack_permission))
                commit()
                role_id = created_role.id
            except TransactionIntegrityError:
                return jsonify({"success": False, "msg": "Role name already exists"})
            except Exception as e:
                print(e)
                return jsonify(
                    {"success": False, "msg": "Server error. Please try again"}
                )
        else:
            role_id = req_json["role"]["id"]
        user_dict["role"] = Role[role_id]
    user_dict["updated_at"] = datetime.now(pytz.UTC)
    user.set(**user_dict)
    commit()
    return jsonify({"success": True, "user": user.dictionary()})


@user_blueprint.route("/user/<user_id>/delete", methods=["GET"])
@db_session
def delete_user(user_id):
    try:
        User[user_id].delete()
    except Exception as e:
        print(e)
        return jsonify({"success": False})
    return jsonify({"success": True, "msg": "user deleted"})


@user_blueprint.route("/login", methods=["POST"])
@db_session
def login():
    req_json = request.get_json()
    if not "username" in req_json or not req_json["username"]:
        return jsonify({"success": False, "msg": "username field is required"})
    if not "password" in req_json or not req_json["password"]:
        return jsonify({"success": False, "msg": "password field is required"})
    try:
        user = User.get(username=req_json["username"])

        hashed_salted_default_password, msg = get_hashed_salted_default_password()
        if not hashed_salted_default_password:
            return jsonify({"success": False, "msg": msg})

        if not user:
            return jsonify({"success": False, "msg": "User not found"})
        salted_password = add_salt_to_password(req_json["password"])
        if not sha256_crypt.verify(salted_password, user.password):
            return jsonify({"success": False, "msg": "Invalid password"})
        is_default_password = False
        if sha256_crypt.verify(salted_password, hashed_salted_default_password):
            is_default_password = True
        jwt_token = generate_jwt(req_json["username"])
        user.auth_token = jwt_token
        commit()
        user_dict = user.to_dict(
            exclude=["password", "pwd_rst_code", "role", "events"]
        )
        user_dict["role"] = user.role.to_dict()
        user_dict["role"]["feature_permissions"] = []
        for feature_permission in user.role.feature_permissions:
            user_dict["role"]["feature_permissions"].append(
                feature_permission.to_dict()
            )
        user_dict["role"]["stack_permissions"] = []
        for satck in user.role.stack_permissions:
            user_dict["role"]["stack_permissions"].append(satck.id)
    except Exception as e:
        print(e)
        return jsonify({"success": False, "msg": "Unknown error. Please try again."})
    return jsonify(
        {"success": True, "user": user_dict, "is_default_password": is_default_password}
    )


@user_blueprint.route("/logout/<user_id>", methods=["GET"])
@db_session
def logout(user_id):
    user = User[user_id]
    if not user:
        return jsonify({"success": False, "msg": "User does not exists"})
    user.auth_token = None
    commit()
    return jsonify({"success": True})


@user_blueprint.route("/user/subscribe", methods=["POST"])
@db_session
def subscribe_firebase_web():
    req_json = request.get_json()
    serverkey = Config.get(name="firebase_server_key").value
    firebase_web_subscribe_url = (
        "https://iid.googleapis.com/iid/v1/"
        + req_json["token"]
        + "/rel/topics/"
        + req_json["topic"]
    )
    headers = {"Content-Type": "application/json", "Authorization": "key=" + serverkey}
    try:
        r = requests.post(firebase_web_subscribe_url, headers=headers)
        print("Subscribing firebase", r.text)
    except Exception as e:
        print(e)
        return jsonify({"success": False})
    return jsonify({"success": True})


@user_blueprint.route("/password/forgot", methods=["POST"])
@db_session
def send_pwd_reset_code():
    req_json = request.get_json()
    if "email" not in req_json:
        return jsonify({"success": False, "msg": "email field is missing"})
    user = User.get(email=req_json["email"])
    if not user:
        return jsonify({"success": False, "msg": "email does not exists"})

    pwd_rst_code = uuid.uuid4().hex[:6].upper()

    user.pwd_rst_code = pwd_rst_code
    try:
        app = current_app._get_current_object()
        sendmail = SendMail(app)
    except Exception as e:
        print(e)
        return jsonify({"success": False, "msg": "Unable to send mail"})
    process_spawn = Process(
        target=sendmail.send_mail,
        args=(
            "TMS Password Reset Code",
            ("ZASTI Admin", "admin@zasti.ai"),
            [user.email],
            render_template(
                "rst_pwd_mail_content.txt",
                name=user.firstname,
                pwd_rst_code=pwd_rst_code,
            ),
            render_template(
                "rst_pwd_mail_content.html",
                name=user.firstname,
                pwd_rst_code=pwd_rst_code,
            ),
        ),
    )
    process_spawn.start()
    return jsonify({"success": True, "user": user.dictionary()})


@user_blueprint.route("/user/<user_id>/code/verify", methods=["POST"])
@db_session
def verify_pwd_rst_code(user_id):
    req_json = request.get_json()
    if "pwd_rst_code" not in req_json:
        return jsonify({"success": False, "msg": "pwd_rst_code field is missing"})
    user = User[user_id]
    if not user:
        return jsonify({"success": False, "msg": "user does not exists"})
    if req_json["pwd_rst_code"] != user.pwd_rst_code:
        return jsonify({"success": False, "msg": "entered code is incorrect"})
    user.pwd_rst_code = None
    return jsonify({"success": True, "user": user.dictionary()})


@user_blueprint.route("/user/<user_id>/password/change", methods=["POST"])
@db_session
def change_password(user_id):
    req_json = request.get_json()
    if "password" not in req_json:
        return jsonify({"success": False, "msg": "password field is missing"})

    try:
        user = User[user_id]
        if not user:
            return jsonify({"success": False, "msg": "user does not exists"})
        hashed_salted_default_password, msg = get_hashed_salted_default_password()
        if not hashed_salted_default_password:
            return jsonify({"success": False, "msg": msg})
        passed, msg = password_check(req_json["password"])
        if not passed:
            return jsonify({"success": False, "msg": msg})

        salted_password = add_salt_to_password(req_json["password"])

        if sha256_crypt.verify(salted_password, hashed_salted_default_password):
            return jsonify(
                {"success": False, "msg": "Please provide a strong password"}
            )
    except Exception as e:
        print(e)
        return jsonify({"success": False, "msg": "Error occured. Please try again."})

    salted_password = add_salt_to_password(req_json["password"])
    user.password = sha256_crypt.encrypt(salted_password)
    return jsonify({"success": True, "user": user.dictionary()})
