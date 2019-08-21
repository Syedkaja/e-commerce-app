import json

from flask import jsonify, request
from pony.orm import db_session

from blueprints.user import user_blueprint

from routes import app

CURR_PORT = None

                      
@app.route("/")
def root():
    return app.send_static_file("index.html")


# to support html5 pushstate
@app.errorhandler(404)
def serve_root(path):
    return app.send_static_file("index.html")


# TODO uncomment this

# User CRUD routes
app.register_blueprint(user_blueprint)



# setup route
# app.add_url_rule("/setup", view_func=setup, methods=["GET"])


# main function
def main(host="0.0.0.0", port=8000, debug=True):
    app.run(host=host, debug=debug, port=port, threaded=True)


if __name__ == "__main__":
    main()
