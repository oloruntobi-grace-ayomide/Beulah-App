import os
from flask import Flask
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_mail import Mail
from beulah_pkg.models import db


csrf=CSRFProtect()
migrate=Migrate()
mail=Mail()

# Load environment variables from the .env file
load_dotenv()

def create_app():
    app=Flask(__name__,instance_relative_config=True)
    app.config.from_pyfile('config.py', silent=True)

    env = os.getenv('FLASK_ENV', 'development')
    database_uri = os.getenv('SQLALCHEMY_DATABASE_URI')

    if env == 'production':
        # Override specific settings for production
        app.config.update(
            DEBUG=False,
            SQLALCHEMY_DATABASE_URI= database_uri
        )
    elif env == 'testing':
        # Override specific settings for testing
        app.config.update(
            TESTING=True,
            DEBUG=True,
            SQLALCHEMY_DATABASE_URI='mysql+mysqlconnector://root@127.0.0.1/beulahapp'
        )
    else:
        # Override specific settings for development (optional)
        app.config.update(
            DEBUG=True,
            SQLALCHEMY_DATABASE_URI='mysql+mysqlconnector://root@127.0.0.1/beulahapp'
        )



    csrf.init_app(app)
    migrate.init_app(app,db)
    db.init_app(app)
    mail.init_app(app)

    return app

app = create_app()

from beulah_pkg import user_route, admin_route, error_route, delete_event




