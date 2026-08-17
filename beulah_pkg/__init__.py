import os
import atexit
from datetime import timedelta
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_mail import Mail
from beulah_pkg.models import db


csrf=CSRFProtect()
migrate=Migrate()
mail=Mail()
limiter = Limiter(key_func=get_remote_address)
event_cleanup_scheduler = None

# Load environment variables from the .env file
load_dotenv()


def _should_start_scheduler(app):
    if app.config.get('TESTING'):
        return False
    if (
        os.getenv('ENABLE_EVENT_CLEANUP_SCHEDULER', 'true').lower() in ('0', 'false', 'no')
        and os.getenv('ENABLE_ADMIN_LOG_CLEANUP_SCHEDULER', 'true').lower() in ('0', 'false', 'no')
    ):
        return False
    if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return False
    return True


def _start_event_cleanup_scheduler(app):
    global event_cleanup_scheduler
    if event_cleanup_scheduler or not _should_start_scheduler(app):
        return

    from beulah_pkg.admin_log_cleanup import delete_old_admin_logs
    from beulah_pkg.event_cleanup import delete_expired_events

    event_cleanup_scheduler = BackgroundScheduler(timezone='Africa/Lagos')
    if os.getenv('ENABLE_EVENT_CLEANUP_SCHEDULER', 'true').lower() not in ('0', 'false', 'no'):
        event_cleanup_scheduler.add_job(
            func=lambda: delete_expired_events(app),
            trigger='interval',
            hours=1,
            id='delete_expired_events',
            replace_existing=True,
            max_instances=1,
        )
    if os.getenv('ENABLE_ADMIN_LOG_CLEANUP_SCHEDULER', 'true').lower() not in ('0', 'false', 'no'):
        event_cleanup_scheduler.add_job(
            func=lambda: delete_old_admin_logs(app),
            trigger='interval',
            hours=24,
            id='delete_old_admin_logs',
            replace_existing=True,
            max_instances=1,
        )
    event_cleanup_scheduler.start()
    atexit.register(lambda: event_cleanup_scheduler.shutdown(wait=False))

def create_app():
    app=Flask(__name__,instance_relative_config=True)
    app.config.from_pyfile('config.py', silent=True)

    env = os.getenv('FLASK_ENV', 'development')
    database_uri = os.getenv('SQLALCHEMY_DATABASE_URI')
    secret_key = os.getenv('SECRET_KEY')

    if env == 'production' and not secret_key:
        raise RuntimeError(
            'SECRET_KEY must be configured in production.'
        )

    if secret_key:
        app.config['SECRET_KEY'] = secret_key

    if env == 'production':
        app.config.update(
            DEBUG=False,
            SQLALCHEMY_DATABASE_URI=database_uri,

            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            SESSION_COOKIE_NAME='beulah_admin_session',

            PERMANENT_SESSION_LIFETIME=timedelta(
                hours=int(
                    os.getenv('ADMIN_SESSION_MAX_HOURS', '5')
                )
            ),
        )
    elif env == 'testing':
        # Override specific settings for testing
        app.config.update(
            TESTING=True,
            DEBUG=True,
            SQLALCHEMY_DATABASE_URI='mysql+pymysql://root@127.0.0.1/beulahappdb'
        )
    else:
        # Override specific settings for development (optional)
        app.config.update(
            DEBUG=True,
            SQLALCHEMY_DATABASE_URI='mysql+pymysql://root@127.0.0.1/beulahappdb'
        )

    app.config.setdefault('RATELIMIT_STORAGE_URI', os.getenv('RATELIMIT_STORAGE_URI', 'beulah-mysql://'))
    app.config.setdefault('RATELIMIT_STRATEGY', 'fixed-window')

    csrf.init_app(app)
    migrate.init_app(app,db)
    db.init_app(app)
    mail.init_app(app)

    from beulah_pkg.rate_limit_storage import ensure_rate_limit_table
    ensure_rate_limit_table(app)
    limiter.init_app(app)

    from beulah_pkg.admin_security import ensure_security_tables
    ensure_security_tables(app)

    _start_event_cleanup_scheduler(app)

    return app

app = create_app()
# app.config['PROPAGATE_EXCEPTIONS'] = True

@app.context_processor
def inject_turnstile_site_key():
    return {'turnstile_site_key': os.environ.get('TURNSTILE_SITE_KEY', '')}

@app.after_request
def apply_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.quilljs.com https://cdnjs.cloudflare.com https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdn.quilljs.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if os.getenv('FLASK_ENV') == 'production':
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response

from beulah_pkg import user_route, admin_route, error_route, counselling_route


