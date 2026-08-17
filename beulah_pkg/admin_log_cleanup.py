import logging
import os
from datetime import datetime, timedelta

from beulah_pkg.models import AdminAuditLog, db


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.FileHandler(os.path.join(LOG_DIR, "admin_log_cleanup.log"))
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def delete_old_admin_logs(app):
    """Delete admin audit logs older than one month."""
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=30)
        deleted_count = AdminAuditLog.query.filter(
            AdminAuditLog.created_at < cutoff
        ).delete(synchronize_session=False)
        db.session.commit()
        logger.info("Deleted %s admin audit log(s) older than %s", deleted_count, cutoff.isoformat())
        return deleted_count


if __name__ == "__main__":
    from beulah_pkg import app
    delete_old_admin_logs(app)
