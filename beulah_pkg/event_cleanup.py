import os
import logging
from datetime import datetime
import pytz
from beulah_pkg.event_uploads import delete_event_flyer
from beulah_pkg.models import db, Event

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


logging.basicConfig(
    level=logging.INFO,
    filename=os.path.join(LOG_DIR, "event_cleanup.log"),
    format="%(asctime)s %(levelname)s: %(message)s"
)



def delete_expired_events(app):
    """Delete events whose date+time has passed, along with their flyer images."""
    with app.app_context():
        local_tz = pytz.timezone('Africa/Lagos')
        now_utc = datetime.now(pytz.UTC)
 
        upload_folder = os.path.join(app.root_path, 'static', 'uploads', 'events')
 
        expired_events = []
        for event in Event.query.all():
            event_datetime_naive = datetime.combine(event.event_date, event.event_time)
            event_datetime = local_tz.localize(event_datetime_naive)
            event_datetime_utc = event_datetime.astimezone(pytz.UTC)
 
            if event_datetime_utc < now_utc:
                expired_events.append(event)
                logging.info(f"Expired event found: {event.event_theme} on {event.event_date} {event.event_time}")
 
        if expired_events:
            for event in expired_events:
                delete_event_flyer(event.event_flyer_filename, upload_folder)
                db.session.delete(event)
                logging.info(f"Deleted event: {event.event_theme}")
            db.session.commit()
            logging.info(f"Deleted {len(expired_events)} expired events")
        else:
            logging.info("No expired events found")

# Only run directly when used as a script
if __name__ == "__main__":
    from beulah_pkg import app
    delete_expired_events(app)
