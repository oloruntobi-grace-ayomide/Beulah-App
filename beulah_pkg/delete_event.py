# import logging
from datetime import datetime
from flask import Flask
import pytz
from beulah_pkg import app
from beulah_pkg.models import db, Event

# Set up logging
# logging.basicConfig(filename="event_cleanup.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Function to delete expired events
def delete_expired_events():
    with app.app_context():
        now_utc = datetime.now(pytz.UTC)  # Get current UTC time
        expired_events = []

        for event in Event.query.all():
            event_datetime = datetime.combine(event.event_date, event.event_time)
            if event_datetime < now_utc.replace(tzinfo=None):
                expired_events.append(event)
        
        if expired_events:
            for event in expired_events:
                db.session.delete(event)
            db.session.commit()


if __name__ == "__main__":
    delete_expired_events() 
    