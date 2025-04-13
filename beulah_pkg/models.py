from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()





# Admin Table
class Admin(db.Model):
    __tablename__ = 'admin'
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_fullname = db.Column(db.String(40), nullable=False)
    admin_username = db.Column(db.String(12), nullable=False, unique=True)
    admin_password = db.Column(db.String(200), nullable=False)
    admin_role = db.Column(db.Enum('Admin'), nullable=False)
    admin_date_added = db.Column(db.DateTime, default=datetime.utcnow)
    admin_last_logged_in = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Admin {self.admin_fullname}>"
    





# Resources Table (Unified Reading and Audio Resources)
class Resource(db.Model):
    __tablename__ = 'resources'
    resource_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    resource_title = db.Column(db.String(255), nullable=False)
    resource_body = db.Column(db.Text, nullable=False)
    resource_type = db.Column(db.Enum('audio', 'text', 'slide'), nullable=False)
    resource_date = db.Column(db.DateTime, default=datetime.utcnow)
    resource_updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resource_is_deleted = db.Column(db.Boolean, default=False)

    # Relationships
    comments = db.relationship('Comment', backref='resource', lazy='dynamic')
    slide_img = db.relationship('Slide', backref='resource', uselist=False)

    def __repr__(self):
        return f"<Resource {self.resource_title}>"
    





# Comment Table
class Comment(db.Model):
    __tablename__ = 'comments'
    comment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.resource_id'), nullable=False, index=True)
    comment_token = db.Column(db.String(100), nullable=False,  index=True)
    comment_by = db.Column(db.String(50), nullable=False)
    comment_body = db.Column(db.String(850), nullable=False)
    comment_is_approve = db.Column(db.Boolean, default=True)
    comment_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Comment by {self.comment_by}>"






# Slide Table
class Slide(db.Model):
    __tablename__ = 'slides'
    slide_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.resource_id'), nullable=False)
    slide_image = db.Column(db.String(100), nullable=False)







# Prayer Request Table
class PrayerRequest(db.Model):
    __tablename__ = 'prayer_requests'
    pr_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pr_name = db.Column(db.String(50), nullable=False)
    pr_email = db.Column(db.String(100), nullable=True)
    pr_phone = db.Column(db.String(50), nullable=True)
    pr_message = db.Column(db.Text, nullable=False)
    pr_date = db.Column(db.DateTime, default=datetime.utcnow)
    pr_is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<PrayerRequest by {self.pr_name}>"
    






# Newsletter Subscriber Table
class NewsletterSubscriber(db.Model):
    __tablename__ = 'newsletter_subscribers'
    subscriber_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    subscriber_email = db.Column(db.String(100), nullable=False, unique=True)
    subscriber_status = db.Column(db.Enum('active', 'unsubscribed'), nullable=False, default='active')
    subscriber_date_joined = db.Column(db.DateTime,nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<NewsletterSubscriber {self.subscriber_email}>"
    




# Upcoming Events Table
class Event(db.Model):
    __tablename__ = 'events'
    event_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_theme = db.Column(db.String(100), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    event_time = db.Column(db.Time, nullable=False)
    event_venue = db.Column(db.String(100), nullable=True)
    event_description = db.Column(db.Text, nullable=True)
    event_date_added = db.Column(db.DateTime, default=datetime.utcnow)
    event_updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Event {self.event_theme} at {self.event_venue}>"
    





# Notification Table
class Notification(db.Model):
    __tablename__ = 'notifications'
    notification_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    notification_message = db.Column(db.Text, nullable=False)
    notification_for = db.Column(db.Enum('newsletter_subscription', 'contact_form', 'prayer_request'), nullable=False)
    notification_date = db.Column(db.DateTime, default=datetime.utcnow)
    notification_is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Notification from {self.notifier_name}>"
    


 