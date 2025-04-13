import os, secrets
import logging
from datetime import datetime
from flask import Flask,render_template,redirect,request,flash,url_for,session,jsonify
from werkzeug.utils import secure_filename
from functools import wraps
from werkzeug.security import check_password_hash,generate_password_hash
from flask_sqlalchemy import pagination
from sqlalchemy.sql import func
from sqlalchemy import extract
from bleach.sanitizer import Cleaner
from beulah_pkg import app
from beulah_pkg.models import db, NewsletterSubscriber,Resource,Admin, Comment, PrayerRequest, Event, Notification, Slide



# Initialize Cleaners
content_cleaner = Cleaner(
    tags=['b', 'i', 'u', 'em', 'strong', 'p', 'ul', 'ol', 'li', 'br', 'span', 'div'],
    attributes={},
    strip=True
)


title_cleaner = Cleaner(
    tags=[],  # No tags allowed in titles
    strip=True
)


@app.after_request
def after_request(response):
    response.headers['Cache-Control']='no-cache, no-store, must-revalidate'
    return response 


def admin_required(f):
    """
    Decorator that ensures an admin is logged in before accessing a route.
    If not, it clears the admin session or aborts with a 403 error depending on the issue,
    flashes a message, and redirects to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_id = session.get('admin_id')
        if not admin_id:  
            flash('Unauthorized access. Please log in.', 'danger')
            return redirect(url_for('home'))  # Redirect to home page
        
        admin_online = Admin.query.get(admin_id)
        if not admin_online:
            session.pop('admin_id', None)  # Clear invalid session
            flash('Invalid session. Please log in again.', 'warning')
            return redirect(url_for('admin_login'))  # Redirect to login page

        # Pass the admin instance to the route function for further use.
        return f(*args, admin_online=admin_online, **kwargs)

    return decorated_function


@app.template_global()
def get_selected_option(option_value):
     return 'selected' if request.args.get('sortOrder', 'desc') == option_value else ''


@app.template_global()
def get_selected_status(option_value, default_value='all'):
    return 'selected' if request.args.get('subscriberStatus', default_value) == option_value else ''


def format_event_date(event_date):
    # Determine the suffix for the day
    day = event_date.day
    if 10 <= day % 100 <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    
    # Format the date without the suffix, then manually insert it
    formatted_date = event_date.strftime(f'{day}{suffix} - %b - %Y')
    return formatted_date



@app.route('/admin/login/', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Validate inputs
        if not username or not password:
            return jsonify({'success': False, 'message': 'Both username and password are required.'}), 400

        # Check admin in the database
        admin = Admin.query.filter_by(admin_username=username).first()
        if admin:
            # Verify password
            if check_password_hash(admin.admin_password, password):
                session['admin_id'] = admin.admin_id
                return jsonify({
                    'success': True,
                    'message': 'Successfully logged in.',
                    'redirect_url': url_for('admin_dashboard')
                }), 200
            else:
                # logging.warning(f"Failed login attempt for username: {username}")
                return jsonify({'success': False, 'message': 'Invalid credentials. Please try again.'}), 401
        else:
            # logging.warning(f"Failed login attempt for non-existent username: {username}")
            return jsonify({'success': False, 'message': 'Invalid credentials. Please try again.'}), 401

    # If the request is a GET request, redirect if already logged in
    if session.get('admin_id'):
        return jsonify({
            'success': True,
            'message': 'Already logged in.',
            'redirect_url': url_for('admin_dashboard')
        }), 200

    return render_template('admin/login.html')



@app.route('/admin/logout/')
def log_out():
    if session.get('admin_id') != None:
        session.pop('admin_id')
        flash('You are now logged out','success')
    else:
        flash('You are not logged in', 'error')
    return redirect(url_for('home'))



@app.route('/admin/dashboard/', methods=['POST', 'GET'])
@admin_required 
def admin_dashboard(admin_online):
    subscribers = db.session.query(NewsletterSubscriber).count()
    upcoming_events = db.session.query(Event).count()
    prayer_requests = db.session.query(PrayerRequest).count()
    return render_template('admin/admin_template.html', subscribers=subscribers, upcoming_events=upcoming_events, prayer_requests=prayer_requests,admin_online=admin_online)


@app.route('/admin/calendar/')
@admin_required 
def admin_calendar(admin_online):
    return render_template('admin/admin_calendar.html', admin_online=admin_online)



# this function works for deleteing but audio, reading, and slide resources
@app.route('/admin/delete-resource/', methods=['POST'])
def delete_resource():
    id = request.json.get('id')  # Expecting JSON data

    if not id:
        return jsonify({'status': 'error', 'message': 'Resource ID is required.'}), 400

    resource = db.session.query(Resource).filter_by(resource_id=id).first()
    
    if not resource:
        return jsonify({'status': 'error', 'message': 'Resource not found.'}), 404
    
    try:
        resource.resource_is_deleted = True
        db.session.add(resource)
        db.session.commit()

        resource_type = "Reading" if resource.resource_type == 'text' else "Audio"
        return jsonify({'status': 'success', 'message': f'{resource_type} resource deleted successfully.'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Something went wrong, Please try again later'}), 500



@app.route('/admin/message-resources/')
@admin_required 
def admin_message_resources(admin_online):
    sort_order = request.args.get('sortOrder', 'desc')
    month = request.args.get('month', 'all')
    title_query = request.args.get('title', '').strip()
    page = request.args.get('page', 1, type=int)  # Get the page number, default is 1
    per_page = 25

    query = db.session.query(
    Resource,
    func.coalesce(func.count(Comment.comment_id), 0).label('comment_count')
    ).outerjoin(Comment, Resource.resource_id == Comment.resource_id).filter(
        Resource.resource_type == 'text',
        Resource.resource_is_deleted == False
    ).group_by(Resource.resource_id)
    
    # Filter by month
    if month != 'all':
        try:
            month_int = int(month)
            if 1 <= month_int <= 12:
                query = query.filter(extract('month', Resource.resource_updated_date) == month_int)
            else:
                raise ValueError("Invalid month value")
        except ValueError:
            return "Invalid month provided", 400

    # Sort based on the selected order
    if sort_order == 'asc':
        query = query.order_by(Resource.resource_updated_date.asc())
    else:
        query = query.order_by(Resource.resource_updated_date.desc())

    # Filter by title (if search query is provided)
    if title_query:
        query = query.filter(Resource.resource_title.ilike(f'%{title_query}%'))

    # Apply pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Fetch paginated results
    reading_resources = pagination.items
    base_url = url_for('admin_message_resources')
    return render_template('admin/admin_message_resources.html', reading_resources=reading_resources, pagination=pagination, base_url=base_url, admin_online=admin_online)



@app.route('/admin/audio-resources/')
@admin_required 
def admin_audio_resources(admin_online):
    sort_order = request.args.get('sortOrder', 'desc').lower()
    month = request.args.get('month', 'all')
    title_query = request.args.get('title', '').strip()
    page = request.args.get('page', 1, type=int)  # Get the page number, default is 1
    per_page = 25


    query = db.session.query(
    Resource,
    func.coalesce(func.count(Comment.comment_id), 0).label('comment_count')
    ).outerjoin(Comment, Resource.resource_id == Comment.resource_id).filter(
        Resource.resource_type == 'audio',
        Resource.resource_is_deleted == False
    ).group_by(Resource.resource_id)

    # Filter by month
    if month != 'all':
        try:
            month_int = int(month)
            if 1 <= month_int <= 12:
                query = query.filter(extract('month', Resource.resource_updated_date) == month_int)
            else:
                raise ValueError("Invalid month value")
        except ValueError:
            return "Invalid month provided", 400

    # Sort based on the selected order
    if sort_order == 'asc':
        query = query.order_by(Resource.resource_updated_date.asc())
    else:
        query = query.order_by(Resource.resource_updated_date.desc())

    # Filter by title (if search query is provided)
    if title_query:
        query = query.filter(Resource.resource_title.ilike(f'%{title_query}%'))

    # Apply pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Fetch paginated results
    audio_resources = pagination.items

    base_url = url_for('admin_audio_resources')
    return render_template('admin/admin_audio_resources.html',  audio_resources=audio_resources, pagination=pagination, base_url=base_url,admin_online=admin_online)



@app.route('/admin/slide-resources/')
@admin_required 
def admin_slide_resources(admin_online):
    slide_resources = db.session.query(
    Resource, Slide,
    func.coalesce(func.count(Comment.comment_id), 0).label('comment_count')
    ).outerjoin(Comment, Resource.resource_id == Comment.resource_id).join(Slide).filter(
        Resource.resource_type == 'slide',
        Resource.resource_is_deleted == False
    ).group_by(Resource.resource_id)

    return render_template('admin/admin_slide_resources.html', slide_resources=slide_resources,admin_online=admin_online)



@app.route('/admin/add-message-resource/', methods=['POST', 'GET'])
@admin_required 
def add_message_resource(admin_online):
    if request.method =='POST':    
        try:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            # Validate title and content
            if not title:
                return jsonify({'success': False, 'message': 'Title cannot be empty.'}), 400
            if not content:
                return jsonify({'success': False, 'message': 'Content cannot be empty.'}), 400
            
            # Sanitize inputs
            sanitized_title = title_cleaner.clean(title)
            sanitized_content = content_cleaner.clean(content)

            new_resource = Resource(
                # Update resource
                resource_title = str(sanitized_title), # Store sanitized title
                resource_body = str(sanitized_content),  # Store sanitized HTML content
                resource_type = 'text'
                )
            # Update resource
            db.session.add(new_resource)
            db.session.commit() 

            return jsonify({'success': True, 'redirect_url': url_for('admin_message_resources')}),200
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'something went wrong, Please try again later.'}),500
       
    return render_template('admin/add_message_resource.html',admin_online=admin_online)



@app.route('/admin/add-audio-resource/', methods=['POST', 'GET'])
@admin_required 
def add_audio_resource(admin_online):
    if request.method == 'POST':    
        try:
            # Retrieve data from the form
            title = request.form.get('title', '').strip()  # Audio title
            audio_url = request.form.get('audio_url', '').strip()  # Audio URL

            # Validate form inputs
            if not title:
                return jsonify({'success': False, 'message': 'Title cannot be empty.'}), 400
            if not audio_url or 'youtube.com/watch' not in audio_url:
               return jsonify({'success': False, 'message': 'Invalid or empty YouTube URL.'}), 400

            audio_id = audio_url.split('v=')[1].split('&')[0] if 'v=' in audio_url else None
            
            if not audio_id:
                return jsonify({'success': False, 'message': 'Invalid YouTube URL format.'}), 400
            sanitized_title = title_cleaner.clean(title)


            # Add new resource to the database
            new_resource = Resource(
                resource_title = str(sanitized_title), # Store sanitized title
                resource_body = audio_id,
                resource_type = 'audio'
            )
            db.session.add(new_resource)
            db.session.commit()

            # Return success response
            return jsonify({'success': True, 'redirect_url': url_for('admin_audio_resources')}), 200
        
        except Exception as e:
            # Rollback database changes in case of an error
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Something went wrong. Please try again later.'}), 500

    return render_template('admin/add_audio_resource.html',admin_online=admin_online)



@app.route('/admin/add-slide-resource/', methods=['POST', 'GET'])
@admin_required 
def add_slide_resource(admin_online):
    if request.method =='POST':    
        try:
            title = request.form.get('title', '').strip()
            image= request.files.get('image')
            content = request.form.get('content', '').strip()

            # Validate title and content
            if not title:
                return jsonify({'success': False, 'message': 'Title cannot be empty.'}), 400
            if not content:
                return jsonify({'success': False, 'message': 'Content cannot be empty.'}), 400
            if not image:
                return jsonify({'success': False, 'message': 'Image is required.'}), 400
            
            #Validate and save the image
            original_image = secure_filename(image.filename)
            allowed_extensions = {'jpg', 'png', 'webp'}
            ext = original_image.rsplit('.', 1)[1].lower() if '.' in original_image else ''
            if ext not in allowed_extensions:
                return jsonify({'success': False, 'message': 'Invalid image format. Allowed: jpg, png, gif.'}), 400

            unique_name = secrets.token_hex(5)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{unique_name}.{ext}')
            web_path = f'slide_images/{unique_name}.{ext}' 
            image.save(image_path)
            
            # Sanitize inputs
            sanitized_title = title_cleaner.clean(title)
            sanitized_content = content_cleaner.clean(content)

            new_resource = Resource(
                resource_title = str(sanitized_title), # Store sanitized title
                resource_body = str(sanitized_content),  # Store sanitized HTML content
                resource_type = 'slide'
                )
            # Update slide
            db.session.add(new_resource)
            db.session.flush()  
            slide = Slide(
                resource_id = new_resource.resource_id,
                slide_image = web_path
            )           
            # Update slide
            db.session.add(slide)
            db.session.commit() 

            return jsonify({'success': True, 'redirect_url': url_for('admin_slide_resources')}),200
        
        except Exception as e:
            db.session.rollback()
            print(e)
            return jsonify({'success': False, 'message': 'something went wrong, Please try again later.'}),500
       
    return render_template('admin/add_slide_resource.html',admin_online=admin_online)



@app.route('/admin/edit-message-resource/<int:id>/', methods=['GET', 'POST'])
@admin_required 
def edit_message_resource(id, admin_online):
    if id <= 0:
        flash('Invalid resource ID.', 'error')
        return redirect(url_for('admin_message_resources'))

    resource = db.session.query(Resource).filter(
        Resource.resource_id == id,
        Resource.resource_type == 'text',
        Resource.resource_is_deleted == False
    ).first()

    if not resource:
        flash('Resource not found', 'error')
        return redirect(url_for('admin_message_resources'))

    if request.method == 'POST':
        try:
            
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            # Validate title and content
            if not title:
                return jsonify({'success': False, 'message': 'Title cannot be empty.'}), 400
            if not content:
                return jsonify({'success': False, 'message': 'Content cannot be empty.'}), 400
            
            # Sanitize inputs
            sanitized_title = title_cleaner.clean(title)
            sanitized_content = content_cleaner.clean(content)

            # Update resource
            resource.resource_title = str(sanitized_title) # Store sanitized title
            resource.resource_body = str(sanitized_content)  # Store sanitized HTML content

            db.session.commit()
            return jsonify({'success': True, 'redirect_url': url_for('admin_message_resources')}),200
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'An unexpected error occurred. Please try again later.'}),500

    return render_template('admin/edit_message_resource.html', resource=resource, admin_online=admin_online)



@app.route('/admin/edit-audio-resource/<int:id>/', methods=['GET','POST'])
@admin_required
def edit_audio_resource(id, admin_online):
    if id <= 0:
        flash('Invalid resource ID.', 'error')
        return redirect(url_for('admin_audio_resources'))
    
    resource = db.session.query(Resource).filter(
        Resource.resource_id == id,
        Resource.resource_type == 'audio',
        Resource.resource_is_deleted == False
    ).first()

    if not resource:
        flash('Resource not found', 'error')
        return redirect(url_for('admin_audio_resources'))

    if request.method == 'POST':
        try:
            
            # Retrieve data from the form
            title = request.form.get('title', '').strip()  # Audio title
            audio_url = request.form.get('audio_url', '').strip()  # Audio URL

            # Validate form inputs
            if not title:
                return jsonify({'success': False, 'message': 'Title cannot be empty.'}), 400
            if not audio_url or 'youtube.com/watch' not in audio_url:
               return jsonify({'success': False, 'message': 'Invalid or empty YouTube URL.'}), 400

            audio_id = audio_url.split('v=')[1].split('&')[0] if 'v=' in audio_url else None

            if not audio_id:
                return jsonify({'success': False, 'message': 'Invalid YouTube URL format.'}), 400
            sanitized_title = title_cleaner.clean(title)

            # Update resource
            resource.resource_title = str(sanitized_title) 
            resource.resource_body = audio_id  

            db.session.commit()
            return jsonify({'success': True, 'redirect_url': url_for('admin_audio_resources')}),200
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'An unexpected error occurred. Please try again later.'}),500

    return render_template('admin/edit_audio_resource.html', resource=resource, admin_online=admin_online)



@app.route('/admin/edit-slide-resource/<int:id>/', methods=['POST', 'GET'])
@admin_required
def edit_slide_resource(id, admin_online):
    if id <= 0:
        flash('Invalid resource ID.', 'error')
        return redirect(url_for('admin_slide_resources'))

    resource = db.session.query(Resource).filter(
        Resource.resource_id == id,
        Resource.resource_type == 'slide',
        Resource.resource_is_deleted == False
    ).first()

    if not resource:
        flash('Resource not found', 'error')
        return redirect(url_for('admin_slide_resources'))
    
    if request.method =='POST':    
        try:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            # Validate title and content
            if not title:
                return jsonify({'success': False, 'message': 'Title cannot be empty.'}), 400
            if not content:
                return jsonify({'success': False, 'message': 'Content cannot be empty.'}), 400
            
            # Sanitize inputs
            sanitized_title = title_cleaner.clean(title)
            sanitized_content = content_cleaner.clean(content)

            resource.resource_title = str(sanitized_title) # Store sanitized title
            resource.resource_body = str(sanitized_content)  # Store sanitized HTML content

            # Update slide
            db.session.commit() 

            return jsonify({'success': True, 'redirect_url': url_for('admin_slide_resources')}),200
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'something went wrong, Please try again later.'}),500
       

    return render_template('admin/edit_slide_resource.html', resource=resource, admin_online=admin_online)




@app.route('/admin/admin-prayer-requests/')
@admin_required
def admin_prayer_requests(admin_online):

    sort_order = request.args.get('sortOrder', 'desc').lower()
    month = request.args.get('month', 'all')
    page = request.args.get('page', 1, type=int)  # Get the page number, default is 1
    per_page = 25


    query = db.session.query(PrayerRequest)

    # Filter by month
    if month != 'all':
        try:
            month_int = int(month)
            if 1 <= month_int <= 12:
                query = query.filter(extract('month', PrayerRequest.pr_date) == month_int)
            else:
                raise ValueError("Invalid month value")
        except ValueError:
            return "Invalid month provided", 400

    # Sort based on the selected order
    if sort_order == 'asc':
        query = query.order_by(PrayerRequest.pr_date.asc())
    else:
        query = query.order_by(PrayerRequest.pr_date.desc())


    # Apply pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Fetch paginated results
    prayer_requests = pagination.items
    base_url = url_for('admin_prayer_requests')

    return render_template('admin/admin_prayer_requests.html',prayer_requests=prayer_requests, pagination=pagination, base_url=base_url, admin_online=admin_online)



@app.route('/admin/delete-prayer-request/', methods=['POST'])
def delete_prayer_request():
    id = request.json.get('id')  # Expecting JSON data

    if not id:
        return jsonify({'status': 'error', 'message': 'Prayer Request ID is required.'}), 400

    prayer_request = db.session.query(PrayerRequest).filter_by(pr_id=id).first()
    
    if not prayer_request:
        return jsonify({'status': 'error', 'message': 'Prayer Request not found.'}), 404
    
    try:
        db.session.delete(prayer_request)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Prayer Request deleted successfully.'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Something went wrong, Please try again later'}), 500



@app.route('/admin/admin-upcoming-events/')
@admin_required
def admin_upcoming_events(admin_online):
    # Fetch  results
    events = db.session.query(Event).order_by(Event.event_updated_date.desc())
    for event in events:
        event.formated_date = format_event_date(event.event_date)
    return render_template('admin/admin_upcoming_events.html', events=events, admin_online=admin_online)



@app.route('/admin/add-new-event/', methods=['GET', 'POST'])
@admin_required
def add_new_event(admin_online):
    if request.method =='POST':    
        try:

            theme = request.form.get('theme', '').strip()
            event_date = request.form.get('event_date', '').strip()
            event_time = request.form.get('event_time', '').strip()
            event_venue = request.form.get('event_venue', '').strip() or None
            prayer = request.form.get('prayer', '').strip() or None

            # Validate inputs
            if not theme:
                return jsonify({'success': False, 'message': 'Theme cannot be empty.'}), 400
            if not event_date:
                return jsonify({'success': False, 'message': 'Event date cannot be empty.'}), 400
            if not event_time:
                return jsonify({'success': False, 'message': 'Event time cannot be empty.'}), 400
            
            try:
                event_date = datetime.strptime(event_date, '%Y-%m-%d').date()
                event_time = datetime.strptime(event_time, '%I:%M %p').time()
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid date or time format.'}), 400

            # Sanitize inputs
            sanitized_theme = title_cleaner.clean(theme)
            sanitized_venue = title_cleaner.clean(event_venue) if event_venue else None
            sanitized_prayer = title_cleaner.clean(prayer) if prayer else None

            new_event = Event(
                event_theme=sanitized_theme,
                event_date=event_date,
                event_time=event_time,
                event_venue=sanitized_venue,
                event_description=sanitized_prayer,
            )
            
            db.session.add(new_event)
            db.session.commit()

            return jsonify({'success': True, 'redirect_url': url_for('admin_upcoming_events')}),200
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'something went wrong, Please try again later.'}),500
        
    return render_template('admin/add_new_event.html', admin_online=admin_online)



@app.route('/admin/edit_event/<int:id>/', methods=['GET','POST'])
@admin_required
def edit_event(id, admin_online):
    if id <= 0:
        flash('Invalid Event ID.', 'error')
        return redirect(url_for('admin_upcoming_events'))
    
    event = db.session.query(Event).filter_by(event_id = id).first()

    if not event:
        flash('Event not found', 'error')
        return redirect(url_for(' admin_upcoming_events'))

    if request.method == 'POST':
        try:

            theme = request.form.get('theme', '').strip()
            event_date = request.form.get('event_date', '').strip()
            event_time = request.form.get('event_time', '').strip()
            event_venue = request.form.get('event_venue', '').strip() or None
            prayer = request.form.get('prayer', '').strip() or None

            # Validate inputs
            if not theme:
                return jsonify({'success': False, 'message': 'Theme cannot be empty.'}), 400
            if not event_date:
                return jsonify({'success': False, 'message': 'Event date cannot be empty.'}), 400
            if not event_time:
                return jsonify({'success': False, 'message': 'Event time cannot be empty.'}), 400
            
            try:
                event_date = datetime.strptime(event_date, '%Y-%m-%d').date()
                event_time = datetime.strptime(event_time, '%I:%M %p').time()
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid date or time format.'}), 400

            # Sanitize inputs
            sanitized_theme = title_cleaner.clean(theme)
            sanitized_venue = title_cleaner.clean(event_venue) if event_venue else None
            sanitized_prayer = title_cleaner.clean(prayer) if prayer else None

            event.event_theme = sanitized_theme
            event.event_date = event_date
            event.event_time = event_time
            event.event_venue =sanitized_venue
            event.event_description=sanitized_prayer
            
            db.session.commit()

            return jsonify({'success': True, 'redirect_url': url_for('admin_upcoming_events')}),200
        
        except Exception as e:
            db.session.rollback()
            print(e)
            return jsonify({'success': False, 'message': 'something went wrong, Please try again later.'}),500
        
    return render_template('admin/edit_event.html', event=event, admin_online=admin_online)



@app.route('/admin/delete-event/', methods=['POST'])
def delete_event():
    id = request.json.get('id')  # Expecting JSON data

    if not id:
        return jsonify({'status': 'error', 'message': 'Event ID is required.'}), 400

    event= db.session.query(Event).filter_by(event_id=id).first()
    
    if not event:
        return jsonify({'status': 'error', 'message': 'Event not found.'}), 404
    
    try:
        db.session.delete(event)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Event deleted successfully.'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Something went wrong, Please try again later'}), 500




@app.route('/admin/admin-comments/')
@admin_required
def admin_comments(admin_online):

    sort_order = request.args.get('sortOrder', 'desc').lower()
    month = request.args.get('month', 'all')
    page = request.args.get('page', 1, type=int)  # Get the page number, default is 1
    per_page = 25


    query = db.session.query(Comment, Resource).join(Resource).filter( Resource.resource_is_deleted == False)
    # Filter by month
    if month != 'all':
        try:
            month_int = int(month)
            if 1 <= month_int <= 12:
                query = query.filter(extract('month', Comment.comment_date) == month_int)
            else:
                raise ValueError("Invalid month value")
        except ValueError:
            return "Invalid month provided", 400

    # Sort based on the selected order
    if sort_order == 'asc':
        query = query.order_by(Comment.comment_date.asc())
    else:
        query = query.order_by(Comment.comment_date.desc())

    # Apply pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Fetch paginated results
    comments = pagination.items
    base_url = url_for('admin_comments')

    return render_template('admin/admin_comments.html',comments=comments, pagination=pagination, base_url=base_url, admin_online=admin_online)



@app.route('/admin/delete-comment/', methods=['POST'])
def admin_delete_comment():
    id = request.json.get('id')  # Expecting JSON data

    if not id:
        return jsonify({'status': 'error', 'message': 'Comment ID is required.'}), 400

    comment = db.session.query(Comment).filter_by(comment_id=id).first()
    
    if not comment:
        return jsonify({'status': 'error', 'message': 'Comment not found.'}), 404
    
    try:
        db.session.delete(comment)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Comment deleted successfully.'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Something went wrong, Please try again later'}), 500



@app.route('/admin/subscribers/')
@admin_required
def admin_subscribers(admin_online):
    sort_order = request.args.get('sortOrder', 'desc')
    subscriber_status = request.args.get('subscriberStatus', 'all')
    email_query = request.args.get('email', '').strip()
    page = request.args.get('page', 1, type=int) 
    per_page = 25

    query = db.session.query(NewsletterSubscriber)

    # Filtering by status
    if subscriber_status != 'all':
        query = query.filter_by(subscriber_status=subscriber_status)

    # Sorting based on the selected order
    if sort_order == 'asc':
        query = query.order_by(NewsletterSubscriber.subscriber_date_joined.asc())
    else:
        query = query.order_by(NewsletterSubscriber.subscriber_date_joined.desc())

    # Filtering by email (if search query is provided)
    if email_query:
        query = query.filter(NewsletterSubscriber.subscriber_email.ilike(f'%{email_query}%'))

     # Apply pagination
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Fetch paginated results
    subscribers = pagination.items
    base_url = url_for('admin_subscribers')
    return render_template('admin/admin_subscribers.html', base_url=base_url, subscribers=subscribers, pagination=pagination, admin_online=admin_online)



@app.route('/admin/subscribers-email/')
def subscribers_email():
    sort_order = request.args.get('sortOrder', 'desc')
    subscriber_status = request.args.get('subscriberStatus', 'all')
    page = request.args.get('page', 1, type=int)  # New line
    per_page = 25  # Adjust as needed

    query = db.session.query(NewsletterSubscriber.subscriber_email)

    if subscriber_status != 'all':
        query = query.filter_by(subscriber_status=subscriber_status)

    if sort_order == 'asc':
        query = query.order_by(NewsletterSubscriber.subscriber_date_joined.asc())
    else:
        query = query.order_by(NewsletterSubscriber.subscriber_date_joined.desc())

    # Apply pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    emails = pagination.items

    # Return just the emails (each is a tuple with one element)
    return jsonify([email[0] for email in emails])



@app.route('/admin/delete-subscriber/', methods=['POST'])
def delete_subscriber():
    id = request.json.get('id')  # Expecting JSON data

    if not id:
        return jsonify({'status': 'error', 'message': "Subscriber's ID is required."}), 400

    subscriber = db.session.query(NewsletterSubscriber).filter_by(subscriber_id=id).first()
    
    if not subscriber:
        return jsonify({'status': 'error', 'message': 'Subscriber not found.'}), 404
    
    try:
        db.session.delete(subscriber)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Subscriber deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500




@app.route('/admin/admin-notification/')
@admin_required
def admin_notifications(admin_online):

    page = request.args.get('page', 1, type=int)  # Get the page number, default is 1
    per_page = 20

    query = db.session.query(Notification).order_by(Notification.notification_date.desc())

    # Apply pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Fetch paginated results
    notifications = pagination.items
    base_url = url_for('admin_notifications')

    return render_template('admin/admin_notification.html',notifications = notifications, pagination=pagination, base_url=base_url, admin_online=admin_online)



@app.route('/admin/delete-notification/', methods=['POST'])
def delete_notification():
    id = request.json.get('id')  # Expecting JSON data
    notification = db.session.query(Notification).filter_by(notification_id=id).first()
    
    if not notification:
        return jsonify({'status': 'error', 'message': 'Notification not found.'}), 404
    
    try:
        db.session.delete(notification)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Notification deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/admin/mark-as-read-notification/', methods=['POST'])
def mark_read_notification():
    id = request.json.get('id')  # Expecting JSON data
    notification = db.session.query(Notification).filter_by(notification_id=id).first()
    
    if not notification:
        return jsonify({'status': 'error', 'message': 'Notification not found.'}), 404
    
    try:
        notification.notification_is_read = True
        db.session.commit()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/admin/delete-bulk/notifications/', methods=['POST'])
def delete_bulk_notifications():
    try:
        # Parse the JSON payload
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])

        # Validate input
        if not notification_ids:
            return jsonify({'success': False, 'message': 'No notifications selected for deletion.'}), 400

        # Perform deletion
        Notification.query.filter(Notification.notification_id.in_(notification_ids)).delete(synchronize_session=False)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Notification(s) deleted successfully.'}), 200

    except Exception as e:
        print(f"Error during bulk deletion: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while deleting notifications.'}), 500







# @app.route('/admin/sign-up/', methods=['POST', 'GET'])
# def admin_sign_up():
#     if request.method == 'POST':
#         fullname=request.form.get('fullname', '').strip()
#         username=request.form.get('username', '').strip()
#         pass1=request.form.get('password', '').strip()
#         pass2=request.form.get('cpassword', '').strip()
        
#         if not all([fullname, username, pass1, pass2]):
#             return jsonify({'success': False, 'message': 'All fields are required.'}), 400
        
#         elif pass1!=pass2:
#             return jsonify({'success': False, 'message': 'The two passwords must match.'}), 400
        
#         else:
#             hashed=generate_password_hash(pass1)
#             data=Admin(
#                 admin_fullname = fullname,
#                 admin_username = username,
#                 admin_password=hashed,
#                 admin_role= 'Admin'
#             )
#             try:
#                 db.session.add(data)
#                 db.session.commit()
#                 return jsonify({'success': True, 'message': 'Successfully Signed up. Plese Login in.', 'redirect_url': url_for('admin_login')}), 200
#             except Exception as e:
#                 db.session.rollback()
#                 return jsonify({'success': False, 'message': 'Something went wrong. Please try again later.'}), 500  
#     return render_template('admin/sign_up.html')    
       




   