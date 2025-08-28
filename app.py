from flask import Flask, render_template, request, redirect, url_for, flash, g, abort, jsonify, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.utils import secure_filename
import os
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv
import logging
import time
from functools import wraps
from datetime import datetime
import secrets
import uuid
import json

load_dotenv()



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config["WTF_CSRF_ENABLED"] = False

# Create data directory for JSON files
DATA_FOLDER = 'data'
USERS_FOLDER = os.path.join(DATA_FOLDER, 'users')
SERVERS_FOLDER = os.path.join(DATA_FOLDER, 'servers')
UPLOADS_FOLDER = os.path.join(DATA_FOLDER, 'uploads')

# Create directories if they don't exist
for folder in [DATA_FOLDER, USERS_FOLDER, SERVERS_FOLDER, UPLOADS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

csrf = CSRFProtect(app)

DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')

STRIPE_PUBLIC_KEY = os.getenv('STRIPE_PUBLIC_KEY')
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID')

STRIPE_ENABLED = False
if STRIPE_SECRET_KEY:
    try:
        import stripe
        stripe.api_key = STRIPE_SECRET_KEY
        STRIPE_ENABLED = True
    except ImportError:
        logger.warning("Stripe module not available. Premium features will be disabled.")
else:
    logger.warning("Stripe keys not configured. Premium features will be disabled.")

# JSON file helper functions
def save_json_file(filepath, data):
    """Save data to a JSON file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.error(f"Error saving JSON file {filepath}: {e}")
        return False

def load_json_file(filepath):
    """Load data from a JSON file"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON file {filepath}: {e}")
    return None

def get_user_by_discord_id(discord_id):
    """Get user by discord ID"""
    for filename in os.listdir(USERS_FOLDER):
        if filename.endswith('.json'):
            user_data = load_json_file(os.path.join(USERS_FOLDER, filename))
            if user_data and user_data.get('discord_id') == discord_id:
                return user_data
    return None

def get_user_by_id(user_id):
    """Get user by user ID"""
    user_file = os.path.join(USERS_FOLDER, f"{user_id}.json")
    return load_json_file(user_file)

def save_user(user_data):
    """Save user data"""
    user_id = user_data.get('id')
    if not user_id:
        user_id = str(uuid.uuid4())
        user_data['id'] = user_id
    
    user_file = os.path.join(USERS_FOLDER, f"{user_id}.json")
    return save_json_file(user_file, user_data)

def get_server_by_discord_id(discord_id):
    """Get server by discord ID"""
    server_file = os.path.join(SERVERS_FOLDER, f"{discord_id}.json")
    return load_json_file(server_file)

def get_server_by_subdomain(subdomain):
    """Get server by subdomain"""
    for filename in os.listdir(SERVERS_FOLDER):
        if filename.endswith('.json'):
            server_data = load_json_file(os.path.join(SERVERS_FOLDER, filename))
            if server_data and server_data.get('subdomain') == subdomain:
                return server_data
    return None

def save_server(server_data):
    """Save server data"""
    discord_id = server_data.get('discord_id')
    if not discord_id:
        return False
    
    server_file = os.path.join(SERVERS_FOLDER, f"{discord_id}.json")
    return save_json_file(server_file, server_data)

def get_servers_by_owner(owner_id):
    """Get all servers owned by a user"""
    servers = []
    for filename in os.listdir(SERVERS_FOLDER):
        if filename.endswith('.json'):
            server_data = load_json_file(os.path.join(SERVERS_FOLDER, filename))
            if server_data and server_data.get('owner_id') == owner_id:
                servers.append(server_data)
    return servers

def get_all_servers():
    """Get all servers"""
    servers = []
    for filename in os.listdir(SERVERS_FOLDER):
        if filename.endswith('.json'):
            server_data = load_json_file(os.path.join(SERVERS_FOLDER, filename))
            if server_data:
                servers.append(server_data)
    return servers

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data.get("id")
        self.discord_id = user_data.get("discord_id")
        self.username = user_data.get("username")
        self.email = user_data.get("email")
        self.avatar = user_data.get("avatar")
        self.is_premium = user_data.get("is_premium", False)
        self.stripe_customer_id = user_data.get("stripe_customer_id")

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = get_user_by_id(user_id)
        if user_data:
            return User(user_data)
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
    return None

def discord_get(url, headers, retries=3):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After", 1))
                logger.warning(f"Rate limited. Retrying after {retry_after}s")
                time.sleep(retry_after)
                continue
            elif r.status_code == 401:
                raise Exception("Unauthorized: Invalid token")
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Discord API request failed (attempt {attempt + 1}): {str(e)}")
            if attempt == retries - 1:
                raise
            time.sleep(1)
    raise Exception("Discord API request failed after retries")

def refresh_token(user_id):
    user_data = get_user_by_id(user_id)
    if not user_data:
        raise Exception("User not found")

    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': user_data['refresh_token'],
        'redirect_uri': DISCORD_REDIRECT_URI,
        'scope': 'identify guilds'
    }

    r = requests.post('https://discord.com/api/oauth2/token', data=data, timeout=10)
    if r.status_code != 200:
        logger.error(f"Token refresh failed: {r.text}")
        raise Exception("Failed to refresh token")

    tokens = r.json()
    user_data['access_token'] = tokens['access_token']
    user_data['refresh_token'] = tokens['refresh_token']
    save_user(user_data)
    return tokens['access_token']

def get_discord_guilds(access_token):
    headers = {'Authorization': f'Bearer {access_token}', 'User-Agent': 'LunaLink'}
    try:
        return discord_get("https://discord.com/api/v10/users/@me/guilds", headers)
    except Exception as e:
        if "Unauthorized" in str(e):
            new_token = refresh_token(current_user.id)
            headers['Authorization'] = f'Bearer {new_token}'
            return discord_get("https://discord.com/api/v10/users/@me/guilds", headers)
        raise

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    return redirect(url_for('login_with_discord'))

@app.route('/login-with-discord')
def login_with_discord():
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify email guilds'
    }
    return redirect(f"https://discord.com/api/oauth2/authorize?{urlencode(params)}")

@app.route('/callback')
def discord_callback():
    code = request.args.get('code')
    if not code:
        flash('Authorization failed', 'error')
        return redirect(url_for('index'))

    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'scope': 'identify email guilds'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        response = requests.post("https://discord.com/api/oauth2/token", data=data, headers=headers, timeout=10)
        response.raise_for_status()
        tokens = response.json()

        headers = {'Authorization': f"Bearer {tokens['access_token']}", 'User-Agent': 'LunaLink'}
        user_response = requests.get("https://discord.com/api/v10/users/@me", headers=headers, timeout=10)
        user_response.raise_for_status()
        user_data = user_response.json()

        avatar_url = None
        if user_data.get('avatar'):
            avatar_url = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"

        # Check if user already exists
        existing_user = get_user_by_discord_id(user_data['id'])
        
        if existing_user:
            # Update existing user
            existing_user.update({
                'username': user_data['username'],
                'email': user_data.get('email'),
                'avatar': avatar_url,
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token'],
                'last_login': datetime.utcnow().isoformat()
            })
            save_user(existing_user)
            user_obj = User(existing_user)
        else:
            # Create new user
            new_user_data = {
                'id': str(uuid.uuid4()),
                'discord_id': user_data['id'],
                'username': user_data['username'],
                'email': user_data.get('email'),
                'avatar': avatar_url,
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token'],
                'is_premium': False,
                'created_at': datetime.utcnow().isoformat(),
                'last_login': datetime.utcnow().isoformat()
            }
            save_user(new_user_data)
            user_obj = User(new_user_data)

        login_user(user_obj)
        return redirect(url_for('dashboard'))

    except Exception as e:
        logger.error(f"Discord auth error: {str(e)}")
        flash('Login failed', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_data = get_user_by_id(current_user.id)
        access_token = user_data['access_token']

        guilds_data = get_discord_guilds(access_token)
        admin_guilds = [
            {
                'id': g['id'],
                'name': g['name'],
                'icon_url': f"https://cdn.discordapp.com/icons/{g['id']}/{g['icon']}.png" if g.get('icon') else None,
                'has_permissions': True
            }
            for g in guilds_data if (int(g['permissions']) & 0x8)
        ]

        servers = get_servers_by_owner(current_user.id)

        # Check server limit - Free users can have 1 server forever
        server_count = len(servers)
        max_servers = 10 if current_user.is_premium else 1
        
        return render_template('dashboard.html', guilds=admin_guilds, servers=servers, 
                              user=current_user, server_count=server_count, max_servers=max_servers)

    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Failed to load dashboard. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/design/<guild_id>')
@login_required
def design(guild_id):
    try:
        # Check server limit for non-premium users - Allow 1 server forever
        if not current_user.is_premium:
            servers = get_servers_by_owner(current_user.id)
            server_count = len(servers)
            
            # Allow free users to have exactly 1 server, not more
            if server_count >= 1:
                # Check if they already have this server
                existing_server = get_server_by_discord_id(guild_id)
                
                if not existing_server or existing_server.get('owner_id') != current_user.id:
                    flash("You've reached the server limit for free accounts. You can manage 1 server forever. Upgrade to Premium to create more servers.", 'error')
                    return redirect(url_for('premium'))

        user_data = get_user_by_id(current_user.id)
        access_token = user_data['access_token']

        guilds = get_discord_guilds(access_token)
        target_guild = next(
            (g for g in guilds if g['id'] == guild_id and (int(g['permissions']) & 0x8)),
            None
        )

        if not target_guild:
            flash("You don't have administrator permissions for this server", 'error')
            return redirect(url_for('dashboard'))

        server = get_server_by_discord_id(guild_id)
        if not server:
            # Generate a unique subdomain
            base_subdomain = target_guild['name'].lower().replace(' ', '-').replace('_', '-')
            base_subdomain = ''.join(c for c in base_subdomain if c.isalnum() or c == '-')[:20]

            # Check if subdomain exists and make it unique
            subdomain = base_subdomain
            counter = 1
            while get_server_by_subdomain(subdomain):
                subdomain = f"{base_subdomain}-{counter}"
                counter += 1

            icon_url = None
            if target_guild.get('icon'):
                icon_url = f"https://cdn.discordapp.com/icons/{guild_id}/{target_guild['icon']}.png"

            server_data = {
                'discord_id': guild_id,
                'name': target_guild['name'],
                'icon': icon_url,
                'owner_id': current_user.id,
                'subdomain': subdomain,
                'title': 'My Server',
                'description': 'Welcome to my server page!',
                'banner_image': '',
                'primary_color': '#3a86ff',
                'secondary_color': '#06ffa5',
                'background_type': 'gradient',
                'gradient_color1': '#3a86ff',
                'gradient_color2': '#06ffa5',
                'font_family': 'Inter',
                'music_url': '',
                'logo_animation': 'none',
                'text_animation': 'none',
                'button_style': 'rounded',
                'particle_effect': 'none',
                'tiktok_url': '',
                'instagram_url': '',
                'website_url': '',
                'discord_invite': '',
                'youtube_url': '',
                'twitter_url': '',
                'custom_css': '',
                'visitor_count': 0,
                'last_updated': datetime.utcnow().isoformat(),
                'created_at': datetime.utcnow().isoformat()
            }

            save_server(server_data)
            server = server_data

        return render_template('designer.html', server=server, user=current_user)

    except Exception as e:
        logger.error(f"Design route error: {str(e)}")
        flash('Failed to load server details', 'error')
        return redirect(url_for('dashboard'))

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        server_id = request.form.get('server_id')
        
        if not server_id:
            return jsonify({'success': False, 'error': 'No server ID provided'}), 400
            
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
            
        if file and allowed_file(file.filename):
            # Verify user owns this server
            server = get_server_by_discord_id(server_id)
            
            if not server or server.get('owner_id') != current_user.id:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
                
            # Generate unique filename
            filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Save file info to uploads folder
            upload_data = {
                'user_id': current_user.id,
                'server_id': server_id,
                'filename': filename,
                'original_name': secure_filename(file.filename),
                'file_type': file.filename.rsplit('.', 1)[1].lower(),
                'file_size': file_size,
                'upload_date': datetime.utcnow().isoformat()
            }
            
            upload_file_path = os.path.join(UPLOADS_FOLDER, f"{filename}.json")
            save_json_file(upload_file_path, upload_data)
            
            # Return the URL for the uploaded file
            file_url = url_for('uploaded_file', filename=filename, _external=True)
            
            return jsonify({
                'success': True, 
                'file_url': file_url,
                'filename': filename
            })
        else:
            return jsonify({'success': False, 'error': 'File type not allowed'}), 400
            
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/save_design', methods=['POST'])
@login_required
def save_design():
    try:
        data = request.json
        if not data or 'server_id' not in data:
            return jsonify({'success': False, 'error': 'Invalid data'}), 400

        server = get_server_by_discord_id(data['server_id'])
        
        if not server or server.get('owner_id') != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        # Verify Discord permissions
        user_data = get_user_by_id(current_user.id)
        access_token = user_data['access_token']
        guilds = get_discord_guilds(access_token)
        if not any(g['id'] == data['server_id'] and (int(g['permissions']) & 0x8) for g in guilds):
            return jsonify({'success': False, 'error': 'No permissions'}), 403

        # Check subdomain uniqueness if changed
        if 'subdomain' in data and data['subdomain']:
            existing = get_server_by_subdomain(data['subdomain'])
            if existing and existing.get('discord_id') != data['server_id']:
                return jsonify({'success': False, 'error': 'Subdomain already taken'}), 400

        # Check premium restrictions
        is_premium = current_user.is_premium
        
        # Premium feature restrictions - improved validation
        premium_features = ['music_url', 'custom_css', 'particle_effect']
        for feature in premium_features:
            if feature in data:
                feature_value = data[feature]
                # Check if the value is not empty/whitespace and not set to 'none' for particle_effect
                if (feature_value and 
                    str(feature_value).strip() and  # Check it's not just whitespace
                    (feature != 'particle_effect' or feature_value != 'none') and  # Allow 'none' for particle_effect
                    not is_premium):
                    
                    return jsonify({'success': False, 'error': f'{feature.replace("_", " ").title()} is a premium feature'}), 403

        # Update server data
        allowed_fields = [
            'subdomain', 'title', 'description', 'primary_color', 'secondary_color',
            'background_type', 'gradient_color1', 'gradient_color2', 'font_family',
            'music_url', 'banner_image', 'logo_animation', 'text_animation', 
            'button_style', 'particle_effect', 'tiktok_url', 'instagram_url', 
            'website_url', 'discord_invite', 'youtube_url', 'twitter_url', 'custom_css'
        ]

        for field in allowed_fields:
            if field in data:
                server[field] = data[field]

        server['last_updated'] = datetime.utcnow().isoformat()
        save_server(server)

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Save design error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/preview/<server_id>')
@csrf.exempt
def api_preview(server_id):
    """API endpoint for live preview with form data"""
    try:
        # Get current server data
        server = get_server_by_discord_id(server_id)
        if not server:
            return "Server not found", 404

        # Override with query parameters for live preview
        preview_fields = [
            'title', 'description', 'primary_color', 'secondary_color', 
            'background_type', 'gradient_color1', 'gradient_color2', 
            'font_family', 'banner_image', 'logo_animation', 'text_animation',
            'button_style', 'particle_effect', 'music_url', 'tiktok_url', 
            'instagram_url', 'website_url', 'discord_invite', 'youtube_url', 
            'twitter_url', 'custom_css'
        ]
        
        for field in preview_fields:
            if request.args.get(field):
                server[field] = request.args.get(field)

        # Render the template
        return render_template('website_template.html', server=server, preview_mode=True)
    
    except Exception as e:
        logger.error(f"Preview error: {str(e)}")
        return f"Preview error: {str(e)}", 500

@app.route('/preview/<server_id>')
def preview(server_id):
    """Public preview route"""
    # First try to find by discord_id
    server = get_server_by_discord_id(server_id)

    # If not found, try subdomain
    if not server:
        server = get_server_by_subdomain(server_id)

    if not server:
        abort(404)

    # Don't increment visitor count for preview mode
    if not request.args.get('preview'):
        server['visitor_count'] = server.get('visitor_count', 0) + 1
        save_server(server)

    return render_template('website_template.html', server=server)

@app.route('/<subdomain>')
def subdomain_preview(subdomain):
    """Handle custom subdomain routes"""
    # Skip certain routes that shouldn't be treated as subdomains
    skip_routes = ['login', 'logout', 'dashboard', 'design', 'preview', 'api', 'callback', 'serverlist', 'static', 'uploads']
    if subdomain in skip_routes:
        abort(404)

    server = get_server_by_subdomain(subdomain)
    if not server:
        abort(404)

    server['visitor_count'] = server.get('visitor_count', 0) + 1
    save_server(server)

    return render_template('website_template.html', server=server)

@app.route('/serverlist')
def server_list():
    servers = get_all_servers()
    
    # Add owner information
    for server in servers:
        owner_id = server.get('owner_id')
        if owner_id:
            owner_data = get_user_by_id(owner_id)
            if owner_data:
                server['owner_name'] = owner_data.get('username')
                server['owner_avatar'] = owner_data.get('avatar')
    
    # Sort by visitor count
    servers.sort(key=lambda x: x.get('visitor_count', 0), reverse=True)

    return render_template('serverlist.html', servers=servers)

@app.route('/premium')
@login_required
def premium():
    return render_template('premium.html', stripe_public_key=STRIPE_PUBLIC_KEY, user=current_user, stripe_enabled=STRIPE_ENABLED)

@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    if not STRIPE_ENABLED:
        return jsonify({'error': 'Stripe integration is not configured'}), 500
        
    try:
        # Get or create Stripe customer
        user_data = get_user_by_id(current_user.id)
        customer_id = user_data.get('stripe_customer_id')
        
        if not customer_id:
            # Create new customer
            customer = stripe.Customer.create(
                email=current_user.email,
                metadata={'user_id': current_user.id}
            )
            customer_id = customer.id
            
            # Save customer ID to user data
            user_data['stripe_customer_id'] = customer_id
            save_user(user_data)
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[
                {
                    'price': STRIPE_PRICE_ID,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('premium', _external=True),
            metadata={
                'user_id': current_user.id
            }
        )
        
        return jsonify({'sessionId': checkout_session.id})
    
    except Exception as e:
        logger.error(f"Checkout session error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/payment-success')
@login_required
def payment_success():
    if not STRIPE_ENABLED:
        flash('Stripe integration is not configured', 'error')
        return redirect(url_for('premium'))
        
    session_id = request.args.get('session_id')
    
    if not session_id:
        flash('Invalid payment session', 'error')
        return redirect(url_for('premium'))
    
    try:
        # Retrieve the session
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        # Verify this session belongs to the current user
        user_data = get_user_by_id(current_user.id)
        if checkout_session.customer != user_data.get('stripe_customer_id'):
            flash('Invalid payment session', 'error')
            return redirect(url_for('premium'))
        
        # Update user to premium
        user_data['is_premium'] = True
        save_user(user_data)
        
        # Save subscription details
        subscription = stripe.Subscription.retrieve(checkout_session.subscription)
        
        subscription_data = {
            'user_id': current_user.id,
            'stripe_subscription_id': checkout_session.subscription,
            'stripe_price_id': STRIPE_PRICE_ID,
            'status': subscription.status,
            'current_period_start': datetime.fromtimestamp(subscription.current_period_start).isoformat(),
            'current_period_end': datetime.fromtimestamp(subscription.current_period_end).isoformat(),
            'cancel_at_period_end': subscription.cancel_at_period_end,
            'created_at': datetime.utcnow().isoformat()
        }
        
        subscription_file = os.path.join(DATA_FOLDER, f"subscription_{checkout_session.subscription}.json")
        save_json_file(subscription_file, subscription_data)
        
        flash('Your premium subscription has been activated!', 'success')
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        logger.error(f"Payment success error: {str(e)}")
        flash('Error processing your payment. Please contact support.', 'error')
        return redirect(url_for('premium'))

@app.route('/api/user/server_count')
@login_required
def user_server_count():
    servers = get_servers_by_owner(current_user.id)
    count = len(servers)
    # Free users can have 1 server forever, premium users get 10
    max_servers = 10 if current_user.is_premium else 1
    
    return jsonify({'count': count, 'max': max_servers})

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    if not STRIPE_ENABLED:
        return jsonify({'error': 'Stripe integration is not configured'}), 400
        
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle the event
    if event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        handle_subscription_cancelled(subscription)
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        handle_subscription_updated(subscription)
    
    return jsonify({'success': True})

def handle_subscription_cancelled(subscription):
    # Find user by stripe customer ID
    for filename in os.listdir(USERS_FOLDER):
        if filename.endswith('.json'):
            user_data = load_json_file(os.path.join(USERS_FOLDER, filename))
            if user_data and user_data.get('stripe_customer_id') == subscription.customer:
                user_data['is_premium'] = False
                save_user(user_data)
                
                # Remove subscription file
                subscription_file = os.path.join(DATA_FOLDER, f"subscription_{subscription.id}.json")
                if os.path.exists(subscription_file):
                    os.remove(subscription_file)
                
                logger.info(f"Subscription cancelled for user {user_data['id']}")
                break

def handle_subscription_updated(subscription):
    for filename in os.listdir(USERS_FOLDER):
        if filename.endswith('.json'):
            user_data = load_json_file(os.path.join(USERS_FOLDER, filename))
            if user_data and user_data.get('stripe_customer_id') == subscription.customer:
                subscription_data = {
                    'user_id': user_data['id'],
                    'stripe_subscription_id': subscription.id,
                    'status': subscription.status,
                    'current_period_start': datetime.fromtimestamp(subscription.current_period_start).isoformat(),
                    'current_period_end': datetime.fromtimestamp(subscription.current_period_end).isoformat(),
                    'cancel_at_period_end': subscription.cancel_at_period_end
                }
                
                subscription_file = os.path.join(DATA_FOLDER, f"subscription_{subscription.id}.json")
                save_json_file(subscription_file, subscription_data)
                
                # Update user premium status based on subscription status
                is_premium = subscription.status == 'active' and not subscription.cancel_at_period_end
                user_data['is_premium'] = is_premium
                save_user(user_data)
                
                logger.info(f"Subscription updated for user {user_data['id']}")
                break

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Health check endpoint for monitoring
@app.route('/health')
def health_check():
    try:
        # Test data folder access
        test_file = os.path.join(DATA_FOLDER, 'health_check.json')
        test_data = {'status': 'test', 'timestamp': datetime.utcnow().isoformat()}
        save_json_file(test_file, test_data)
        
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'storage': 'connected'
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'storage': 'disconnected',
            'error': str(e)
        }), 503

# Fixed error handlers that don't depend on templates
@app.errorhandler(404)
def not_found_error(error):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Page Not Found</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1a1a2e; color: white; text-align: center; padding: 50px; }
            h1 { color: #3a86ff; }
        </style>
    </head>
    <body>
        <h1>404 - Page Not Found</h1>
        <p>The page you requested could not be found.</p>
        <a href="/" style="color: #06ffa5;">Return to Home</a>
    </body>
    </html>
    ''', 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>500 - Internal Server Error</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1a1a2e; color: white; text-align: center; padding: 50px; }
            h1 { color: #dc3545; }
        </style>
    </head>
    <body>
        <h1>500 - Internal Server Error</h1>
        <p>Something went wrong on our end. Please try again later.</p>
        <a href="/" style="color: #06ffa5;">Return to Home</a>
    </body>
    </html>
    ''', 500

@app.errorhandler(503)
def service_unavailable(error):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>503 - Service Unavailable</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1a1a2e; color: white; text-align: center; padding: 50px; }
            h1 { color: #ffc107; }
        </style>
    </head>
    <body>
        <h1>503 - Service Unavailable</h1>
        <p>The service is temporarily unavailable. Please try again later.</p>
        <a href="/" style="color: #06ffa5;">Return to Home</a>
    </body>
    </html>
    ''', 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
