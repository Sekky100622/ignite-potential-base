import os
import re
import base64
import secrets
import hashlib
import hmac
import time
import csv
import smtplib
import requests as req
from datetime import datetime, timezone
from functools import wraps
from io import StringIO
from urllib.parse import urlparse, quote_plus
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, Response
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
import bcrypt
import markdown as md
import bleach
from dateutil import parser as dtparser
import psycopg
from psycopg.rows import dict_row
import cloudinary
import cloudinary.uploader

load_dotenv()

app = Flask(__name__)

# SECRET_KEY: 本番(Render)では環境変数必須、未設定なら起動エラー
_IS_PRODUCTION = bool(os.getenv('RENDER'))
_secret_key = os.getenv('SECRET_KEY')
if not _secret_key:
    if _IS_PRODUCTION:
        raise RuntimeError('SECRET_KEY 環境変数が設定されていません。Renderの環境変数に追加してください。')
    _secret_key = 'dev-secret-key-local-only'
app.secret_key = _secret_key

# ファイルアップロード上限 5MB
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# セキュリティ設定
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = _IS_PRODUCTION  # Renderは RENDER=true を自動設定
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[], storage_uri='memory://')

NOTE_URL = os.getenv('NOTE_URL', '#')
OG_IMAGE_URL = os.getenv('OG_IMAGE_URL', '')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
GA_MEASUREMENT_ID = os.getenv('GA_MEASUREMENT_ID', '')
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
)

DRILL_CATEGORIES = [
    'リセット',
    'コレクティブ',
    'モーターコントロール',
    'ベーシックムーブメント',
    'ウエイトトレーニング',
    'プライオメトリクス',
    'スキル（アトラクターベース）',
]
PLAYER_LEVELS = ['小学生', '中学生', '高校生', '大学生', '社会人', 'プロ', 'メジャーリーガー']
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')

# bleach 許可設定（markdownコンテンツのサニタイズ用）
_BLEACH_TAGS = [
    'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'blockquote', 'hr',
    'pre', 'code', 'a', 'img',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
]
_BLEACH_ATTRS = {
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'loading', 'width', 'height'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
    'code': ['class'],
    'pre': ['class'],
}


def sanitize_html(html: str) -> str:
    return bleach.clean(html, tags=_BLEACH_TAGS, attributes=_BLEACH_ATTRS, strip=True)


# パスワードの特殊文字（!など）をURLエンコード
def _encode_db_url(url):
    if not url:
        return url
    p = urlparse(url)
    if p.password:
        return url.replace(f':{p.password}@', f':{quote_plus(p.password)}@', 1)
    return url

_DB_URL = _encode_db_url(DATABASE_URL)


# ── Direct PostgreSQL helpers ─────────────────────────────────────────────────

def db_execute(sql, params=None):
    if not _DB_URL:
        print('[db_execute] DATABASE_URL not set', flush=True)
        return False
    try:
        with psycopg.connect(_DB_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
        return True
    except Exception as e:
        print(f'[db_execute] error: {e}', flush=True)
        return False


def db_fetchone(sql, params=None):
    if not _DB_URL:
        print('[db_fetchone] DATABASE_URL not set', flush=True)
        return None
    try:
        with psycopg.connect(_DB_URL, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchone()
    except Exception as e:
        print(f'[db_fetchone] error: {e}', flush=True)
        return None


def db_fetchall(sql, params=None):
    if not _DB_URL:
        print('[db_fetchall] DATABASE_URL not set', flush=True)
        return []
    try:
        with psycopg.connect(_DB_URL, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        print(f'[db_fetchall] error: {e}', flush=True)
        return []


# ── Supabase helpers ──────────────────────────────────────────────────────────

def supabase_headers(service=False):
    key = SUPABASE_SERVICE_KEY if service else SUPABASE_KEY
    return {
        'apikey': key,
        'Authorization': f'Bearer {key}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
    }


def sb_get(table, params=None, service=False):
    if not SUPABASE_URL:
        return []
    try:
        r = req.get(f'{SUPABASE_URL}/rest/v1/{table}',
                    headers=supabase_headers(service), params=params, timeout=10)
        return r.json() if r.ok else []
    except Exception:
        return []


def sb_post(table, data, service=False):
    if not SUPABASE_URL:
        print(f'[sb_post] SUPABASE_URL not set')
        return None
    try:
        r = req.post(f'{SUPABASE_URL}/rest/v1/{table}',
                     headers=supabase_headers(service), json=data, timeout=10)
        print(f'[sb_post] {table} status={r.status_code} body={r.text[:300]}')
        if not r.ok:
            return None
        try:
            result = r.json()
            if isinstance(result, list) and result:
                return result[0]
        except Exception:
            pass
        return True  # 成功だがデータなし
    except Exception as e:
        print(f'[sb_post] exception: {e}')
        return None


def sb_rpc(func_name, data, service=False):
    if not SUPABASE_URL:
        return None
    try:
        r = req.post(f'{SUPABASE_URL}/rest/v1/rpc/{func_name}',
                     headers=supabase_headers(service), json=data, timeout=10)
        if not r.ok:
            print(f'[sb_rpc] {func_name} status={r.status_code} body={r.text[:300]}')
            return None
        try:
            return r.json()
        except Exception:
            return True
    except Exception as e:
        print(f'[sb_rpc] exception: {e}')
        return None


# ── Drill helpers (Supabase REST API) ─────────────────────────────────────────

def pg_drills(drill_id=None, is_free=None, category=None, q=None):
    """Get drills via direct SQL."""
    sql = ('SELECT id,name,purpose,video_url,image_url,method,points,is_free,created_at,category,difficulty '
           'FROM ipb_drills')
    conditions = []
    params = []
    if drill_id is not None:
        conditions.append('id=%s')
        params.append(drill_id)
    if is_free is not None:
        conditions.append('is_free=%s')
        params.append(is_free)
    if category:
        conditions.append('category=%s')
        params.append(category)
    if q:
        conditions.append('(name ILIKE %s OR purpose ILIKE %s OR points ILIKE %s)')
        params.extend([f'%{q}%', f'%{q}%', f'%{q}%'])
    if conditions:
        sql += ' WHERE ' + ' AND '.join(conditions)
    sql += ' ORDER BY sort_order ASC, created_at DESC'
    return db_fetchall(sql, params) or []


_ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'gif'}
_ALLOWED_IMAGE_MIMETYPES = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}

def upload_drill_image(file_obj):
    """Cloudinaryにドリル画像をアップロードしてURLを返す。失敗時はNone。"""
    # 拡張子チェック
    filename = file_obj.filename or ''
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in _ALLOWED_IMAGE_EXTENSIONS:
        print(f'[upload] 許可されていない拡張子: {ext}')
        return None
    # MIMEタイプチェック
    if file_obj.content_type not in _ALLOWED_IMAGE_MIMETYPES:
        print(f'[upload] 許可されていないMIMEタイプ: {file_obj.content_type}')
        return None
    try:
        result = cloudinary.uploader.upload(
            file_obj,
            folder='ipb_drills',
            resource_type='image',
            transformation=[{'width': 800, 'height': 600, 'crop': 'fill', 'quality': 'auto', 'fetch_format': 'auto'}]
        )
        return result.get('secure_url')
    except Exception as e:
        print(f'[cloudinary] upload error: {e}')
        return None


def pg_drill_save(data, drill_id=None):
    """Insert or update a drill via direct SQL (bypasses PostgREST schema cache)."""
    _FIELDS = ['name', 'purpose', 'video_url', 'image_url', 'method', 'points', 'is_free', 'category', 'difficulty']
    present = [f for f in _FIELDS if f in data]
    if drill_id:
        set_clauses = ', '.join(f'{f}=%s' for f in present)
        values = [data[f] for f in present] + [drill_id]
        return db_execute(f'UPDATE ipb_drills SET {set_clauses} WHERE id=%s', values)
    else:
        cols = ', '.join(present)
        placeholders = ', '.join(['%s'] * len(present))
        values = [data[f] for f in present]
        return db_execute(f'INSERT INTO ipb_drills ({cols}) VALUES ({placeholders})', values)


def sb_patch(table, params, data, service=False):
    if not SUPABASE_URL:
        return False
    try:
        r = req.patch(f'{SUPABASE_URL}/rest/v1/{table}',
                      headers=supabase_headers(service), params=params, json=data, timeout=10)
        print(f'[sb_patch] {table} params={params} status={r.status_code} body={r.text[:600]}', flush=True)
        return r.ok
    except Exception as e:
        print(f'[sb_patch] exception: {e}', flush=True)
        return False


def sb_delete(table, params, service=False):
    if not SUPABASE_URL:
        return False
    try:
        r = req.delete(f'{SUPABASE_URL}/rest/v1/{table}',
                       headers=supabase_headers(service), params=params, timeout=10)
        return r.ok
    except Exception:
        return False


# ── Auth decorators ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── DB setup (auto-create tables) ─────────────────────────────────────────────

def ensure_tables():
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_drills (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            name TEXT NOT NULL,
            purpose TEXT DEFAULT '',
            video_url TEXT DEFAULT '',
            method TEXT DEFAULT '',
            points TEXT DEFAULT '',
            is_free BOOLEAN DEFAULT FALSE,
            category TEXT DEFAULT '',
            difficulty TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 9999,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_likes (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id UUID NOT NULL,
            article_id UUID NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, article_id)
        )
    ''')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_comments (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id UUID NOT NULL,
            article_id UUID NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_bookmarks (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id UUID NOT NULL,
            article_id UUID NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, article_id)
        )
    ''')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_notices (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT,
            published BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')
    db_execute('ALTER TABLE ipb_users ADD COLUMN IF NOT EXISTS google_id TEXT')
    db_execute('ALTER TABLE ipb_articles ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0')
    db_execute('ALTER TABLE ipb_articles ADD COLUMN IF NOT EXISTS tags TEXT')
    db_execute('ALTER TABLE ipb_drills ADD COLUMN IF NOT EXISTS difficulty TEXT')
    db_execute('ALTER TABLE ipb_drills ADD COLUMN IF NOT EXISTS sort_order INTEGER DEFAULT 9999')
    db_execute('ALTER TABLE ipb_drills ADD COLUMN IF NOT EXISTS image_url TEXT')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_programs (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            target TEXT DEFAULT '',
            is_published BOOLEAN DEFAULT TRUE,
            sort_order INTEGER DEFAULT 9999,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_program_drills (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            program_id UUID REFERENCES ipb_programs(id) ON DELETE CASCADE,
            drill_id UUID REFERENCES ipb_drills(id) ON DELETE CASCADE,
            step_number INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')
    db_execute('ALTER TABLE ipb_comments ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT TRUE')
    db_execute('''
        CREATE TABLE IF NOT EXISTS ipb_questions (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id UUID REFERENCES ipb_users(id) ON DELETE SET NULL,
            question TEXT NOT NULL,
            answer TEXT,
            is_anonymous BOOLEAN DEFAULT FALSE,
            is_public BOOLEAN DEFAULT TRUE,
            status TEXT DEFAULT 'pending',
            user_name TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            answered_at TIMESTAMPTZ
        )
    ''')

ensure_tables()


# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(resp):
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if _IS_PRODUCTION:
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return resp


@app.errorhandler(413)
def request_entity_too_large(e):
    flash('ファイルサイズが大きすぎます（上限5MB）', 'error')
    return redirect(request.referrer or url_for('admin_library'))


# ── Context processor ─────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'note_url': NOTE_URL,
        'og_image_url': OG_IMAGE_URL,
        'current_year': datetime.now().year,
        'google_client_id': GOOGLE_CLIENT_ID,
        'ga_measurement_id': GA_MEASUREMENT_ID,
    }


# ── Public routes ─────────────────────────────────────────────────────────────

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


@app.route('/terms')
def terms():
    return render_template('terms.html')


@app.route('/')
def index():
    free_articles = sb_get('ipb_articles', {
        'is_free': 'eq.true',
        'published': 'eq.true',
        'order': 'created_at.desc',
        'limit': 3,
        'select': 'id,title,slug,excerpt,created_at',
    }) or []
    article_count = len(sb_get('ipb_articles', {'published': 'eq.true', 'select': 'id'}) or [])
    drill_count = len(pg_drills())
    return render_template('index.html', free_articles=free_articles,
                           article_count=article_count, drill_count=drill_count)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def register():
    if session.get('user_id'):
        return redirect(url_for('library'))
    error = None
    if request.method == 'POST':
        name  = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            error = 'すべての項目を入力してください'
        elif len(password) < 8:
            error = 'パスワードは8文字以上で設定してください'
        else:
            existing = sb_get('ipb_users', {'email': f'eq.{email}', 'select': 'id'}, service=True)
            if existing:
                error = 'このメールアドレスはすでに登録されています'
            else:
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                user = sb_post('ipb_users', {
                    'name': name, 'email': email,
                    'password_hash': pw_hash, 'role': 'member', 'plan': 'free',
                }, service=True)
                if user and isinstance(user, dict):
                    _set_session(user)
                    flash('登録が完了しました！', 'success')
                    return redirect(url_for('welcome'))
                error = '登録に失敗しました。時間をおいて再度お試しください。'
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        users = sb_get('ipb_users', {'email': f'eq.{email}', 'select': '*'}, service=True)
        if users and isinstance(users, list):
            user = users[0]
            pw_hash = user.get('password_hash', '')
            authenticated = False

            # bcrypt check
            try:
                if bcrypt.checkpw(password.encode(), pw_hash.encode()):
                    authenticated = True
            except Exception:
                pass

            # fallback: sha256 hex (legacy from setup.sql)
            if not authenticated:
                if hashlib.sha256(password.encode()).hexdigest() == pw_hash:
                    # migrate to bcrypt
                    new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                    sb_patch('ipb_users', {'id': f'eq.{user["id"]}'}, {'password_hash': new_hash}, service=True)
                    authenticated = True

            if authenticated:
                _set_session(user)
                return redirect(url_for('dashboard'))

        flash('メールアドレスまたはパスワードが正しくありません', 'error')

    return render_template('login.html')


@app.route('/auth/google', methods=['POST'])
@csrf.exempt
def auth_google():
    credential = request.form.get('credential', '')
    if not credential or not GOOGLE_CLIENT_ID:
        flash('Googleログインに失敗しました', 'error')
        return redirect(url_for('login'))
    try:
        idinfo = google_id_token.verify_oauth2_token(
            credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except Exception as e:
        print(f'[auth_google] token verify failed: {e}', flush=True)
        flash('Googleログインに失敗しました。再度お試しください。', 'error')
        return redirect(url_for('login'))

    email = (idinfo.get('email') or '').lower()
    name = idinfo.get('name') or email.split('@')[0]
    google_id = idinfo.get('sub', '')

    if not email:
        flash('メールアドレスを取得できませんでした', 'error')
        return redirect(url_for('login'))

    # 既存ユーザー確認
    users = sb_get('ipb_users', {'email': f'eq.{email}', 'select': '*'}, service=True)
    if users:
        user = users[0]
        if not user.get('google_id') and google_id:
            sb_patch('ipb_users', {'id': f'eq.{user["id"]}'}, {'google_id': google_id}, service=True)
        _set_session(user)
        return redirect(url_for('dashboard'))

    # 新規登録（google_idはINSERT後にUPDATEで設定）
    new_user = sb_post('ipb_users', {
        'name': name, 'email': email,
        'password_hash': '', 'role': 'member', 'plan': 'free',
    }, service=True)
    if new_user and isinstance(new_user, dict):
        # google_idを直接SQLでセット（PostgRESTキャッシュ問題を回避）
        if google_id:
            db_execute('UPDATE ipb_users SET google_id=%s WHERE id=%s',
                       (google_id, new_user['id']))
        _set_session(new_user)
        flash('Googleアカウントで登録が完了しました！', 'success')
        return redirect(url_for('welcome'))

    # sb_postが失敗＝メール重複の可能性 → 再度検索してログイン
    users2 = sb_get('ipb_users', {'email': f'eq.{email}', 'select': '*'}, service=True)
    if users2:
        user = users2[0]
        if google_id:
            db_execute('UPDATE ipb_users SET google_id=%s WHERE id=%s AND (google_id IS NULL OR google_id=\'\')',
                       (google_id, user['id']))
        _set_session(user)
        return redirect(url_for('dashboard'))

    flash('登録に失敗しました。時間をおいて再度お試しください。', 'error')
    return redirect(url_for('register'))


def _set_session(user):
    session['user_id'] = user['id']
    session['name'] = user['name']
    session['email'] = user['email']
    session['role'] = user['role']
    session['plan'] = user['plan']
    session['is_team'] = bool(user.get('is_team'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ── Member routes ─────────────────────────────────────────────────────────────

@app.route('/welcome')
@login_required
def welcome():
    free_articles = sb_get('ipb_articles', {
        'is_free': 'eq.true', 'published': 'eq.true',
        'order': 'created_at.desc', 'limit': 3,
        'select': 'id,title,slug,excerpt',
    }) or []
    return render_template('welcome.html', free_articles=free_articles)


@app.route('/dashboard')
@login_required
def dashboard():
    user = {
        'id': session['user_id'],
        'name': session['name'],
        'email': session['email'],
        'role': session['role'],
        'plan': session['plan'],
    }
    recent_articles = sb_get('ipb_articles', {
        'published': 'eq.true',
        'order': 'created_at.desc',
        'limit': 3,
        'select': 'id,title,slug,is_free,created_at',
    }) or []

    all_drills = pg_drills()
    is_premium = user['plan'] in ('premium', 'team') or bool(user.get('is_team'))
    if is_premium:
        available_drills = all_drills
    else:
        available_drills = [d for d in all_drills if d.get('is_free')][:20]

    # カテゴリ別件数
    cat_counts = {}
    for d in available_drills:
        c = d.get('category') or '未分類'
        cat_counts[c] = cat_counts.get(c, 0) + 1

    recent_drills = all_drills[:4]

    # お知らせ
    notices = db_fetchall('SELECT * FROM ipb_notices WHERE published=TRUE ORDER BY created_at DESC LIMIT 3') or []

    # ブックマーク記事
    user_id = session['user_id']
    bookmarks = db_fetchall('''
        SELECT a.id, a.title, a.slug, a.excerpt
        FROM ipb_bookmarks b
        JOIN ipb_articles a ON b.article_id = a.id
        WHERE b.user_id = %s ORDER BY b.created_at DESC LIMIT 5
    ''', (user_id,)) or []

    recently_viewed = session.get('recently_viewed', [])

    return render_template('dashboard.html', user=user,
                           recent_articles=recent_articles,
                           drill_count=len(available_drills),
                           recent_drills=recent_drills,
                           cat_counts=cat_counts,
                           is_premium=is_premium,
                           notices=notices,
                           bookmarks=bookmarks,
                           recently_viewed=recently_viewed)


@app.route('/learn')
def learn():
    is_logged_in = bool(session.get('user_id'))
    cat_slug = request.args.get('category', '')
    active_tag = request.args.get('tag', '').strip()
    q = request.args.get('q', '').strip()
    sort = request.args.get('sort', 'newest')
    page = max(1, int(request.args.get('page', 1)))
    per_page = 9

    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []
    cat_map = {c['id']: c for c in categories}

    all_articles = sb_get('ipb_articles', {
        'order': 'created_at.desc',
        'select': 'id,title,slug,excerpt,is_free,thumbnail_url,video_url,pdf_url,category_id,created_at,published,tags',
    }) or []

    articles = [a for a in all_articles if a.get('published')]
    if not is_logged_in:
        articles = [a for a in articles if a.get('is_free')]

    if cat_slug:
        matching = [c for c in categories if c['slug'] == cat_slug]
        if matching:
            cat_id = matching[0]['id']
            articles = [a for a in articles if str(a.get('category_id')) == str(cat_id)]
        else:
            articles = []

    if active_tag:
        articles = [a for a in articles if
                    any(t.strip() == active_tag for t in (a.get('tags') or '').split(','))]

    if q:
        ql = q.lower()
        articles = [a for a in articles if
                    ql in (a.get('title') or '').lower() or
                    ql in (a.get('excerpt') or '').lower()]

    all_likes = sb_get('ipb_likes', {'select': 'article_id'}) or []
    like_counts = {}
    for like in all_likes:
        aid = str(like.get('article_id', ''))
        like_counts[aid] = like_counts.get(aid, 0) + 1

    for a in articles:
        a['category'] = cat_map.get(a.get('category_id'))
        a['like_count'] = like_counts.get(str(a.get('id', '')), 0)

    if sort == 'popular':
        articles.sort(key=lambda a: a['like_count'], reverse=True)

    # 全タグ収集
    all_tags = []
    seen = set()
    for a in [x for x in all_articles if x.get('published') and (is_logged_in or x.get('is_free'))]:
        for t in (a.get('tags') or '').split(','):
            t = t.strip()
            if t and t not in seen:
                all_tags.append(t)
                seen.add(t)

    # ページネーション
    total = len(articles)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    articles_page = articles[(page - 1) * per_page: page * per_page]

    return render_template('learn.html', articles=articles_page, categories=categories,
                           active_category=cat_slug, active_tag=active_tag,
                           all_tags=all_tags, q=q, sort=sort, is_logged_in=is_logged_in,
                           page=page, total_pages=total_pages, total=total, per_page=per_page)


@app.route('/learn/<slug>')
def learn_detail(slug):
    articles = sb_get('ipb_articles', {'slug': f'eq.{slug}', 'published': 'is.true', 'select': '*'})
    if not articles:
        return redirect(url_for('learn'))
    article = articles[0]
    article_id = article['id']

    # attach category
    if article.get('category_id'):
        cats = sb_get('ipb_categories', {'id': f'eq.{article["category_id"]}', 'select': '*'})
        article['category'] = cats[0] if cats else None
    else:
        article['category'] = None

    # render markdown (bleach でサニタイズ)
    article['content_html'] = sanitize_html(md.markdown(
        article.get('content', ''),
        extensions=['fenced_code', 'tables'],
    ))

    # convert YouTube watch URL to embed URL
    video_url = article.get('video_url', '') or ''
    embed_url = ''
    if 'youtube.com/watch' in video_url:
        m = re.search(r'v=([^&]+)', video_url)
        if m:
            embed_url = f'https://www.youtube.com/embed/{m.group(1)}'
    elif 'youtu.be/' in video_url:
        vid = video_url.split('youtu.be/')[-1].split('?')[0]
        embed_url = f'https://www.youtube.com/embed/{vid}'
    elif video_url:
        embed_url = video_url
    article['video_embed_url'] = embed_url

    # 読了時間（日本語400文字/分）
    content_text = re.sub(r'<[^>]+>', '', article.get('content_html', ''))
    reading_time = max(1, len(content_text) // 400) if len(content_text) > 100 else None

    # 閲覧数カウント
    db_execute('UPDATE ipb_articles SET view_count = COALESCE(view_count, 0) + 1 WHERE id=%s',
               (article_id,))

    # 最近閲覧した記事（セッション保存）
    rv = session.get('recently_viewed', [])
    rv = [r for r in rv if r.get('slug') != slug]
    rv.insert(0, {'slug': article['slug'], 'title': article['title']})
    session['recently_viewed'] = rv[:5]
    session.modified = True

    # related articles (same category)
    related = []
    if article.get('category_id'):
        related = sb_get('ipb_articles', {
            'category_id': f'eq.{article["category_id"]}',
            'published': 'is.true',
            'id': f'neq.{article["id"]}',
            'limit': 4,
            'select': 'id,title,slug,is_free',
        }) or []

    can_view = article.get('is_free') or session.get('plan') in ('premium', 'team') or session.get('is_team')
    if not can_view:
        return redirect(url_for('register'))

    # いいね
    user_id = session.get('user_id')
    likes = sb_get('ipb_likes', {'article_id': f'eq.{article_id}', 'select': 'user_id'}) or []
    like_count = len(likes)
    user_liked = any(str(l.get('user_id')) == str(user_id) for l in likes) if user_id else False

    # ブックマーク
    user_bookmarked = False
    if user_id:
        bm = db_fetchone('SELECT id FROM ipb_bookmarks WHERE user_id=%s AND article_id=%s',
                         (user_id, article_id))
        user_bookmarked = bm is not None

    # コメント（ユーザー名付き）
    comments = db_fetchall('''
        SELECT c.id, c.content, c.created_at, u.name AS user_name, c.user_id
        FROM ipb_comments c
        JOIN ipb_users u ON c.user_id = u.id
        WHERE c.article_id = %s AND c.approved = TRUE
        ORDER BY c.created_at ASC
    ''', (article_id,))

    return render_template('article.html', article=article, related=related, can_view=True,
                           like_count=like_count, user_liked=user_liked,
                           user_bookmarked=user_bookmarked,
                           comments=comments or [], user_id=user_id,
                           reading_time=reading_time)


@app.route('/learn/<slug>/like', methods=['POST'])
@login_required
def article_like(slug):
    articles = sb_get('ipb_articles', {'slug': f'eq.{slug}', 'select': 'id,published'})
    if not articles:
        return jsonify({'error': 'not found'}), 404
    article = articles[0]
    if not article.get('published'):
        return jsonify({'error': 'not found'}), 404
    article_id = article['id']
    user_id = session.get('user_id')

    existing = db_fetchone('SELECT id FROM ipb_likes WHERE user_id=%s AND article_id=%s',
                           (user_id, article_id))
    if existing:
        db_execute('DELETE FROM ipb_likes WHERE user_id=%s AND article_id=%s',
                   (user_id, article_id))
        liked = False
    else:
        db_execute('INSERT INTO ipb_likes (user_id, article_id) VALUES (%s, %s)',
                   (user_id, article_id))
        liked = True

    count_row = db_fetchone('SELECT COUNT(*) AS cnt FROM ipb_likes WHERE article_id=%s', (article_id,))
    count = count_row['cnt'] if count_row else 0
    return jsonify({'liked': liked, 'count': count})


@app.route('/learn/<slug>/comment', methods=['POST'])
@login_required
def article_comment(slug):
    articles = sb_get('ipb_articles', {'slug': f'eq.{slug}', 'select': 'id,published'})
    if not articles or not articles[0].get('published'):
        return redirect(url_for('learn'))
    article_id = articles[0]['id']
    user_id = session.get('user_id')
    content = request.form.get('content', '').strip()
    if content:
        db_execute('INSERT INTO ipb_comments (user_id, article_id, content) VALUES (%s, %s, %s)',
                   (user_id, article_id, content))
    return redirect(url_for('learn_detail', slug=slug) + '#comments')


@app.route('/learn/<slug>/comment/<comment_id>/delete', methods=['POST'])
@admin_required
def article_comment_delete(slug, comment_id):
    db_execute('DELETE FROM ipb_comments WHERE id=%s', (comment_id,))
    return redirect(url_for('learn_detail', slug=slug) + '#comments')


@app.route('/learn/<slug>/bookmark', methods=['POST'])
@login_required
def article_bookmark(slug):
    articles = sb_get('ipb_articles', {'slug': f'eq.{slug}', 'select': 'id,published'})
    if not articles:
        return jsonify({'error': 'not found'}), 404
    article_id = articles[0]['id']
    user_id = session.get('user_id')
    existing = db_fetchone('SELECT id FROM ipb_bookmarks WHERE user_id=%s AND article_id=%s',
                           (user_id, article_id))
    if existing:
        db_execute('DELETE FROM ipb_bookmarks WHERE user_id=%s AND article_id=%s',
                   (user_id, article_id))
        bookmarked = False
    else:
        db_execute('INSERT INTO ipb_bookmarks (user_id, article_id) VALUES (%s, %s)',
                   (user_id, article_id))
        bookmarked = True
    return jsonify({'bookmarked': bookmarked})


@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    article_results = []
    drill_results = []
    if q:
        ql = q.lower()
        is_logged_in = bool(session.get('user_id'))
        all_articles = sb_get('ipb_articles', {
            'published': 'eq.true',
            'select': 'id,title,slug,excerpt,is_free',
        }) or []
        if not is_logged_in:
            all_articles = [a for a in all_articles if a.get('is_free')]
        article_results = [a for a in all_articles if
                           ql in (a.get('title') or '').lower() or
                           ql in (a.get('excerpt') or '').lower()]
        if is_logged_in:
            drills = pg_drills()
            drill_results = [d for d in drills if
                             ql in (d.get('name') or '').lower() or
                             ql in (d.get('purpose') or '').lower() or
                             ql in (d.get('points') or '').lower()]
    return render_template('search.html', q=q,
                           article_results=article_results, drill_results=drill_results)


# ── Library routes ────────────────────────────────────────────────────────────

@app.route('/library')
def library():
    is_logged_in = bool(session.get('user_id'))
    q = request.args.get('q', '').strip()
    cat = request.args.get('cat', '').strip()
    is_premium = session.get('plan') in ('premium', 'team') or session.get('is_team')

    if q or cat:
        # フィルタ・検索時: フラットリスト + ページネーション
        drills = pg_drills(q=q or None, category=cat or None) or []
        per_page = 12
        page = max(1, int(request.args.get('page', 1)))
        total = len(drills)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        drills_page = drills[(page - 1) * per_page: page * per_page]
        return render_template('library.html', drills=drills_page, q=q, cat=cat,
                               categories=DRILL_CATEGORIES, is_premium=is_premium,
                               is_logged_in=is_logged_in, drills_by_cat=None,
                               page=page, total_pages=total_pages, total=total, per_page=per_page)
    else:
        # フィルタなし: カテゴリ別セクション表示
        all_drills = pg_drills() or []
        drills_by_cat = {}
        for d in all_drills:
            c = d.get('category') or 'その他'
            drills_by_cat.setdefault(c, []).append(d)
        # DRILL_CATEGORIES の順に並べ、未定義カテゴリは末尾
        ordered = {c: drills_by_cat[c] for c in DRILL_CATEGORIES if c in drills_by_cat}
        for c, ds in drills_by_cat.items():
            if c not in ordered:
                ordered[c] = ds
        return render_template('library.html', drills=[], q=q, cat=cat,
                               categories=DRILL_CATEGORIES, is_premium=is_premium,
                               is_logged_in=is_logged_in, drills_by_cat=ordered,
                               page=1, total_pages=1, total=len(all_drills), per_page=12)


@app.route('/library/<drill_id>')
def drill_detail(drill_id):
    drills = pg_drills(drill_id=drill_id)
    if not drills:
        return redirect(url_for('library'))
    drill = drills[0]
    if not session.get('user_id'):
        return redirect(url_for('register'))
    is_premium_drill = not drill.get('is_free')
    is_premium_user = session.get('plan') in ('premium', 'team') or session.get('is_team')
    if is_premium_drill and not is_premium_user:
        return render_template('drill_upsell.html', drill=drill)

    # 動画URLをYouTube埋め込みに変換
    video_url = drill.get('video_url', '') or ''
    embed_url = ''
    if 'youtube.com/watch' in video_url:
        m = re.search(r'v=([^&]+)', video_url)
        if m:
            embed_url = f'https://www.youtube.com/embed/{m.group(1)}'
    elif 'youtu.be/' in video_url:
        vid = video_url.split('youtu.be/')[-1].split('?')[0]
        embed_url = f'https://www.youtube.com/embed/{vid}'
    elif 'youtube.com/shorts/' in video_url:
        vid = video_url.split('shorts/')[-1].split('?')[0]
        embed_url = f'https://www.youtube.com/embed/{vid}'
    elif video_url:
        embed_url = video_url
    drill['video_embed_url'] = embed_url

    # 同カテゴリの関連ドリル
    related_drills = []
    if drill.get('category'):
        all_related = pg_drills(category=drill['category'])
        related_drills = [d for d in all_related if str(d['id']) != str(drill_id)][:3]

    return render_template('drill.html', drill=drill, related_drills=related_drills)


# ── Admin routes ──────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    all_articles = sb_get('ipb_articles', {'select': 'id'}) or []
    all_members = sb_get('ipb_users', {'select': 'id'}, service=True) or []
    premium_members = sb_get('ipb_users', {'plan': 'eq.premium', 'select': 'id'}, service=True) or []
    recent_articles = sb_get('ipb_articles', {
        'order': 'created_at.desc', 'limit': 5,
        'select': 'id,title,slug,published,is_free',
    }) or []
    recent_members = sb_get('ipb_users', {
        'order': 'created_at.desc', 'limit': 5,
        'select': 'id,name,email,plan,created_at',
    }, service=True) or []

    # いいね数集計 → 人気記事TOP5
    all_likes = sb_get('ipb_likes', {'select': 'article_id'}) or []
    like_counts = {}
    for like in all_likes:
        aid = str(like.get('article_id', ''))
        like_counts[aid] = like_counts.get(aid, 0) + 1

    pub_articles = sb_get('ipb_articles', {
        'published': 'eq.true', 'select': 'id,title,slug,view_count',
    }) or []
    for a in pub_articles:
        a['like_count'] = like_counts.get(str(a.get('id', '')), 0)
    popular_articles = sorted(pub_articles, key=lambda a: a['like_count'], reverse=True)[:5]
    view_ranking = sorted(pub_articles, key=lambda a: a.get('view_count') or 0, reverse=True)[:5]

    # 最新コメント5件
    recent_comments = db_fetchall('''
        SELECT c.content, c.created_at, u.name AS user_name,
               a.title AS article_title, a.slug AS article_slug
        FROM ipb_comments c
        JOIN ipb_users u ON c.user_id = u.id
        JOIN ipb_articles a ON c.article_id = a.id
        ORDER BY c.created_at DESC LIMIT 5
    ''') or []

    total_likes = len(all_likes)
    cnt_row = db_fetchone('SELECT COUNT(*) AS cnt FROM ipb_comments')
    total_comments = cnt_row['cnt'] if cnt_row else 0

    return render_template('admin/dashboard.html',
        article_count=len(all_articles),
        member_count=len(all_members),
        premium_count=len(premium_members),
        recent_articles=recent_articles,
        recent_members=recent_members,
        popular_articles=popular_articles,
        view_ranking=view_ranking,
        recent_comments=recent_comments,
        total_likes=total_likes,
        total_comments=total_comments,
    )


@app.route('/admin/articles')
@admin_required
def admin_articles():
    articles = sb_get('ipb_articles', {'order': 'created_at.desc', 'select': 'id,title,slug,published,is_free,category_id,created_at'}) or []
    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []
    cat_map = {c['id']: c for c in categories}
    for a in articles:
        a['category'] = cat_map.get(a.get('category_id'))
    return render_template('admin/articles.html', articles=articles)


@app.route('/admin/articles/new', methods=['GET', 'POST'])
@admin_required
def admin_articles_new():
    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []
    if request.method == 'POST':
        d = _article_form_data(request.form)
        ok = db_execute(
            '''INSERT INTO ipb_articles
               (title,slug,content,excerpt,category_id,is_free,published,thumbnail_url,video_url,pdf_url,author_id,tags)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (d['title'], d['slug'], d['content'], d['excerpt'],
             d['category_id'] or None, d['is_free'], d['published'],
             d['thumbnail_url'] or None, d['video_url'] or None, d['pdf_url'] or None,
             session['user_id'], d['tags'] or None)
        )
        if ok:
            flash('記事を作成しました', 'success')
            return redirect(url_for('admin_articles'))
        flash('作成に失敗しました', 'error')
    return render_template('admin/article_form.html', article={}, categories=categories, edit=False)


@app.route('/admin/articles/<article_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_articles_edit(article_id):
    arts = sb_get('ipb_articles', {'id': f'eq.{article_id}', 'select': '*'}) or []
    if not arts:
        return redirect(url_for('admin_articles'))
    article = arts[0]
    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []

    if request.method == 'POST':
        d = _article_form_data(request.form)
        db_execute(
            '''UPDATE ipb_articles SET title=%s,slug=%s,content=%s,excerpt=%s,category_id=%s,
               is_free=%s,published=%s,thumbnail_url=%s,video_url=%s,pdf_url=%s,tags=%s
               WHERE id=%s''',
            (d['title'], d['slug'], d['content'], d['excerpt'],
             d['category_id'] or None, d['is_free'], d['published'],
             d['thumbnail_url'] or None, d['video_url'] or None, d['pdf_url'] or None,
             d['tags'] or None, article_id)
        )
        flash('記事を更新しました', 'success')
        return redirect(url_for('admin_articles'))

    return render_template('admin/article_form.html', article=article, categories=categories, edit=True)


@app.route('/admin/articles/<article_id>/delete', methods=['POST'])
@admin_required
def admin_articles_delete(article_id):
    db_execute('DELETE FROM ipb_articles WHERE id=%s', (article_id,))
    flash('記事を削除しました', 'success')
    return redirect(url_for('admin_articles'))


def _article_form_data(form):
    raw_slug = form.get('slug', '').strip().lower().replace(' ', '-')
    slug = re.sub(r'[^\w-]', '', raw_slug)
    return {
        'title':         form.get('title', '').strip(),
        'slug':          slug,
        'excerpt':       form.get('excerpt', '').strip(),
        'content':       form.get('content', ''),
        'category_id':   form.get('category_id') or None,
        'is_free':       'is_free' in form,
        'published':     'published' in form,
        'thumbnail_url': form.get('thumbnail_url', '').strip(),
        'video_url':     form.get('video_url', '').strip(),
        'pdf_url':       form.get('pdf_url', '').strip(),
        'pdf_name':      form.get('pdf_name', '').strip(),
        'tags':          form.get('tags', '').strip(),
    }



@app.route('/admin/notices')
@admin_required
def admin_notices():
    notices = db_fetchall('SELECT * FROM ipb_notices ORDER BY created_at DESC') or []
    return render_template('admin/notices.html', notices=notices)


@app.route('/admin/notices/new', methods=['POST'])
@admin_required
def admin_notices_new():
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    if title:
        db_execute('INSERT INTO ipb_notices (title, content) VALUES (%s, %s)', (title, content))
        flash('お知らせを投稿しました', 'success')
    return redirect(url_for('admin_notices'))


@app.route('/admin/notices/<notice_id>/delete', methods=['POST'])
@admin_required
def admin_notices_delete(notice_id):
    db_execute('DELETE FROM ipb_notices WHERE id=%s', (notice_id,))
    flash('削除しました', 'success')
    return redirect(url_for('admin_notices'))


@app.route('/admin/library')
@admin_required
def admin_library():
    q = request.args.get('q', '').strip()
    cat = request.args.get('cat', '').strip()
    sql = ('SELECT id,name,purpose,video_url,method,points,is_free,created_at,category '
           'FROM ipb_drills')
    conditions, params = [], []
    if q:
        conditions.append('(name ILIKE %s OR purpose ILIKE %s OR points ILIKE %s)')
        params.extend([f'%{q}%', f'%{q}%', f'%{q}%'])
    if cat:
        conditions.append('category=%s')
        params.append(cat)
    if conditions:
        sql += ' WHERE ' + ' AND '.join(conditions)
    sql += ' ORDER BY sort_order ASC, created_at DESC'
    drills = db_fetchall(sql, params) or []
    return render_template('admin/library.html', drills=drills, categories=DRILL_CATEGORIES, q=q, cat=cat)


@app.route('/admin/library/bulk-category', methods=['POST'])
@admin_required
def admin_library_bulk_category():
    ids = request.form.getlist('ids')
    cat_raw = request.form.get('category', '').strip()
    if not ids:
        flash('ドリルが選択されていません', 'error')
        return redirect(url_for('admin_library'))

    category = None if cat_raw == '__clear__' else (cat_raw or None)

    placeholders = ','.join(['%s'] * len(ids))
    ok = db_execute(f'UPDATE ipb_drills SET category=%s WHERE id IN ({placeholders})',
                    [category] + ids)
    if ok:
        flash(f'{len(ids)} 件のカテゴリを更新しました', 'success')
    else:
        flash('更新に失敗しました', 'error')
    return redirect(url_for('admin_library'))


@app.route('/admin/library/new', methods=['GET', 'POST'])
@admin_required
def admin_library_new():
    if request.method == 'POST':
        image_url = None
        f = request.files.get('image')
        if f and f.filename:
            image_url = upload_drill_image(f)
        data = {
            'name':       request.form.get('name', '').strip(),
            'purpose':    request.form.get('purpose', '').strip(),
            'video_url':  request.form.get('video_url', '').strip(),
            'method':     request.form.get('method', '').strip(),
            'points':     request.form.get('points', '').strip(),
            'is_free':    'is_free' in request.form,
            'category':   request.form.get('category', '').strip() or None,
            'difficulty': request.form.get('difficulty', '').strip() or None,
        }
        if image_url:
            data['image_url'] = image_url
        result = pg_drill_save(data)
        if result:
            flash('ドリルを追加しました', 'success')
            return redirect(url_for('admin_library'))
        flash('追加に失敗しました', 'error')
    return render_template('admin/drill_form.html', drill={}, edit=False, categories=DRILL_CATEGORIES)


@app.route('/admin/library/<drill_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_library_edit(drill_id):
    rows = pg_drills(drill_id=drill_id)
    if not rows:
        return redirect(url_for('admin_library'))
    drill = rows[0]
    if request.method == 'POST':
        data = {
            'name':       request.form.get('name', '').strip(),
            'purpose':    request.form.get('purpose', '').strip(),
            'video_url':  request.form.get('video_url', '').strip(),
            'method':     request.form.get('method', '').strip(),
            'points':     request.form.get('points', '').strip(),
            'is_free':    'is_free' in request.form,
            'category':   request.form.get('category', '').strip() or None,
            'difficulty': request.form.get('difficulty', '').strip() or None,
        }
        f = request.files.get('image')
        if f and f.filename:
            new_url = upload_drill_image(f)
            if new_url:
                data['image_url'] = new_url
        result = pg_drill_save(data, drill_id=drill_id)
        if result:
            flash('更新しました', 'success')
        else:
            flash('更新に失敗しました', 'error')
        return redirect(url_for('admin_library'))
    return render_template('admin/drill_form.html', drill=drill, edit=True, categories=DRILL_CATEGORIES)


@app.route('/admin/library/<drill_id>/delete', methods=['POST'])
@admin_required
def admin_library_delete(drill_id):
    db_execute('DELETE FROM ipb_drills WHERE id=%s', (drill_id,))
    flash('削除しました', 'success')
    return redirect(url_for('admin_library'))


@app.route('/admin/library/sort', methods=['POST'])
@admin_required
def admin_library_sort():
    data = request.get_json()
    order = data.get('order', [])
    for i, drill_id in enumerate(order):
        db_execute('UPDATE ipb_drills SET sort_order=%s WHERE id=%s', (i, drill_id))
    return jsonify({'ok': True})


@app.route('/admin/comments')
@admin_required
def admin_comments():
    comments = db_fetchall('''
        SELECT c.id, c.content, c.created_at, c.approved,
               u.name AS user_name, u.email AS user_email,
               a.title AS article_title, a.slug AS article_slug
        FROM ipb_comments c
        JOIN ipb_users u ON c.user_id = u.id
        JOIN ipb_articles a ON c.article_id = a.id
        ORDER BY c.created_at DESC
    ''') or []
    return render_template('admin/comments.html', comments=comments)


@app.route('/admin/comments/bulk', methods=['POST'])
@admin_required
def admin_comments_bulk():
    action = request.form.get('action')
    ids = request.form.getlist('comment_ids')
    if not ids:
        flash('コメントを選択してください', 'error')
        return redirect(url_for('admin_comments'))
    if action == 'delete':
        for cid in ids:
            db_execute('DELETE FROM ipb_comments WHERE id=%s', (cid,))
        flash(f'{len(ids)}件を削除しました', 'success')
    elif action == 'reject':
        for cid in ids:
            db_execute('UPDATE ipb_comments SET approved=FALSE WHERE id=%s', (cid,))
        flash(f'{len(ids)}件を非承認にしました', 'success')
    elif action == 'approve':
        for cid in ids:
            db_execute('UPDATE ipb_comments SET approved=TRUE WHERE id=%s', (cid,))
        flash(f'{len(ids)}件を承認しました', 'success')
    return redirect(url_for('admin_comments'))


@app.route('/admin/members')
@admin_required
def admin_members():
    members = sb_get('ipb_users', {'order': 'created_at.desc', 'select': '*'}, service=True) or []
    return render_template('admin/members.html', members=members)


@app.route('/admin/members/new', methods=['GET', 'POST'])
@admin_required
def admin_members_new():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        plan = request.form.get('plan', 'premium')

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        result = sb_post('ipb_users', {
            'name':          name,
            'email':         email,
            'password_hash': pw_hash,
            'role':          'member',
            'plan':          plan,
        }, service=True)
        if result:
            flash(f'{name} を追加しました', 'success')
            return redirect(url_for('admin_members'))
        flash('作成に失敗しました（メールアドレスが重複している可能性があります）', 'error')

    return render_template('admin/member_form.html')


@app.route('/admin/members/<member_id>/plan', methods=['POST'])
@admin_required
def admin_members_plan(member_id):
    new_plan = request.form.get('plan', 'free')
    if new_plan not in ('premium', 'team', 'free'):
        flash('不正なプランです', 'error')
        return redirect(url_for('admin_members'))

    result = sb_rpc('admin_set_plan', {'uid': member_id, 'new_plan': new_plan}, service=True)
    ok = result is not None
    print(f'[plan_change] member={member_id} plan={new_plan} ok={ok}', flush=True)
    if ok:
        flash('プランを変更しました', 'success')
    else:
        flash('プランの変更に失敗しました', 'error')
    return redirect(url_for('admin_members'))


@app.route('/admin/members/bulk-plan', methods=['POST'])
@admin_required
def admin_members_bulk_plan():
    member_ids = request.form.getlist('member_ids')
    new_plan = request.form.get('plan', 'free')
    if new_plan not in ('premium', 'team', 'free') or not member_ids:
        flash('メンバーを選択してください', 'error')
        return redirect(url_for('admin_members'))
    count = 0
    for mid in member_ids:
        result = sb_rpc('admin_set_plan', {'uid': mid, 'new_plan': new_plan}, service=True)
        if result is not None:
            count += 1
    flash(f'{count}名のプランを変更しました', 'success')
    return redirect(url_for('admin_members'))


@app.route('/admin/members/<member_id>/delete', methods=['POST'])
@admin_required
def admin_members_delete(member_id):
    if member_id == session.get('user_id'):
        flash('自分自身は削除できません', 'error')
        return redirect(url_for('admin_members'))
    sb_delete('ipb_users', {'id': f'eq.{member_id}'}, service=True)
    flash('メンバーを削除しました', 'success')
    return redirect(url_for('admin_members'))


# ── Email helper ──────────────────────────────────────────────────────────────

def send_email(to_email, subject, body_html):
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f'[send_email] SMTP未設定 → {to_email}: {subject}', flush=True)
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f'Ignite Potential Base <{SMTP_USER}>'
        msg['To'] = to_email
        msg.attach(MIMEText(body_html, 'html', 'utf-8'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as srv:
            srv.login(SMTP_USER, SMTP_PASSWORD)
            srv.sendmail(SMTP_USER, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f'[send_email] error: {e}', flush=True)
        return False


# ── Password reset helpers ────────────────────────────────────────────────────

def _make_reset_token(email, expires_in=3600):
    expires = int(time.time()) + expires_in
    payload = f'{email}|{expires}'.encode()
    sig = hmac.new(app.secret_key.encode(), payload, 'sha256').hexdigest()
    return base64.urlsafe_b64encode(payload).decode() + '.' + sig

def _verify_reset_token(token):
    try:
        data_b64, sig = token.rsplit('.', 1)
        payload = base64.urlsafe_b64decode(data_b64 + '==')
        expected = hmac.new(app.secret_key.encode(), payload, 'sha256').hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        email, expires_str = payload.decode().rsplit('|', 1)
        if int(time.time()) > int(expires_str):
            return None
        return email
    except Exception:
        return None


# ── Invite helpers (署名付きトークン、DB不要) ────────────────────────────────

import json as _json

def _invite_sign(payload: dict) -> str:
    data = _json.dumps(payload, separators=(',', ':')).encode()
    sig = hmac.new(app.secret_key.encode(), data, 'sha256').hexdigest()
    return base64.urlsafe_b64encode(data).decode() + '.' + sig

def _invite_verify(token: str):
    try:
        data_b64, sig = token.rsplit('.', 1)
        data = base64.urlsafe_b64decode(data_b64 + '==')
        expected = hmac.new(app.secret_key.encode(), data, 'sha256').hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = _json.loads(data)
        if payload.get('exp', 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ── Invite routes ─────────────────────────────────────────────────────────────

@app.route('/admin/invites', methods=['POST'])
@admin_required
def admin_invites_create():
    data = request.get_json() or {}
    plan = data.get('plan', 'premium')
    payload = {
        'plan': plan,
        'exp': int(time.time()) + 7 * 24 * 3600,
        'nonce': secrets.token_urlsafe(8),
    }
    token = _invite_sign(payload)
    invite_url = url_for('invite_register', token=token, _external=True)
    return jsonify({'url': invite_url})


@app.route('/invite/<path:token>', methods=['GET', 'POST'])
def invite_register(token):
    invite = _invite_verify(token)
    if not invite:
        return render_template('invite.html', error='この招待リンクは無効または期限切れです（有効期限: 7日）', token=None, invite=None)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        team_name = request.form.get('team_name', '').strip()

        if not name or not email or len(password) < 8:
            return render_template('invite.html', error='すべての項目を入力してください（パスワードは8文字以上）', token=token, invite=invite)
        if invite['plan'] == 'team' and not team_name:
            return render_template('invite.html', error='チーム名を入力してください', token=token, invite=invite)

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        invite_plan = invite['plan']

        # 直接SQLでINSERT（plan='team'をそのまま保存）
        user = db_fetchone(
            """
            INSERT INTO ipb_users (name, email, password_hash, role, plan, team_name)
            VALUES (%s, %s, %s, 'member', %s, %s)
            RETURNING *
            """,
            (name, email, pw_hash, invite_plan, team_name or None)
        )

        if not user:
            return render_template('invite.html', error='登録に失敗しました（メールアドレスが重複している可能性があります）', token=token, invite=invite)

        _set_session(user)
        flash('登録が完了しました！', 'success')
        return redirect(url_for('dashboard'))

    return render_template('invite.html', token=token, invite=invite, error=None)


# ── Password reset routes ─────────────────────────────────────────────────────

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        users = sb_get('ipb_users', {'email': f'eq.{email}', 'select': 'id,name'}, service=True)
        if users:
            token = _make_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(email, 'パスワードのリセット | Ignite Potential Base', f'''
<div style="font-family:sans-serif;max-width:500px;margin:0 auto;background:#0f1923;color:#fff;padding:2rem;border-radius:12px;">
  <h2 style="color:#f97316;margin-bottom:1rem;">パスワードリセット</h2>
  <p>こんにちは、{users[0]["name"]}さん。</p>
  <p>以下のボタンからパスワードをリセットしてください。<br>（有効期限: 1時間）</p>
  <a href="{reset_url}" style="display:inline-block;margin:1.5rem 0;background:#f97316;color:#fff;padding:.75rem 2rem;border-radius:8px;text-decoration:none;font-weight:700;">パスワードをリセットする →</a>
  <p style="color:#94a3b8;font-size:.85rem;">このメールに心当たりがない場合は無視してください。</p>
</div>''')
        flash('メールアドレスが登録されている場合、リセットリンクを送信しました。', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = _verify_reset_token(token)
    if not email:
        flash('リセットリンクが無効または期限切れです。再度お試しください。', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_pw = request.form.get('password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if new_pw != confirm_pw:
            return render_template('reset_password.html', token=token, error='パスワードが一致しません')
        if len(new_pw) < 8:
            return render_template('reset_password.html', token=token, error='パスワードは8文字以上で設定してください')
        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
        db_execute('UPDATE ipb_users SET password_hash=%s WHERE email=%s', (new_hash, email))
        flash('パスワードをリセットしました。ログインしてください。', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token, error=None)


# ── Profile route ─────────────────────────────────────────────────────────────

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'name':
            new_name = request.form.get('name', '').strip()
            if new_name:
                db_execute('UPDATE ipb_users SET name=%s WHERE id=%s', (new_name, user_id))
                session['name'] = new_name
                flash('名前を更新しました', 'success')
            else:
                flash('名前を入力してください', 'error')
        elif action == 'password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')
            if new_pw != confirm_pw:
                flash('新しいパスワードが一致しません', 'error')
            elif len(new_pw) < 8:
                flash('パスワードは8文字以上で設定してください', 'error')
            else:
                users = sb_get('ipb_users', {'id': f'eq.{user_id}', 'select': 'password_hash'}, service=True)
                if users:
                    pw_hash = users[0].get('password_hash', '')
                    valid = False
                    try:
                        valid = bool(pw_hash) and bcrypt.checkpw(current_pw.encode(), pw_hash.encode())
                    except Exception:
                        pass
                    if valid:
                        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                        db_execute('UPDATE ipb_users SET password_hash=%s WHERE id=%s', (new_hash, user_id))
                        flash('パスワードを更新しました', 'success')
                    else:
                        flash('現在のパスワードが正しくありません', 'error')
        return redirect(url_for('profile'))
    users = sb_get('ipb_users', {'id': f'eq.{user_id}', 'select': 'id,name,email,plan,role,created_at'}, service=True)
    user = users[0] if users else {}
    return render_template('profile.html', user=user)


@app.route('/account/delete', methods=['POST'])
@login_required
def account_delete():
    user_id = session['user_id']
    password = request.form.get('password', '')

    # パスワード確認
    users = sb_get('ipb_users', {'id': f'eq.{user_id}', 'select': 'password_hash,role'}, service=True)
    if not users:
        flash('アカウントが見つかりません', 'error')
        return redirect(url_for('profile'))

    user = users[0]
    # 管理者は退会不可
    if user.get('role') == 'admin':
        flash('管理者アカウントは退会できません', 'error')
        return redirect(url_for('profile'))

    pw_hash = user.get('password_hash', '')
    try:
        valid = bool(pw_hash) and bcrypt.checkpw(password.encode(), pw_hash.encode())
    except Exception:
        valid = False

    if not valid:
        flash('パスワードが正しくありません', 'error')
        return redirect(url_for('profile'))

    # 関連データを削除してからユーザーを削除
    db_execute('DELETE FROM ipb_likes WHERE user_id=%s', (user_id,))
    db_execute('DELETE FROM ipb_comments WHERE user_id=%s', (user_id,))
    db_execute('DELETE FROM ipb_bookmarks WHERE user_id=%s', (user_id,))
    db_execute('DELETE FROM ipb_users WHERE id=%s', (user_id,))

    session.clear()
    flash('退会が完了しました。ご利用ありがとうございました。', 'success')
    return redirect(url_for('index'))


# ── Admin: CSV export / Sitemap / Robots ──────────────────────────────────────

@app.route('/admin/members/export')
@admin_required
def admin_members_export():
    members = sb_get('ipb_users', {'order': 'created_at.desc', 'select': '*'}, service=True) or []
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['名前', 'メールアドレス', 'プラン', '権限', 'チーム名', '登録日'])
    for m in members:
        writer.writerow([
            m.get('name', ''), m.get('email', ''), m.get('plan', ''),
            m.get('role', ''), m.get('team_name', ''),
            (m.get('created_at') or '')[:10],
        ])
    return Response(
        '\ufeff' + si.getvalue(),  # BOM for Excel
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=members.csv'},
    )


@app.route('/sitemap.xml')
def sitemap():
    articles = sb_get('ipb_articles', {'published': 'eq.true', 'select': 'slug,created_at'}) or []
    base = request.host_url.rstrip('/')
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
             f'<url><loc>{base}/</loc></url>',
             f'<url><loc>{base}/learn</loc></url>',
             f'<url><loc>{base}/library</loc></url>']
    for a in articles:
        loc = f'{base}/learn/{a["slug"]}'
        lastmod = ''
        if a.get('created_at'):
            try:
                lastmod = f'<lastmod>{dtparser.parse(a["created_at"]).strftime("%Y-%m-%d")}</lastmod>'
            except Exception:
                pass
        lines.append(f'<url><loc>{loc}</loc>{lastmod}</url>')
    lines.append('</urlset>')
    return '\n'.join(lines), 200, {'Content-Type': 'application/xml'}


@app.route('/api/notices/latest')
def api_notices_latest():
    row = db_fetchone('SELECT id FROM ipb_notices WHERE published=TRUE ORDER BY created_at DESC LIMIT 1')
    return jsonify({'id': str(row['id']) if row else None})


@app.route('/bookmarks')
@login_required
def bookmarks():
    user_id = session['user_id']
    bm_list = db_fetchall('''
        SELECT a.id, a.title, a.slug, a.excerpt, a.thumbnail_url, b.created_at AS bookmarked_at
        FROM ipb_bookmarks b
        JOIN ipb_articles a ON b.article_id = a.id
        WHERE b.user_id = %s ORDER BY b.created_at DESC
    ''', (user_id,)) or []
    return render_template('bookmarks.html', bookmarks=bm_list)


@app.route('/history')
@login_required
def history():
    recently_viewed = session.get('recently_viewed', [])
    return render_template('history.html', recently_viewed=recently_viewed)


@app.route('/admin/debug-db')
@admin_required
def admin_debug_db():
    results = {}
    results['database_url_set'] = bool(_DB_URL)
    try:
        row = db_fetchone('SELECT COUNT(*) AS cnt FROM ipb_drills')
        results['drills_count'] = row['cnt'] if row else 'query failed'
    except Exception as e:
        results['drills_count'] = f'error: {e}'
    try:
        tables = db_fetchall("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
        results['tables'] = [t['tablename'] for t in tables]
    except Exception as e:
        results['tables'] = f'error: {e}'
    return jsonify(results)


@app.route('/robots.txt')
def robots_txt():
    content = f'User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /profile\nSitemap: {request.host_url}sitemap.xml\n'
    return content, 200, {'Content-Type': 'text/plain'}


# ── YouTube helpers ────────────────────────────────────────────────────────────

def _yt_video_id(url):
    """YouTube URLから動画IDを抽出"""
    for p in [r'youtu\.be/([^?&\s]+)', r'[?&]v=([^&\s]+)', r'/embed/([^?&\s]+)']:
        m = re.search(p, url or '')
        if m:
            return m.group(1)
    return ''

@app.template_filter('fmt_date')
def fmt_date_filter(value, fmt='%Y-%m-%d'):
    """datetime オブジェクトにも ISO 文字列にも対応する日付フォーマットフィルター。
    sb_get（Supabase REST）は文字列、db_fetchall（psycopg3）は datetime で返るため両対応。"""
    if not value:
        return '-'
    if isinstance(value, str):
        # 時刻フォーマット指定時は "2024-01-01T12:00" → "2024-01-01 12:00"
        if '%H' in fmt or '%M' in fmt:
            return value[:16].replace('T', ' ')
        return value[:10]
    return value.strftime(fmt)


@app.template_filter('yt_thumb')
def yt_thumb_filter(url):
    vid = _yt_video_id(url)
    return f'https://img.youtube.com/vi/{vid}/hqdefault.jpg' if vid else ''

# ── Programs (Roadmap) ────────────────────────────────────────────────────────

def _make_embed_url(video_url):
    """YouTube URLを埋め込みURLに変換する"""
    video_url = video_url or ''
    if 'youtube.com/watch' in video_url:
        import re as _re
        m = _re.search(r'v=([^&]+)', video_url)
        if m:
            return f'https://www.youtube.com/embed/{m.group(1)}'
    elif 'youtu.be/' in video_url:
        vid = video_url.split('youtu.be/')[-1].split('?')[0]
        return f'https://www.youtube.com/embed/{vid}'
    elif 'youtube.com/shorts/' in video_url:
        vid = video_url.split('shorts/')[-1].split('?')[0]
        return f'https://www.youtube.com/embed/{vid}'
    return video_url


@app.route('/programs')
@login_required
def programs():
    progs = db_fetchall(
        'SELECT * FROM ipb_programs WHERE is_published=TRUE ORDER BY sort_order ASC, created_at DESC'
    ) or []
    return render_template('programs.html', programs=progs)


@app.route('/programs/<program_id>')
@login_required
def program_detail(program_id):
    prog = db_fetchone('SELECT * FROM ipb_programs WHERE id=%s AND is_published=TRUE', (program_id,))
    if not prog:
        return redirect(url_for('programs'))
    steps = db_fetchall('''
        SELECT pd.step_number, pd.note,
               d.id as drill_id, d.name, d.purpose, d.video_url, d.category, d.is_free, d.difficulty
        FROM ipb_program_drills pd
        JOIN ipb_drills d ON d.id = pd.drill_id
        WHERE pd.program_id = %s
        ORDER BY pd.step_number ASC
    ''', (program_id,)) or []
    for s in steps:
        s['video_embed_url'] = _make_embed_url(s.get('video_url', ''))
    is_premium = session.get('plan') == 'premium'
    return render_template('program.html', program=prog, steps=steps, is_premium=is_premium)


@app.route('/admin/programs')
@admin_required
def admin_programs():
    progs = db_fetchall(
        'SELECT p.*, (SELECT COUNT(*) FROM ipb_program_drills WHERE program_id=p.id) as drill_count '
        'FROM ipb_programs p ORDER BY p.sort_order ASC, p.created_at DESC'
    ) or []
    return render_template('admin/programs.html', programs=progs)


@app.route('/admin/programs/new', methods=['GET', 'POST'])
@admin_required
def admin_programs_new():
    all_drills = db_fetchall(
        'SELECT id, name, category FROM ipb_drills ORDER BY sort_order ASC, created_at DESC'
    ) or []
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        target = ','.join(request.form.getlist('target_levels'))
        is_published = request.form.get('is_published') == '1'
        if not title:
            return render_template('admin/program_form.html', program={}, edit=False,
                                   all_drills=all_drills, player_levels=PLAYER_LEVELS, error='タイトルを入力してください')
        prog = db_fetchone(
            'INSERT INTO ipb_programs (title, description, target, is_published) VALUES (%s,%s,%s,%s) RETURNING *',
            (title, description, target, is_published)
        )
        if prog:
            _save_program_drills(prog['id'], request.form)
            flash('プログラムを作成しました', 'success')
            return redirect(url_for('admin_programs'))
        flash('作成に失敗しました', 'error')
    return render_template('admin/program_form.html', program={}, edit=False,
                           all_drills=all_drills, player_levels=PLAYER_LEVELS, error=None)


@app.route('/admin/programs/<program_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_programs_edit(program_id):
    prog = db_fetchone('SELECT * FROM ipb_programs WHERE id=%s', (program_id,))
    if not prog:
        return redirect(url_for('admin_programs'))
    all_drills = db_fetchall(
        'SELECT id, name, category FROM ipb_drills ORDER BY sort_order ASC, created_at DESC'
    ) or []
    existing_steps = db_fetchall(
        'SELECT pd.*, d.name as drill_name, d.category FROM ipb_program_drills pd '
        'JOIN ipb_drills d ON d.id=pd.drill_id WHERE pd.program_id=%s ORDER BY pd.step_number ASC',
        (program_id,)
    ) or []
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        target = ','.join(request.form.getlist('target_levels'))
        is_published = request.form.get('is_published') == '1'
        if not title:
            return render_template('admin/program_form.html', program=prog, edit=True,
                                   all_drills=all_drills, existing_steps=existing_steps,
                                   player_levels=PLAYER_LEVELS, error='タイトルを入力してください')
        db_execute(
            'UPDATE ipb_programs SET title=%s, description=%s, target=%s, is_published=%s WHERE id=%s',
            (title, description, target, is_published, program_id)
        )
        _save_program_drills(program_id, request.form)
        flash('更新しました', 'success')
        return redirect(url_for('admin_programs'))
    return render_template('admin/program_form.html', program=prog, edit=True,
                           all_drills=all_drills, existing_steps=existing_steps,
                           player_levels=PLAYER_LEVELS, error=None)


@app.route('/admin/programs/<program_id>/delete', methods=['POST'])
@admin_required
def admin_programs_delete(program_id):
    db_execute('DELETE FROM ipb_programs WHERE id=%s', (program_id,))
    flash('削除しました', 'success')
    return redirect(url_for('admin_programs'))


def _save_program_drills(program_id, form):
    """フォームからドリル一覧を保存（既存レコードを置き換え）"""
    db_execute('DELETE FROM ipb_program_drills WHERE program_id=%s', (program_id,))
    drill_ids = form.getlist('drill_ids')
    for i, drill_id in enumerate(drill_ids):
        note = form.get(f'note_{drill_id}', '').strip()
        db_execute(
            'INSERT INTO ipb_program_drills (program_id, drill_id, step_number, note) VALUES (%s,%s,%s,%s)',
            (program_id, drill_id, i + 1, note)
        )


@app.route('/step0')
@login_required
def step0():
    return render_template('step0.html')


# ── Q&A ───────────────────────────────────────────────────────────────────────

@app.route('/qa', methods=['GET', 'POST'])
@login_required
def qa():
    if request.method == 'POST':
        question = request.form.get('question', '').strip()
        is_anonymous = request.form.get('is_anonymous') == '1'
        if not question:
            flash('質問を入力してください', 'error')
            return redirect(url_for('qa'))
        if len(question) > 1000:
            flash('質問は1000文字以内で入力してください', 'error')
            return redirect(url_for('qa'))
        user_name = '' if is_anonymous else session.get('name', '')
        db_execute(
            'INSERT INTO ipb_questions (user_id, question, is_anonymous, user_name) VALUES (%s,%s,%s,%s)',
            (session['user_id'], question, is_anonymous, user_name)
        )
        flash('質問を送信しました！回答をお待ちください。', 'success')
        return redirect(url_for('qa'))

    answered = db_fetchall(
        "SELECT q.*, u.name as asker_name FROM ipb_questions q "
        "LEFT JOIN ipb_users u ON u.id = q.user_id "
        "WHERE q.status='answered' AND q.is_public=TRUE "
        "ORDER BY q.answered_at DESC"
    ) or []
    my_questions = db_fetchall(
        "SELECT * FROM ipb_questions WHERE user_id=%s ORDER BY created_at DESC LIMIT 10",
        (session['user_id'],)
    ) or []
    return render_template('qa.html', answered=answered, my_questions=my_questions)


@app.route('/admin/qa')
@admin_required
def admin_qa():
    pending = db_fetchall(
        "SELECT q.*, u.name as asker_name FROM ipb_questions q "
        "LEFT JOIN ipb_users u ON u.id = q.user_id "
        "WHERE q.status='pending' ORDER BY q.created_at ASC"
    ) or []
    answered = db_fetchall(
        "SELECT q.*, u.name as asker_name FROM ipb_questions q "
        "LEFT JOIN ipb_users u ON u.id = q.user_id "
        "WHERE q.status='answered' ORDER BY q.answered_at DESC LIMIT 50"
    ) or []
    return render_template('admin/qa.html', pending=pending, answered=answered)


@app.route('/admin/qa/<question_id>/answer', methods=['POST'])
@admin_required
def admin_qa_answer(question_id):
    answer = request.form.get('answer', '').strip()
    is_public = request.form.get('is_public') == '1'
    if not answer:
        flash('回答を入力してください', 'error')
        return redirect(url_for('admin_qa'))
    db_execute(
        "UPDATE ipb_questions SET answer=%s, status='answered', is_public=%s, answered_at=NOW() WHERE id=%s",
        (answer, is_public, question_id)
    )
    flash('回答しました', 'success')
    return redirect(url_for('admin_qa'))


@app.route('/admin/qa/<question_id>/delete', methods=['POST'])
@admin_required
def admin_qa_delete(question_id):
    db_execute('DELETE FROM ipb_questions WHERE id=%s', (question_id,))
    flash('削除しました', 'success')
    return redirect(url_for('admin_qa'))


@app.route('/admin/qa/<question_id>/toggle-public', methods=['POST'])
@admin_required
def admin_qa_toggle_public(question_id):
    q = db_fetchone('SELECT is_public FROM ipb_questions WHERE id=%s', (question_id,))
    if q:
        db_execute('UPDATE ipb_questions SET is_public=%s WHERE id=%s', (not q['is_public'], question_id))
    return redirect(url_for('admin_qa'))


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
