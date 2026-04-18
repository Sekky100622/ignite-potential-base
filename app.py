import os
import re
import base64
import secrets
import hashlib
import requests as req
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse, quote_plus
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
import bcrypt
import markdown as md
from dateutil import parser as dtparser
import psycopg
from psycopg.rows import dict_row

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

NOTE_URL = os.getenv('NOTE_URL', '#')
OG_IMAGE_URL = os.getenv('OG_IMAGE_URL', '')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')

DRILL_CATEGORIES = [
    'リセット',
    'コレクティブ',
    'モーターコントロール',
    'ベーシックムーブメント',
    'ウエイトトレーニング',
    'プライオメトリクス',
    'スキル（アトラクターベース）',
]
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')

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

_DRILL_SELECT = 'id,name,purpose,video_url,method,points,is_free,created_at,category'


def pg_drills(**filters):
    """Get drills via Supabase REST API."""
    params = {'select': _DRILL_SELECT, 'order': 'created_at.desc'}
    params.update(filters)
    return sb_get('ipb_drills', params=params, service=True)


def pg_drill_save(data, drill_id=None):
    """Insert or update a drill via Supabase REST API."""
    if drill_id:
        ok = sb_patch('ipb_drills', {'id': f'eq.{drill_id}'}, data, service=True)
        if not ok:
            return None
        rows = pg_drills(**{'id': f'eq.{drill_id}'})
        return rows[0] if rows else None
    else:
        return sb_post('ipb_drills', data, service=True)


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

ensure_tables()


# ── Context processor ─────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'note_url': NOTE_URL,
        'og_image_url': OG_IMAGE_URL,
        'current_year': datetime.now().year,
        'google_client_id': GOOGLE_CLIENT_ID,
    }


# ── Public routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    free_articles = sb_get('ipb_articles', {
        'is_free': 'eq.true',
        'published': 'eq.true',
        'order': 'created_at.desc',
        'limit': 3,
        'select': 'id,title,slug,excerpt,created_at',
    }) or []
    return render_template('index.html', free_articles=free_articles)


@app.route('/register', methods=['GET', 'POST'])
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

    return render_template('dashboard.html', user=user,
                           recent_articles=recent_articles,
                           drill_count=len(available_drills),
                           recent_drills=recent_drills,
                           cat_counts=cat_counts,
                           is_premium=is_premium,
                           notices=notices,
                           bookmarks=bookmarks)


@app.route('/learn')
def learn():
    is_logged_in = bool(session.get('user_id'))
    cat_slug = request.args.get('category', '')
    q = request.args.get('q', '').strip()
    sort = request.args.get('sort', 'newest')

    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []
    cat_map = {c['id']: c for c in categories}

    all_articles = sb_get('ipb_articles', {
        'order': 'created_at.desc',
        'select': 'id,title,slug,excerpt,is_free,thumbnail_url,video_url,pdf_url,category_id,created_at,published',
    }) or []

    articles = [a for a in all_articles if a.get('published')]
    # 未ログインは無料記事のみ
    if not is_logged_in:
        articles = [a for a in articles if a.get('is_free')]

    if cat_slug:
        matching = [c for c in categories if c['slug'] == cat_slug]
        if matching:
            cat_id = matching[0]['id']
            articles = [a for a in articles if str(a.get('category_id')) == str(cat_id)]
        else:
            articles = []

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

    return render_template('learn.html', articles=articles, categories=categories,
                           active_category=cat_slug, q=q, sort=sort, is_logged_in=is_logged_in)


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

    # render markdown
    article['content_html'] = md.markdown(
        article.get('content', ''),
        extensions=['fenced_code', 'tables'],
    )

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
        WHERE c.article_id = %s
        ORDER BY c.created_at ASC
    ''', (article_id,))

    return render_template('article.html', article=article, related=related, can_view=True,
                           like_count=like_count, user_liked=user_liked,
                           user_bookmarked=user_bookmarked,
                           comments=comments or [], user_id=user_id)


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


# ── Library routes ────────────────────────────────────────────────────────────

@app.route('/library')
def library():
    if not session.get('user_id'):
        return redirect(url_for('register'))

    q = request.args.get('q', '').strip()
    cat = request.args.get('cat', '').strip()
    drills = pg_drills()

    if q:
        ql = q.lower()
        drills = [d for d in drills if ql in (d.get('name') or '').lower()
                  or ql in (d.get('purpose') or '').lower()
                  or ql in (d.get('points') or '').lower()]

    if cat:
        drills = [d for d in drills if d.get('category') == cat]

    is_premium = session.get('plan') in ('premium', 'team') or session.get('is_team')

    # 全ドリルを表示（プレミアム限定はロック表示）
    return render_template('library.html', drills=drills, q=q, cat=cat,
                           categories=DRILL_CATEGORIES, is_premium=is_premium, is_logged_in=True)


@app.route('/library/<drill_id>')
def drill_detail(drill_id):
    drills = pg_drills(**{'id': f'eq.{drill_id}'})
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
        related_drills = pg_drills(**{'category': f'eq.{drill["category"]}', 'id': f'neq.{drill_id}', 'limit': '3'})

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
        'published': 'eq.true', 'select': 'id,title,slug',
    }) or []
    for a in pub_articles:
        a['like_count'] = like_counts.get(str(a.get('id', '')), 0)
    popular_articles = sorted(pub_articles, key=lambda a: a['like_count'], reverse=True)[:5]

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
               (title,slug,content,excerpt,category_id,is_free,published,thumbnail_url,video_url,pdf_url,author_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (d['title'], d['slug'], d['content'], d['excerpt'],
             d['category_id'] or None, d['is_free'], d['published'],
             d['thumbnail_url'] or None, d['video_url'] or None, d['pdf_url'] or None,
             session['user_id'])
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
               is_free=%s,published=%s,thumbnail_url=%s,video_url=%s,pdf_url=%s
               WHERE id=%s''',
            (d['title'], d['slug'], d['content'], d['excerpt'],
             d['category_id'] or None, d['is_free'], d['published'],
             d['thumbnail_url'] or None, d['video_url'] or None, d['pdf_url'] or None,
             article_id)
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
    drills = pg_drills()
    return render_template('admin/library.html', drills=drills, categories=DRILL_CATEGORIES)


@app.route('/admin/library/bulk-category', methods=['POST'])
@admin_required
def admin_library_bulk_category():
    ids = request.form.getlist('ids')
    cat_raw = request.form.get('category', '').strip()
    if not ids:
        flash('ドリルが選択されていません', 'error')
        return redirect(url_for('admin_library'))

    category = None if cat_raw == '__clear__' else (cat_raw or None)

    ok = sb_patch('ipb_drills', {'id': f'in.({",".join(ids)})'}, {'category': category}, service=True)
    if ok:
        flash(f'{len(ids)} 件のカテゴリを更新しました', 'success')
    else:
        flash('更新に失敗しました', 'error')
    return redirect(url_for('admin_library'))


@app.route('/admin/library/new', methods=['GET', 'POST'])
@admin_required
def admin_library_new():
    if request.method == 'POST':
        data = {
            'name':      request.form.get('name', '').strip(),
            'purpose':   request.form.get('purpose', '').strip(),
            'video_url': request.form.get('video_url', '').strip(),
            'method':    request.form.get('method', '').strip(),
            'points':    request.form.get('points', '').strip(),
            'is_free':   'is_free' in request.form,
            'category':  request.form.get('category', '').strip() or None,
        }
        result = pg_drill_save(data)
        if result:
            flash('ドリルを追加しました', 'success')
            return redirect(url_for('admin_library'))
        flash('追加に失敗しました', 'error')
    return render_template('admin/drill_form.html', drill={}, edit=False, categories=DRILL_CATEGORIES)


@app.route('/admin/library/<drill_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_library_edit(drill_id):
    rows = pg_drills(**{'id': f'eq.{drill_id}'})
    if not rows:
        return redirect(url_for('admin_library'))
    drill = rows[0]
    if request.method == 'POST':
        data = {
            'name':      request.form.get('name', '').strip(),
            'purpose':   request.form.get('purpose', '').strip(),
            'video_url': request.form.get('video_url', '').strip(),
            'method':    request.form.get('method', '').strip(),
            'points':    request.form.get('points', '').strip(),
            'is_free':   'is_free' in request.form,
            'category':  request.form.get('category', '').strip() or None,
        }
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
    sb_delete('ipb_drills', {'id': f'eq.{drill_id}'}, service=True)
    flash('削除しました', 'success')
    return redirect(url_for('admin_library'))


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


# ── Invite helpers (署名付きトークン、DB不要) ────────────────────────────────

import hmac as _hmac
import json as _json
import time as _time

def _invite_sign(payload: dict) -> str:
    data = _json.dumps(payload, separators=(',', ':')).encode()
    sig = _hmac.new(app.secret_key.encode(), data, 'sha256').hexdigest()
    return base64.urlsafe_b64encode(data).decode() + '.' + sig

def _invite_verify(token: str):
    try:
        data_b64, sig = token.rsplit('.', 1)
        data = base64.urlsafe_b64decode(data_b64 + '==')
        expected = _hmac.new(app.secret_key.encode(), data, 'sha256').hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        payload = _json.loads(data)
        if payload.get('exp', 0) < _time.time():
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
        'exp': int(_time.time()) + 7 * 24 * 3600,
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

        if not name or not email or len(password) < 6:
            return render_template('invite.html', error='すべての項目を入力してください（パスワードは6文字以上）', token=token, invite=invite)
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


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
