import os
import re
import secrets
import hashlib
import requests as req
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from dotenv import load_dotenv
import bcrypt
import markdown as md
from dateutil import parser as dtparser

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

NOTE_URL = os.getenv('NOTE_URL', '#')

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


def sb_patch(table, params, data, service=False):
    if not SUPABASE_URL:
        return False
    try:
        r = req.patch(f'{SUPABASE_URL}/rest/v1/{table}',
                      headers=supabase_headers(service), params=params, json=data, timeout=10)
        return r.ok
    except Exception:
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


# ── Context processor ─────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'note_url': NOTE_URL,
        'current_year': datetime.now().year,
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
                    flash('登録が完了しました！ライブラリをご覧ください。', 'success')
                    return redirect(url_for('library'))
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


def _set_session(user):
    session['user_id'] = user['id']
    session['name'] = user['name']
    session['email'] = user['email']
    session['role'] = user['role']
    session['plan'] = user['plan']


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ── Member routes ─────────────────────────────────────────────────────────────

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
        'limit': 5,
        'select': 'id,title,slug,is_free,created_at',
    }) or []
    return render_template('dashboard.html', user=user, recent_articles=recent_articles)


@app.route('/learn')
@login_required
def learn():
    cat_slug = request.args.get('category', '')
    params = {
        'published': 'eq.true',
        'order': 'created_at.desc',
        'select': 'id,title,slug,excerpt,is_free,thumbnail_url,video_url,pdf_url,category_id,created_at',
    }
    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []
    cat_map = {c['id']: c for c in categories}

    if cat_slug:
        matching = [c for c in categories if c['slug'] == cat_slug]
        if matching:
            params['category_id'] = f'eq.{matching[0]["id"]}'

    articles = sb_get('ipb_articles', params) or []
    for a in articles:
        a['category'] = cat_map.get(a.get('category_id'))

    return render_template('learn.html', articles=articles, categories=categories, active_category=cat_slug)


@app.route('/learn/<slug>')
def learn_detail(slug):
    articles = sb_get('ipb_articles', {
        'slug': f'eq.{slug}',
        'published': 'eq.true',
        'select': '*',
    })
    if not articles:
        return redirect(url_for('learn'))

    article = articles[0]

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
            'published': 'eq.true',
            'id': f'neq.{article["id"]}',
            'limit': 4,
            'select': 'id,title,slug,is_free',
        }) or []

    can_view = article.get('is_free') or session.get('plan') == 'premium'
    if not can_view:
        return redirect(url_for('register'))
    return render_template('article.html', article=article, related=related, can_view=True)


# ── Library routes ────────────────────────────────────────────────────────────

@app.route('/library')
def library():
    if not session.get('user_id'):
        return redirect(url_for('register'))

    q = request.args.get('q', '').strip()
    cat = request.args.get('cat', '').strip()
    drills = sb_rpc('get_drills_with_category', {}) or []

    if q:
        ql = q.lower()
        drills = [d for d in drills if ql in (d.get('name') or '').lower()
                  or ql in (d.get('purpose') or '').lower()
                  or ql in (d.get('points') or '').lower()]

    if cat:
        drills = [d for d in drills if d.get('category') == cat]

    is_premium = session.get('plan') == 'premium'

    if not is_premium:
        drills = [d for d in drills if d.get('is_free')]
        drills = drills[:20]

    return render_template('library.html', drills=drills, q=q, cat=cat,
                           categories=DRILL_CATEGORIES, is_premium=is_premium, is_logged_in=True)


@app.route('/library/<drill_id>')
def drill_detail(drill_id):
    drills = sb_get('ipb_drills', {'id': f'eq.{drill_id}', 'select': '*'})
    if not drills:
        return redirect(url_for('library'))
    drill = drills[0]
    if not session.get('user_id'):
        return redirect(url_for('register'))
    is_premium_drill = not drill.get('is_free')
    is_premium_user = session.get('plan') == 'premium'
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

    return render_template('drill.html', drill=drill)


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

    return render_template('admin/dashboard.html',
        article_count=len(all_articles),
        member_count=len(all_members),
        premium_count=len(premium_members),
        recent_articles=recent_articles,
        recent_members=recent_members,
    )


@app.route('/admin/articles')
@admin_required
def admin_articles():
    articles = sb_get('ipb_articles', {'order': 'created_at.desc', 'select': '*'}) or []
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
        data = _article_form_data(request.form)
        data['author_id'] = session['user_id']
        result = sb_post('ipb_articles', data)
        if result:
            flash('記事を作成しました', 'success')
            return redirect(url_for('admin_articles'))
        flash('作成に失敗しました', 'error')
    return render_template('admin/article_form.html', article={}, categories=categories, edit=False)


@app.route('/admin/articles/<article_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_articles_edit(article_id):
    articles = sb_get('ipb_articles', {'id': f'eq.{article_id}', 'select': '*'})
    if not articles:
        return redirect(url_for('admin_articles'))
    article = articles[0]
    categories = sb_get('ipb_categories', {'order': 'sort_order.asc', 'select': '*'}) or []

    if request.method == 'POST':
        data = _article_form_data(request.form)
        data['updated_at'] = datetime.utcnow().isoformat()
        sb_patch('ipb_articles', {'id': f'eq.{article_id}'}, data)
        flash('記事を更新しました', 'success')
        return redirect(url_for('admin_articles'))

    return render_template('admin/article_form.html', article=article, categories=categories, edit=True)


@app.route('/admin/articles/<article_id>/delete', methods=['POST'])
@admin_required
def admin_articles_delete(article_id):
    sb_delete('ipb_articles', {'id': f'eq.{article_id}'})
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


@app.route('/admin/library')
@admin_required
def admin_library():
    drills = sb_get('ipb_drills', {'order': 'created_at.desc', 'select': '*'}) or []
    return render_template('admin/library.html', drills=drills)


@app.route('/admin/library/new', methods=['GET', 'POST'])
@admin_required
def admin_library_new():
    if request.method == 'POST':
        cat = request.form.get('category', '').strip() or None
        data = {
            'name':      request.form.get('name', '').strip(),
            'purpose':   request.form.get('purpose', '').strip(),
            'video_url': request.form.get('video_url', '').strip(),
            'method':    request.form.get('method', '').strip(),
            'points':    request.form.get('points', '').strip(),
            'is_free':   'is_free' in request.form,
        }
        if cat:
            data['category'] = cat
        result = sb_post('ipb_drills', data, service=True)
        if result:
            if cat and isinstance(result, dict):
                sb_rpc('set_drill_category', {'p_id': result['id'], 'p_category': cat}, service=True)
            flash('ドリルを追加しました', 'success')
            return redirect(url_for('admin_library'))
        flash('追加に失敗しました', 'error')
    return render_template('admin/drill_form.html', drill={}, edit=False, categories=DRILL_CATEGORIES)


@app.route('/admin/library/<drill_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_library_edit(drill_id):
    drills = sb_get('ipb_drills', {'id': f'eq.{drill_id}', 'select': '*'})
    if not drills:
        return redirect(url_for('admin_library'))
    drill = drills[0]
    if request.method == 'POST':
        cat = request.form.get('category', '').strip() or None
        patch_data = {
            'name':      request.form.get('name', '').strip(),
            'purpose':   request.form.get('purpose', '').strip(),
            'video_url': request.form.get('video_url', '').strip(),
            'method':    request.form.get('method', '').strip(),
            'points':    request.form.get('points', '').strip(),
            'is_free':   'is_free' in request.form,
        }
        if cat:
            patch_data['category'] = cat
        sb_patch('ipb_drills', {'id': f'eq.{drill_id}'}, patch_data, service=True)
        if cat:
            sb_rpc('set_drill_category', {'p_id': drill_id, 'p_category': cat}, service=True)
        flash('更新しました', 'success')
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


@app.route('/admin/members/<member_id>/delete', methods=['POST'])
@admin_required
def admin_members_delete(member_id):
    if member_id == session.get('user_id'):
        flash('自分自身は削除できません', 'error')
        return redirect(url_for('admin_members'))
    sb_delete('ipb_users', {'id': f'eq.{member_id}'}, service=True)
    flash('メンバーを削除しました', 'success')
    return redirect(url_for('admin_members'))


# ── Invite routes ─────────────────────────────────────────────────────────────

@app.route('/admin/invites', methods=['POST'])
@admin_required
def admin_invites_create():
    data = request.get_json() or {}
    plan = data.get('plan', 'premium')
    token = secrets.token_urlsafe(24)
    result = sb_post('ipb_invites', {
        'token': token,
        'plan': plan,
        'created_by': session['user_id'],
    }, service=True)
    if result:
        invite_url = url_for('invite_register', token=token, _external=True)
        return jsonify({'url': invite_url})
    return jsonify({'error': '作成に失敗しました'}), 500


@app.route('/invite/<token>', methods=['GET', 'POST'])
def invite_register(token):
    invites = sb_get('ipb_invites', {'token': f'eq.{token}', 'used': 'eq.false', 'select': '*'}, service=True)
    if not invites:
        return render_template('invite.html', error='この招待リンクは無効または使用済みです', token=None, invite=None)

    invite = invites[0]
    expires_at = dtparser.parse(invite['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        return render_template('invite.html', error='この招待リンクは期限切れです（有効期限: 7日）', token=None, invite=None)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not name or not email or len(password) < 6:
            return render_template('invite.html', error='すべての項目を入力してください（パスワードは6文字以上）', token=token, invite=invite)

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = sb_post('ipb_users', {
            'name': name,
            'email': email,
            'password_hash': pw_hash,
            'role': 'member',
            'plan': invite['plan'],
        }, service=True)

        if not user or not isinstance(user, dict):
            return render_template('invite.html', error='登録に失敗しました（メールアドレスが重複している可能性があります）', token=token, invite=invite)

        sb_patch('ipb_invites', {'token': f'eq.{token}'}, {'used': True}, service=True)
        _set_session(user)
        flash('登録が完了しました！', 'success')
        return redirect(url_for('dashboard'))

    return render_template('invite.html', token=token, invite=invite, error=None)


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
