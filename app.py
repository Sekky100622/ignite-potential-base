import os
import re
import base64
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
OG_IMAGE_URL = os.getenv('OG_IMAGE_URL', '')

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
        print(f'[sb_patch] {table} params={params} status={r.status_code} body={r.text[:200]}', flush=True)
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


# ── Context processor ─────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'note_url': NOTE_URL,
        'og_image_url': OG_IMAGE_URL,
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
        'limit': 3,
        'select': 'id,title,slug,is_free,created_at',
    }) or []

    all_drills = pg_drills()
    is_premium = user['plan'] in ('premium', 'team')
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

    return render_template('dashboard.html', user=user,
                           recent_articles=recent_articles,
                           drill_count=len(available_drills),
                           recent_drills=recent_drills,
                           cat_counts=cat_counts,
                           is_premium=is_premium)


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

    can_view = article.get('is_free') or session.get('plan') in ('premium', 'team')
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
    drills = pg_drills()

    if q:
        ql = q.lower()
        drills = [d for d in drills if ql in (d.get('name') or '').lower()
                  or ql in (d.get('purpose') or '').lower()
                  or ql in (d.get('points') or '').lower()]

    if cat:
        drills = [d for d in drills if d.get('category') == cat]

    is_premium = session.get('plan') in ('premium', 'team')

    if not is_premium:
        drills = [d for d in drills if d.get('is_free')]
        drills = drills[:20]

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
    is_premium_user = session.get('plan') in ('premium', 'team')
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
    try:
        r = req.patch(
            f'{SUPABASE_URL}/rest/v1/ipb_users',
            headers={'apikey': SUPABASE_SERVICE_KEY, 'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}', 'Content-Type': 'application/json'},
            params={'id': f'eq.{member_id}'},
            json={'plan': new_plan},
            timeout=10,
        )
        print(f'[plan_change] member={member_id} plan={new_plan} status={r.status_code} body={r.text[:200]}', flush=True)
        ok = r.ok
    except Exception as e:
        print(f'[plan_change] exception: {e}', flush=True)
        ok = False
    if ok:
        flash('プランを変更しました', 'success')
    else:
        flash('プランの変更に失敗しました', 'error')
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
        user_data = {
            'name': name,
            'email': email,
            'password_hash': pw_hash,
            'role': 'member',
            'plan': invite['plan'],
        }
        if team_name:
            user_data['team_name'] = team_name
        user = sb_post('ipb_users', user_data, service=True)

        if not user or not isinstance(user, dict):
            return render_template('invite.html', error='登録に失敗しました（メールアドレスが重複している可能性があります）', token=token, invite=invite)

        _set_session(user)
        flash('登録が完了しました！', 'success')
        return redirect(url_for('dashboard'))

    return render_template('invite.html', token=token, invite=invite, error=None)


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
