import os
import re
import hashlib
import requests as req
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, flash
from dotenv import load_dotenv
import bcrypt
import markdown as md

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

NOTE_URL = os.getenv('NOTE_URL', '#')
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
        return None
    try:
        r = req.post(f'{SUPABASE_URL}/rest/v1/{table}',
                     headers=supabase_headers(service), json=data, timeout=10)
        result = r.json()
        return result[0] if (r.ok and isinstance(result, list) and result) else None
    except Exception:
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
    return render_template('index.html')


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
@login_required
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

    return render_template('article.html', article=article, related=related, can_view=True)


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


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
