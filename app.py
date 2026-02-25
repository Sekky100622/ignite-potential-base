import os
import hashlib
import json
from functools import wraps
from datetime import datetime

import requests
import stripe
import markdown as md
from flask import (Flask, render_template, request, session, redirect,
                   url_for, flash, jsonify)
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

# Stripe setup
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', '')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID', '')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', '')
STRIPE_READY = not (stripe.api_key.startswith('sk_test_placeholder') or stripe.api_key == '')

SUPABASE_URL = os.getenv('SUPABASE_URL', '')
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY', '')

# ── DB helpers ────────────────────────────────────────────────────────────────

def sb_headers():
    return {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
    }


def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_user(user_id: str):
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_users',
        headers=sb_headers(),
        params={'id': f'eq.{user_id}', 'limit': '1'},
    )
    data = r.json()
    return data[0] if data else None


def get_categories():
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_categories',
        headers=sb_headers(),
        params={'order': 'sort_order.asc'},
    )
    return r.json() if r.ok else []


# ── Auth decorators ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('ログインが必要です。', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def premium_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('ログインが必要です。', 'warning')
            return redirect(url_for('login'))
        if session.get('plan') != 'premium':
            flash('プレミアムプランへのアップグレードが必要です。', 'info')
            return redirect(url_for('subscribe'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('ログインが必要です。', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('管理者権限が必要です。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# ── Context processor ─────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'stripe_ready': STRIPE_READY,
        'stripe_publishable_key': STRIPE_PUBLISHABLE_KEY,
        'current_year': datetime.now().year,
    }


# ── Public routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    # Fetch a few published free articles for the landing page
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'published': 'eq.true', 'is_free': 'eq.true',
                'limit': '3', 'order': 'created_at.desc',
                'select': 'id,title,slug,excerpt,category_id,created_at'},
    )
    sample_articles = r.json() if r.ok else []
    return render_template('index.html', sample_articles=sample_articles)


# ── Articles ──────────────────────────────────────────────────────────────────

@app.route('/articles')
def articles():
    category_filter = request.args.get('category', '')
    params = {
        'published': 'eq.true',
        'order': 'created_at.desc',
        'select': 'id,title,slug,excerpt,category_id,is_free,thumbnail_url,created_at',
    }
    if category_filter:
        # Look up category id
        cr = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_categories',
            headers=sb_headers(),
            params={'slug': f'eq.{category_filter}', 'limit': '1'},
        )
        cats = cr.json()
        if cats:
            params['category_id'] = f'eq.{cats[0]["id"]}'

    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params=params,
    )
    article_list = r.json() if r.ok else []

    # Fetch categories for filter tabs
    categories = get_categories()

    # Build category name lookup
    cat_map = {c['id']: c for c in categories}
    for a in article_list:
        a['category'] = cat_map.get(a.get('category_id'), {})

    return render_template('articles.html',
                           articles=article_list,
                           categories=categories,
                           active_category=category_filter)


@app.route('/articles/<slug>')
def article_detail(slug):
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'slug': f'eq.{slug}', 'published': 'eq.true', 'limit': '1',
                'select': '*'},
    )
    data = r.json()
    if not data:
        flash('記事が見つかりません。', 'warning')
        return redirect(url_for('articles'))

    article = data[0]

    # Check premium access
    is_premium_content = not article.get('is_free', False)
    user_is_premium = session.get('plan') == 'premium'
    can_view = (not is_premium_content) or user_is_premium

    # Render markdown content
    if can_view:
        article['content_html'] = md.markdown(article.get('content', ''),
                                               extensions=['fenced_code', 'tables'])
    else:
        # Show first portion only as teaser
        content = article.get('content', '')
        teaser = '\n'.join(content.split('\n')[:8])
        article['content_html'] = md.markdown(teaser)

    # Fetch category
    if article.get('category_id'):
        cr = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_categories',
            headers=sb_headers(),
            params={'id': f'eq.{article["category_id"]}', 'limit': '1'},
        )
        cats = cr.json()
        article['category'] = cats[0] if cats else {}

    # Related articles
    related = []
    if article.get('category_id'):
        rr = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_articles',
            headers=sb_headers(),
            params={
                'category_id': f'eq.{article["category_id"]}',
                'published': 'eq.true',
                'slug': f'neq.{slug}',
                'limit': '3',
                'select': 'id,title,slug,is_free,thumbnail_url',
            },
        )
        related = rr.json() if rr.ok else []

    return render_template('article.html',
                           article=article,
                           can_view=can_view,
                           is_premium_content=is_premium_content,
                           related=related)


# ── Videos ────────────────────────────────────────────────────────────────────

@app.route('/videos')
def videos():
    category_filter = request.args.get('category', '')
    params = {
        'published': 'eq.true',
        'order': 'created_at.desc',
        'select': 'id,title,description,youtube_url,category_id,is_free,thumbnail_url,created_at',
    }
    if category_filter:
        cr = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_categories',
            headers=sb_headers(),
            params={'slug': f'eq.{category_filter}', 'limit': '1'},
        )
        cats = cr.json()
        if cats:
            params['category_id'] = f'eq.{cats[0]["id"]}'

    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_videos',
        headers=sb_headers(),
        params=params,
    )
    video_list = r.json() if r.ok else []
    categories = get_categories()
    cat_map = {c['id']: c for c in categories}
    for v in video_list:
        v['category'] = cat_map.get(v.get('category_id'), {})

    return render_template('videos.html',
                           videos=video_list,
                           categories=categories,
                           active_category=category_filter)


@app.route('/videos/<video_id>')
def video_detail(video_id):
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_videos',
        headers=sb_headers(),
        params={'id': f'eq.{video_id}', 'published': 'eq.true', 'limit': '1'},
    )
    data = r.json()
    if not data:
        flash('動画が見つかりません。', 'warning')
        return redirect(url_for('videos'))

    video = data[0]
    is_premium_content = not video.get('is_free', False)
    user_is_premium = session.get('plan') == 'premium'
    can_view = (not is_premium_content) or user_is_premium

    # Convert YouTube URL to embed URL
    yt_url = video.get('youtube_url', '')
    embed_url = ''
    if 'youtube.com/watch?v=' in yt_url:
        vid_id = yt_url.split('v=')[1].split('&')[0]
        embed_url = f'https://www.youtube.com/embed/{vid_id}'
    elif 'youtu.be/' in yt_url:
        vid_id = yt_url.split('youtu.be/')[1].split('?')[0]
        embed_url = f'https://www.youtube.com/embed/{vid_id}'

    if video.get('category_id'):
        cr = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_categories',
            headers=sb_headers(),
            params={'id': f'eq.{video["category_id"]}', 'limit': '1'},
        )
        cats = cr.json()
        video['category'] = cats[0] if cats else {}

    return render_template('video.html',
                           video=video,
                           embed_url=embed_url,
                           can_view=can_view,
                           is_premium_content=is_premium_content)


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        r = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_users',
            headers=sb_headers(),
            params={'email': f'eq.{email}', 'limit': '1'},
        )
        users = r.json()
        if users and users[0]['password_hash'] == hash_pw(password):
            u = users[0]
            session['user_id'] = u['id']
            session['email'] = u['email']
            session['name'] = u['name']
            session['role'] = u['role']
            session['plan'] = u['plan']
            flash(f'おかえりなさい、{u["name"]}さん！', 'success')
            next_url = request.args.get('next', url_for('dashboard'))
            return redirect(next_url)
        else:
            flash('メールアドレスまたはパスワードが正しくありません。', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not name or not email or not password:
            flash('すべての項目を入力してください。', 'danger')
            return render_template('register.html')

        if password != confirm:
            flash('パスワードが一致しません。', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('パスワードは6文字以上で入力してください。', 'danger')
            return render_template('register.html')

        # Check if email exists
        cr = requests.get(
            f'{SUPABASE_URL}/rest/v1/ipb_users',
            headers=sb_headers(),
            params={'email': f'eq.{email}', 'limit': '1'},
        )
        if cr.json():
            flash('このメールアドレスは既に登録されています。', 'danger')
            return render_template('register.html')

        # Create user
        payload = {
            'email': email,
            'name': name,
            'password_hash': hash_pw(password),
            'role': 'member',
            'plan': 'free',
        }
        headers = sb_headers()
        headers['Prefer'] = 'return=representation'
        r = requests.post(
            f'{SUPABASE_URL}/rest/v1/ipb_users',
            headers=headers,
            json=payload,
        )
        if r.ok:
            u = r.json()[0]
            session['user_id'] = u['id']
            session['email'] = u['email']
            session['name'] = u['name']
            session['role'] = u['role']
            session['plan'] = u['plan']
            flash('登録が完了しました！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('登録に失敗しました。もう一度お試しください。', 'danger')

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Sync session plan
    session['plan'] = user['plan']

    # Recent articles
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'published': 'eq.true', 'limit': '5', 'order': 'created_at.desc',
                'select': 'id,title,slug,is_free,created_at'},
    )
    recent_articles = r.json() if r.ok else []

    return render_template('dashboard.html', user=user, recent_articles=recent_articles)


# ── Subscription ──────────────────────────────────────────────────────────────

@app.route('/subscribe')
def subscribe():
    return render_template('subscribe.html',
                           stripe_ready=STRIPE_READY,
                           stripe_publishable_key=STRIPE_PUBLISHABLE_KEY)


@app.route('/subscribe/checkout', methods=['POST'])
@login_required
def subscribe_checkout():
    if not STRIPE_READY:
        flash('決済システムは現在準備中です。', 'info')
        return redirect(url_for('subscribe'))

    user = get_user(session['user_id'])

    try:
        # Create or retrieve Stripe customer
        customer_id = user.get('stripe_customer_id')
        if not customer_id:
            customer = stripe.Customer.create(
                email=user['email'],
                name=user['name'],
                metadata={'user_id': user['id']},
            )
            customer_id = customer.id
            requests.patch(
                f'{SUPABASE_URL}/rest/v1/ipb_users',
                headers=sb_headers(),
                params={'id': f'eq.{user["id"]}'},
                json={'stripe_customer_id': customer_id},
            )

        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('subscribe_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('subscribe_cancel', _external=True),
        )
        return redirect(checkout_session.url, code=303)
    except stripe.error.StripeError as e:
        flash(f'決済処理でエラーが発生しました: {str(e)}', 'danger')
        return redirect(url_for('subscribe'))


@app.route('/subscribe/success')
def subscribe_success():
    return render_template('subscribe_success.html')


@app.route('/subscribe/cancel')
def subscribe_cancel():
    flash('サブスクリプションのお申し込みをキャンセルしました。', 'info')
    return redirect(url_for('subscribe'))


@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')

    if not STRIPE_READY:
        return jsonify({'status': 'skipped'}), 200

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({'error': 'Invalid payload or signature'}), 400

    if event['type'] == 'checkout.session.completed':
        sess = event['data']['object']
        customer_id = sess.get('customer')
        subscription_id = sess.get('subscription')
        if customer_id:
            requests.patch(
                f'{SUPABASE_URL}/rest/v1/ipb_users',
                headers=sb_headers(),
                params={'stripe_customer_id': f'eq.{customer_id}'},
                json={'plan': 'premium', 'stripe_subscription_id': subscription_id},
            )

    elif event['type'] == 'customer.subscription.deleted':
        sub = event['data']['object']
        customer_id = sub.get('customer')
        if customer_id:
            requests.patch(
                f'{SUPABASE_URL}/rest/v1/ipb_users',
                headers=sb_headers(),
                params={'stripe_customer_id': f'eq.{customer_id}'},
                json={'plan': 'free', 'stripe_subscription_id': None},
            )

    return jsonify({'status': 'ok'}), 200


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Count articles
    ar = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers={**sb_headers(), 'Prefer': 'count=exact'},
        params={'select': 'id'},
    )
    article_count = int(ar.headers.get('Content-Range', '0/0').split('/')[-1]) if ar.ok else 0

    # Count members
    mr = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_users',
        headers={**sb_headers(), 'Prefer': 'count=exact'},
        params={'select': 'id'},
    )
    member_count = int(mr.headers.get('Content-Range', '0/0').split('/')[-1]) if mr.ok else 0

    # Count premium members
    pr = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_users',
        headers={**sb_headers(), 'Prefer': 'count=exact'},
        params={'select': 'id', 'plan': 'eq.premium'},
    )
    premium_count = int(pr.headers.get('Content-Range', '0/0').split('/')[-1]) if pr.ok else 0

    # Recent registrations
    rr = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_users',
        headers=sb_headers(),
        params={'order': 'created_at.desc', 'limit': '5',
                'select': 'id,name,email,plan,created_at'},
    )
    recent_members = rr.json() if rr.ok else []

    # Recent articles
    ra = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'order': 'created_at.desc', 'limit': '5',
                'select': 'id,title,slug,is_free,published,created_at'},
    )
    recent_articles = ra.json() if ra.ok else []

    return render_template('admin/dashboard.html',
                           article_count=article_count,
                           member_count=member_count,
                           premium_count=premium_count,
                           recent_members=recent_members,
                           recent_articles=recent_articles)


@app.route('/admin/articles')
@admin_required
def admin_articles():
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'order': 'created_at.desc',
                'select': 'id,title,slug,is_free,published,created_at,category_id'},
    )
    article_list = r.json() if r.ok else []
    categories = get_categories()
    cat_map = {c['id']: c for c in categories}
    for a in article_list:
        a['category'] = cat_map.get(a.get('category_id'), {})
    return render_template('admin/articles.html', articles=article_list)


@app.route('/admin/articles/new', methods=['GET', 'POST'])
@admin_required
def admin_articles_new():
    categories = get_categories()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        slug = request.form.get('slug', '').strip()
        content = request.form.get('content', '').strip()
        excerpt = request.form.get('excerpt', '').strip()
        category_id = request.form.get('category_id', '') or None
        is_free = request.form.get('is_free') == 'on'
        thumbnail_url = request.form.get('thumbnail_url', '').strip()
        published = request.form.get('published') == 'on'

        if not title or not slug:
            flash('タイトルとスラッグは必須です。', 'danger')
            return render_template('admin/article_form.html',
                                   categories=categories, article=request.form)

        payload = {
            'title': title, 'slug': slug, 'content': content,
            'excerpt': excerpt, 'category_id': category_id,
            'is_free': is_free, 'thumbnail_url': thumbnail_url,
            'published': published, 'author_id': session['user_id'],
        }
        headers = sb_headers()
        headers['Prefer'] = 'return=representation'
        r = requests.post(
            f'{SUPABASE_URL}/rest/v1/ipb_articles',
            headers=headers,
            json=payload,
        )
        if r.ok:
            flash('記事を作成しました。', 'success')
            return redirect(url_for('admin_articles'))
        else:
            flash(f'エラーが発生しました: {r.text}', 'danger')

    return render_template('admin/article_form.html',
                           categories=categories, article={}, edit=False)


@app.route('/admin/articles/<article_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_articles_edit(article_id):
    categories = get_categories()

    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'id': f'eq.{article_id}', 'limit': '1'},
    )
    data = r.json()
    if not data:
        flash('記事が見つかりません。', 'warning')
        return redirect(url_for('admin_articles'))

    article = data[0]

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        slug = request.form.get('slug', '').strip()
        content = request.form.get('content', '').strip()
        excerpt = request.form.get('excerpt', '').strip()
        category_id = request.form.get('category_id', '') or None
        is_free = request.form.get('is_free') == 'on'
        thumbnail_url = request.form.get('thumbnail_url', '').strip()
        published = request.form.get('published') == 'on'

        payload = {
            'title': title, 'slug': slug, 'content': content,
            'excerpt': excerpt, 'category_id': category_id,
            'is_free': is_free, 'thumbnail_url': thumbnail_url,
            'published': published,
        }
        pr = requests.patch(
            f'{SUPABASE_URL}/rest/v1/ipb_articles',
            headers=sb_headers(),
            params={'id': f'eq.{article_id}'},
            json=payload,
        )
        if pr.ok:
            flash('記事を更新しました。', 'success')
            return redirect(url_for('admin_articles'))
        else:
            flash(f'エラーが発生しました: {pr.text}', 'danger')

    return render_template('admin/article_form.html',
                           categories=categories, article=article, edit=True)


@app.route('/admin/articles/<article_id>/delete', methods=['POST'])
@admin_required
def admin_articles_delete(article_id):
    r = requests.delete(
        f'{SUPABASE_URL}/rest/v1/ipb_articles',
        headers=sb_headers(),
        params={'id': f'eq.{article_id}'},
    )
    if r.ok:
        flash('記事を削除しました。', 'success')
    else:
        flash('削除に失敗しました。', 'danger')
    return redirect(url_for('admin_articles'))


@app.route('/admin/videos/new', methods=['GET', 'POST'])
@admin_required
def admin_videos_new():
    categories = get_categories()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        youtube_url = request.form.get('youtube_url', '').strip()
        category_id = request.form.get('category_id', '') or None
        is_free = request.form.get('is_free') == 'on'
        thumbnail_url = request.form.get('thumbnail_url', '').strip()
        published = request.form.get('published') == 'on'

        if not title:
            flash('タイトルは必須です。', 'danger')
            return render_template('admin/video_form.html',
                                   categories=categories, video={})

        payload = {
            'title': title, 'description': description,
            'youtube_url': youtube_url, 'category_id': category_id,
            'is_free': is_free, 'thumbnail_url': thumbnail_url,
            'published': published, 'author_id': session['user_id'],
        }
        headers = sb_headers()
        headers['Prefer'] = 'return=representation'
        r = requests.post(
            f'{SUPABASE_URL}/rest/v1/ipb_videos',
            headers=headers,
            json=payload,
        )
        if r.ok:
            flash('動画を追加しました。', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(f'エラーが発生しました: {r.text}', 'danger')

    return render_template('admin/video_form.html', categories=categories, video={})


@app.route('/admin/members')
@admin_required
def admin_members():
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/ipb_users',
        headers=sb_headers(),
        params={'order': 'created_at.desc',
                'select': 'id,name,email,role,plan,created_at'},
    )
    members = r.json() if r.ok else []
    return render_template('admin/members.html', members=members)


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(debug=True, port=port)
