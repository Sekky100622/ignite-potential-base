-- Run this in Supabase SQL Editor

CREATE TABLE IF NOT EXISTS ipb_users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'member' CHECK (role IN ('member', 'admin')),
  plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'premium')),
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  subscription_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ipb_categories (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  sort_order INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ipb_articles (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  excerpt TEXT DEFAULT '',
  category_id UUID REFERENCES ipb_categories(id),
  is_free BOOLEAN DEFAULT FALSE,
  thumbnail_url TEXT DEFAULT '',
  published BOOLEAN DEFAULT FALSE,
  author_id UUID REFERENCES ipb_users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ipb_videos (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  youtube_url TEXT DEFAULT '',
  category_id UUID REFERENCES ipb_categories(id),
  is_free BOOLEAN DEFAULT FALSE,
  thumbnail_url TEXT DEFAULT '',
  published BOOLEAN DEFAULT FALSE,
  author_id UUID REFERENCES ipb_users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert categories
INSERT INTO ipb_categories (name, slug, sort_order) VALUES
  ('技術', 'skill', 1),
  ('トレーニング', 'training', 2),
  ('メンタル', 'mental', 3),
  ('栄養', 'nutrition', 4),
  ('コンディション', 'condition', 5),
  ('指導理論', 'coaching', 6)
ON CONFLICT (slug) DO NOTHING;

-- Insert admin user (password: admin123 - change this!)
INSERT INTO ipb_users (email, name, password_hash, role, plan) VALUES (
  'coach@ignite.jp',
  '積山大輝',
  encode(sha256('admin123'::bytea), 'hex'),
  'admin',
  'premium'
) ON CONFLICT (email) DO NOTHING;

-- Insert sample free article
INSERT INTO ipb_articles (title, slug, content, excerpt, is_free, published, category_id, author_id)
SELECT 
  '野球パフォーマンス向上の3つの柱',
  'three-pillars-of-baseball-performance',
  '## はじめに

野球で結果を出すためには、技術だけでなく、体力・メンタル・栄養など多くの要素が絡み合っています。

## 1. 技術の習得

正しい動作パターンを繰り返すことで、脳と体に動きを刻み込みます。

## 2. フィジカルの強化

筋力・柔軟性・スピードをバランスよく鍛えることが重要です。

## 3. リカバリーの管理

練習の質を上げるためには、休養と栄養管理が欠かせません。

## まとめ

これらの3つの柱をバランスよく取り組むことで、野球パフォーマンスは大きく向上します。',
  'このサイトで学べる野球パフォーマンス向上の基礎概念を解説します。',
  TRUE,
  TRUE,
  c.id,
  u.id
FROM ipb_categories c, ipb_users u
WHERE c.slug = 'skill' AND u.role = 'admin'
LIMIT 1;
