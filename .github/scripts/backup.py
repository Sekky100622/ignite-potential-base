import json, os, sys
from datetime import datetime
from urllib.parse import urlparse, quote_plus
import psycopg
from psycopg.rows import dict_row

url = os.environ.get('DATABASE_URL', '')
if not url:
    sys.exit('DATABASE_URL not set')

p = urlparse(url)
if p.password:
    url = url.replace(f':{p.password}@', f':{quote_plus(p.password)}@', 1)

TABLES = ['ipb_drills', 'ipb_articles', 'ipb_categories',
          'ipb_users', 'ipb_notices', 'ipb_comments']
data = {'timestamp': datetime.now().isoformat(), 'tables': {}}
total = 0

for table in TABLES:
    try:
        with psycopg.connect(url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name=%s AND column_name='created_at'", (table,))
                order = 'ORDER BY created_at DESC' if cur.fetchone() else ''
                cur.execute(f'SELECT * FROM {table} {order}')
                rows = []
                for r in cur.fetchall():
                    rows.append({k: str(v) if v is not None and
                                 not isinstance(v, (str, int, float, bool)) else v
                                 for k, v in dict(r).items()})
                data['tables'][table] = rows
                total += len(rows)
                print(f'{table}: {len(rows)} 件')
    except Exception as e:
        print(f'{table}: skip ({e})')
        data['tables'][table] = []

fname = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
with open(fname, 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
print(f'Saved: {fname} ({total} records)')
