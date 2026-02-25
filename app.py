import os
from datetime import datetime
from flask import Flask, render_template
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

NOTE_URL = os.getenv('NOTE_URL', '#')


@app.context_processor
def inject_globals():
    return {
        'note_url': NOTE_URL,
        'current_year': datetime.now().year,
    }


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
