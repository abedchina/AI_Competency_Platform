import os, json, re
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-only-change-before-deployment')
db_url = os.getenv('DATABASE_URL', 'sqlite:///platform.db')
if db_url.startswith('postgres://'): db_url = 'postgresql://' + db_url[11:]
if db_url.startswith('postgresql://'): db_url = 'postgresql+psycopg://' + db_url[13:]  # psycopg 3 driver
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
# Stay signed in for 30 days (survives closing the browser).
from datetime import timedelta
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']
# Hosted Postgres (Neon, Render) drops idle connections; test each one before use.
if not db_url.startswith('sqlite'):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 280}
import competency as comp
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    language = db.Column(db.String(2), default='he')

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    title = db.Column(db.String(250), default='')
    proposal = db.Column(db.Text, default='')
    status = db.Column(db.String(30), default='draft')
    teacher_feedback = db.Column(db.Text, default='')
    teacher_level = db.Column(db.Integer, nullable=True)
    student = db.relationship('User', foreign_keys=[student_id])

class ProposalVersion(db.Model):
    """A snapshot of the proposal each time the student submits it."""
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    number = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(250), default='')
    proposal = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    msg_count = db.Column(db.Integer, default=0)          # student chat messages at submit time
    signals = db.Column(db.Text, default='[]')            # competency keys seen in the chat (JSON)
    teacher_feedback = db.Column(db.Text, default='')     # feedback the teacher gave on this version
    teacher_level = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(30), default='submitted')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))

def teacher_only(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if current_user.role != 'teacher':
            flash('אתה מחובר כתלמיד. כדי להיכנס כמורה, התנתק והיכנס עם חשבון המורה (או השתמש בחלון גלישה בסתר).' if current_user.language!='ar' else 'أنت مسجل كطالب. لتدخل كمعلم، اخرج وادخل بحساب المعلم (أو استخدم نافذة تصفح خفي).')
            return redirect(url_for('index'))
        return fn(*args, **kwargs)
    return inner

def student_only(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if current_user.role != 'student':
            if request.path.startswith('/api/'): return jsonify(error='החשבון המחובר אינו חשבון תלמיד. רענן את הדף.'),403
            flash('אתה מחובר כמורה. כדי להיכנס כתלמיד, התנתק והיכנס עם חשבון התלמיד (או השתמש בחלון גלישה בסתר).' if current_user.language!='ar' else 'أنت مسجل كمعلم. لتدخل كطالب، اخرج وادخل بحساب الطالب (أو استخدم نافذة تصفح خفي).')
            return redirect(url_for('index'))
        return fn(*args, **kwargs)
    return inner

def csrf_ok():
    return request.form.get('csrf_token') == session.get('csrf_token') if not request.is_json else request.headers.get('X-CSRF-Token') == session.get('csrf_token')

@app.before_request
def setup_csrf():
    if 'csrf_token' not in session:
        import secrets
        session['csrf_token'] = secrets.token_urlsafe(24)
    if request.method in ('POST','PUT','DELETE') and not csrf_ok(): abort(400, 'Invalid CSRF token')

@app.context_processor
def common():
    lang = current_user.language if current_user.is_authenticated else session.get('lang', 'he')
    return {'csrf_token': session.get('csrf_token'), 'lang': lang, 'comp': comp, 'L': (lambda item: comp.t(item, lang))}

@app.route('/language/<code>')
def language(code):
    if code not in ('he','ar'): abort(404)
    session['lang'] = code
    if current_user.is_authenticated:
        current_user.language = code
        db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('teacher_dashboard' if current_user.role == 'teacher' else 'student_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role','student')
        email = request.form.get('email','').strip().lower()
        name = request.form.get('name','').strip()[:100]
        password = request.form.get('password','')
        if role not in ('student','teacher') or not name or not email or len(password)<10:
            flash('נא למלא פרטים תקינים וסיסמה של 10 תווים לפחות'); return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('כתובת הדוא״ל כבר קיימת'); return redirect(url_for('register'))
        teacher_id = None
        if role == 'teacher':
            code = os.getenv('TEACHER_INVITE_CODE','')
            if os.getenv('ALLOW_TEACHER_SIGNUP','false').lower() != 'true' or not code or request.form.get('invite_code') != code:
                flash('רישום מורה מחייב קוד הזמנה והפעלה בשרת'); return redirect(url_for('register'))
        else:
            teacher_email = request.form.get('teacher_email','').strip().lower()
            teacher = User.query.filter_by(email=teacher_email,role='teacher').first()
            if not teacher:
                flash('יש להזין כתובת דוא״ל של מורה רשום'); return redirect(url_for('register'))
            teacher_id = teacher.id
        user=User(name=name,email=email,password_hash=generate_password_hash(password),role=role,teacher_id=teacher_id,language=session.get('lang','he'))
        db.session.add(user); db.session.commit(); login_user(user, remember=True)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        user=User.query.filter_by(email=request.form.get('email','').strip().lower()).first()
        if user and check_password_hash(user.password_hash,request.form.get('password','')):
            login_user(user, remember=True); return redirect(url_for('index'))
        flash('פרטי כניסה שגויים')
    return render_template('login.html')

@app.post('/logout')
@login_required
def logout():
    logout_user(); return redirect(url_for('index'))

@app.route('/student')
@student_only
def student_dashboard():
    project=Project.query.filter_by(student_id=current_user.id).first()
    messages=Message.query.filter_by(student_id=current_user.id).order_by(Message.id.asc()).all()
    return render_template('student.html',project=project,messages=messages)


def ask_gemini(history, language):
    key=(os.getenv('GEMINI_API_KEY') or '').strip()
    if not key: raise RuntimeError('מפתח Gemini טרם הוגדר בשרת')
    from google import genai
    from google.genai import types
    client=genai.Client(api_key=key,http_options=types.HttpOptions(timeout=25000))  # 25 s per call
    contents=[types.Content(role='user' if m.role=='user' else 'model',parts=[types.Part(text=m.content)]) for m in history[-16:]]
    import time
    primary=(os.getenv('GEMINI_MODEL') or 'gemini-3.8-flash').strip()
    extra=[m.strip() for m in os.getenv('GEMINI_FALLBACK_MODELS','gemini-flash-latest,gemini-flash-lite-latest').split(',') if m.strip()]
    models=[primary]+[m for m in extra if m!=primary]
    cfg=types.GenerateContentConfig(system_instruction=comp.system_prompt(language),temperature=0.5,max_output_tokens=1500)
    response=None;last=None;start=time.time()
    for model in models:
        tries=4 if model==primary else 2
        for attempt in range(tries):
            if time.time()-start>55: break
            try:
                response=client.models.generate_content(model=model,contents=contents,config=cfg)
                break
            except Exception as e:
                last=e
                code=getattr(e,'code',None) or getattr(e,'status_code',None)
                if code==404 or code is None: break   # model missing or timed out -> next model
                if code not in (429,500,503,504): raise
                if attempt<tries-1: time.sleep(2*(attempt+1))
        if response is not None: break
    if response is None: raise last or RuntimeError('Gemini unavailable')
    return (response.text or '').strip() or 'לא התקבלה תשובה מהמודל'

@app.post('/api/chat')
@student_only
def chat():
    data=request.get_json(silent=True) or {}
    content=str(data.get('message','')).strip()[:2500]
    if not content: return jsonify(error='Empty message'),400
    prior=Message.query.filter_by(student_id=current_user.id).order_by(Message.id.desc()).limit(16).all()
    history=list(reversed(prior))
    db.session.add(Message(student_id=current_user.id,role='user',content=content));db.session.commit()
    try:
        response=ask_gemini(history+[Message(role='user',content=content)],current_user.language)
    except Exception as e:
        app.logger.exception('Gemini request failed')
        detail=f'{type(e).__name__}: {str(e)[:300]}'
        key=(os.getenv('GEMINI_API_KEY') or '').strip()
        if key: detail=detail.replace(key,'***')
        busy=getattr(e,'code',None) in (429,500,503,504,None)
        msg='שירות ה-AI עמוס כרגע. נסה שוב בעוד דקה.' if busy else 'לא ניתן לקבל תשובה כעת. בדוק את הגדרות Gemini או נסה שוב.'
        return jsonify(error=msg,detail=detail),503
    db.session.add(Message(student_id=current_user.id,role='model',content=response));db.session.commit()
    return jsonify(reply=response)

@app.post('/proposal')
@student_only
def save_proposal():
    project=Project.query.filter_by(student_id=current_user.id).first()
    if not project:
        project=Project(student_id=current_user.id);db.session.add(project)
    project.title=request.form.get('title','').strip()[:250]
    project.proposal=request.form.get('proposal','').strip()[:15000]
    submitting=request.form.get('action')=='submit'
    project.status='submitted' if submitting else ('revision' if project.status=='revision' else 'draft')
    if submitting:
        msgs=Message.query.filter_by(student_id=current_user.id).order_by(Message.id.asc()).all()
        ev=comp.preliminary_evidence(msgs)
        n=ProposalVersion.query.filter_by(student_id=current_user.id).count()+1
        db.session.add(ProposalVersion(student_id=current_user.id,number=n,title=project.title,proposal=project.proposal,
                                       msg_count=ev['turns'],signals=json.dumps([x['key'] for x in ev['signals'] if x['found']])))
    db.session.commit()
    flash(('ההצעה הוגשה למורה' if submitting else 'הטיוטה נשמרה') if current_user.language!='ar' else ('تم تقديم المقترح للمعلم' if submitting else 'تم حفظ المسودة'))
    return redirect(url_for('student_dashboard'))

@app.route('/teacher')
@teacher_only
def teacher_dashboard():
    students=User.query.filter_by(role='student',teacher_id=current_user.id).order_by(User.name).all()
    rows=[]
    for st in students:
        project=Project.query.filter_by(student_id=st.id).first()
        n=Message.query.filter_by(student_id=st.id,role='user').count()
        rows.append((st,project,n,ProposalVersion.query.filter_by(student_id=st.id).count()))
    return render_template('teacher.html',rows=rows)

def diff_html(old, new):
    """Word-level diff: added words in <ins>, removed words in <del>."""
    import difflib
    from markupsafe import Markup, escape
    a, b = re.split(r'(\s+)', old), re.split(r'(\s+)', new)
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == 'equal':
            out.append(escape(''.join(a[i1:i2])))
        if op in ('delete', 'replace') and ''.join(a[i1:i2]).strip():
            out.append(Markup('<del>') + escape(''.join(a[i1:i2])) + Markup('</del>'))
        if op in ('insert', 'replace') and ''.join(b[j1:j2]).strip():
            out.append(Markup('<ins>') + escape(''.join(b[j1:j2])) + Markup('</ins>'))
    return Markup('').join(out)

def local_time(dt):
    if not dt: return ''
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo
        dt = dt.astimezone(ZoneInfo('Asia/Jerusalem'))
    except Exception:
        pass
    return dt.strftime('%d/%m/%Y %H:%M')

@app.route('/teacher/student/<int:student_id>')
@teacher_only
def student_review(student_id):
    student=db.session.get(User,student_id)
    if not student or student.teacher_id!=current_user.id: abort(404)
    project=Project.query.filter_by(student_id=student.id).first()
    messages=Message.query.filter_by(student_id=student.id).order_by(Message.id.asc()).all()
    versions=ProposalVersion.query.filter_by(student_id=student.id).order_by(ProposalVersion.number.asc()).all()
    history=[]
    prev=None
    for v in versions:
        found=set(json.loads(v.signals or '[]'))
        history.append({'v':v,'when':local_time(v.created_at),'found':found,
                        'diff':diff_html(prev.title+'\n'+prev.proposal, v.title+'\n'+v.proposal) if prev else None,
                        'added':len(found-set(json.loads(prev.signals or '[]'))) if prev else None})
        prev=v
    return render_template('review.html',student=student,project=project,messages=messages,
                           evidence=comp.preliminary_evidence(messages,current_user.language),history=history[::-1])

@app.post('/teacher/student/<int:student_id>/feedback')
@teacher_only
def feedback(student_id):
    student=db.session.get(User,student_id)
    if not student or student.teacher_id!=current_user.id: abort(404)
    project=Project.query.filter_by(student_id=student.id).first()
    if not project: abort(404)
    project.teacher_feedback=request.form.get('feedback','').strip()[:5000]
    level=request.form.get('level','')
    project.teacher_level=int(level) if level in ('1','2','3','4') else None
    project.status=request.form.get('status') if request.form.get('status') in ('draft','submitted','revision','approved') else project.status
    latest=ProposalVersion.query.filter_by(student_id=student.id).order_by(ProposalVersion.number.desc()).first()
    if latest:
        latest.teacher_feedback=project.teacher_feedback; latest.teacher_level=project.teacher_level; latest.status=project.status
    db.session.commit();flash('משוב המורה נשמר')
    return redirect(url_for('student_review',student_id=student.id))

@app.route('/framework')
def framework():
    return render_template('framework.html')

@app.route('/health')
def health():
    # 'storage' shows whether data survives restarts: sqlite on Render is wiped on every restart.
    return jsonify(status='ok', storage=db.engine.dialect.name)

with app.app_context(): db.create_all()

if __name__=='__main__': app.run(debug=os.getenv('FLASK_DEBUG')=='1')
