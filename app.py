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
        if current_user.role != 'teacher': abort(403)
        return fn(*args, **kwargs)
    return inner

def student_only(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if current_user.role != 'student': abort(403)
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
    return {'csrf_token': session.get('csrf_token'), 'lang': current_user.language if current_user.is_authenticated else session.get('lang', 'he')}

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
        db.session.add(user); db.session.commit(); login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        user=User.query.filter_by(email=request.form.get('email','').strip().lower()).first()
        if user and check_password_hash(user.password_hash,request.form.get('password','')):
            login_user(user); return redirect(url_for('index'))
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

SYSTEM_HE = '''אתה מנחה פדגוגי לתלמידי תיכון באלקטרוניקה. המטרה היא לפתח כשירות AI תוך גיבוש הצעת פרויקט. אל תכתוב מיד הצעה שלמה ואל תעשה את החשיבה במקום התלמיד. כאשר הפרומפט עמום, הסבר בנימוס מה חסר (בעיה, משתמשים, אילוצים, בדיקה), הצע שיפור קצר ובקש מהתלמיד לנסח בעצמו. קדם חקר, השוואת חלופות, אימות מקורות וחשיבה ביקורתית. הבהר אי-ודאות ואל תמציא מקורות. התייחס לתיאור הבעיה והצורך, מטרות, חלופות, פתרון, רכיבים, בדיקות וסיכונים. השב בעברית בהירה, עד 180 מילים. אין לקבוע לתלמיד רמת כשירות מתוך שיחה אחת.'''
SYSTEM_AR = '''أنت مرشد تربوي لطلاب المرحلة الثانوية في الإلكترونيات. هدفك تنمية كفايات الذكاء الاصطناعي أثناء إعداد مقترح مشروع. لا تكتب المشروع كاملاً بدلاً من الطالب. عندما يكون السؤال عاماً، وضح ما ينقصه (المشكلة، المستفيدون، القيود، التحقق)، وقدّم تلميحاً ثم اطلب من الطالب تحسين سؤاله بنفسه. شجّع البحث والمقارنة والتحقق والنقد. لا تختلق مصادر. ناقش المشكلة والحاجة والأهداف والبدائل والمكونات والاختبارات والمخاطر. أجب بالعربية الواضحة باختصار. لا تصنف مستوى الطالب من رسالة واحدة.'''

def ask_gemini(history, language):
    key=os.getenv('GEMINI_API_KEY')
    if not key: raise RuntimeError('מפתח Gemini טרם הוגדר בשרת')
    from google import genai
    from google.genai import types
    client=genai.Client(api_key=key)
    contents=[types.Content(role='user' if m.role=='user' else 'model',parts=[types.Part(text=m.content)]) for m in history[-16:]]
    response=client.models.generate_content(model=os.getenv('GEMINI_MODEL','gemini-3.8-flash'), contents=contents, config=types.GenerateContentConfig(system_instruction=SYSTEM_AR if language=='ar' else SYSTEM_HE,temperature=0.5,max_output_tokens=1500))
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
        key=os.getenv('GEMINI_API_KEY') or ''
        if key: detail=detail.replace(key,'***')
        return jsonify(error='לא ניתן לקבל תשובה כעת. בדוק את הגדרות Gemini או נסה שוב.',detail=detail),503
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
    project.status='submitted' if request.form.get('action')=='submit' else 'draft'
    db.session.commit()
    flash('ההצעה נשמרה');return redirect(url_for('student_dashboard'))

@app.route('/teacher')
@teacher_only
def teacher_dashboard():
    students=User.query.filter_by(role='student',teacher_id=current_user.id).order_by(User.name).all()
    rows=[]
    for st in students:
        project=Project.query.filter_by(student_id=st.id).first()
        n=Message.query.filter_by(student_id=st.id,role='user').count()
        rows.append((st,project,n))
    return render_template('teacher.html',rows=rows)

def preliminary_evidence(messages):
    user_texts=[m.content for m in messages if m.role=='user']
    combined=' '.join(user_texts).lower()
    patterns={
        'prompt_detail':r'מטרה|אילוץ|דרישה|חיישן|מגבלה|هدف|قيود|متطلبات|مستشعر',
        'research':r'השוו|השווא|חלופ|יתרון|חסרון|قارن|بديل|مقارنة|ميزة',
        'verification':r'בדק|מקור|אימות|ניסוי|מדיד|تحقق|مصدر|تجربة|قياس',
        'engineering':r'רכיב|מעגל|תכנון|קוד|בדיקה|مكونات|دائرة|تصميم|اختبار'
    }
    flags={k:bool(re.search(v,combined)) for k,v in patterns.items()}
    return {'turns':len(user_texts),'signals':flags,'note':'סימנים ראשוניים בלבד. לא נקבעת רמת כשירות אוטומטית: יש לבחון איכות, עצמאות וראיות לאורך זמן.'}

@app.route('/teacher/student/<int:student_id>')
@teacher_only
def student_review(student_id):
    student=db.session.get(User,student_id)
    if not student or student.teacher_id!=current_user.id: abort(404)
    project=Project.query.filter_by(student_id=student.id).first()
    messages=Message.query.filter_by(student_id=student.id).order_by(Message.id.asc()).all()
    return render_template('review.html',student=student,project=project,messages=messages,evidence=preliminary_evidence(messages))

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
    db.session.commit();flash('משוב המורה נשמר')
    return redirect(url_for('student_review',student_id=student.id))

@app.route('/health')
def health(): return jsonify(status='ok')

with app.app_context(): db.create_all()

if __name__=='__main__': app.run(debug=os.getenv('FLASK_DEBUG')=='1')
