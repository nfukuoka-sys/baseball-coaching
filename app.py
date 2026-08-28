import os
import re
import secrets
from datetime import datetime, date, timedelta
from flask import (Flask, render_template, redirect, url_for, request,
                   flash, send_from_directory, session, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_VIDEO = {'mp4', 'mov', 'avi', 'webm'}
ALLOWED_IMAGE = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
MAX_UPLOAD_MB = 500

app = Flask(__name__)
# ── Security config ──────────────────────────────────────────────────────────
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'baseball.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'ログインが必要です'

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── Models ──────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=True)   # 招待前はNULL可
    password_hash = db.Column(db.String(200), nullable=True)
    role          = db.Column(db.String(20), nullable=False, default='player')
    status        = db.Column(db.String(20), nullable=False, default='active')  # active / pending
    position      = db.Column(db.String(50))
    grade         = db.Column(db.String(50))
    team          = db.Column(db.String(100))
    born_year     = db.Column(db.Integer)
    dominant_hand = db.Column(db.String(10))
    priority_note = db.Column(db.Text)   # コーチが設定する最優先課題メッセージ
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    physical_data = db.relationship('PhysicalData', backref='player', lazy='dynamic',
                                    order_by='PhysicalData.date.desc()')
    inbody_data   = db.relationship('InBodyData', backref='player', lazy='dynamic',
                                    order_by='InBodyData.date.desc()')
    rapsodo_data  = db.relationship('RapsodoData', backref='player', lazy='dynamic',
                                    order_by='RapsodoData.date.desc()')
    vald_data     = db.relationship('VALDData', backref='player', lazy='dynamic',
                                    order_by='VALDData.date.desc()')
    assignments   = db.relationship('Assignment', foreign_keys='Assignment.player_id',
                                    backref='player', lazy=True)
    issues        = db.relationship('Issue', backref='player', lazy=True)
    feedbacks     = db.relationship('CoachFeedback', foreign_keys='CoachFeedback.player_id',
                                    lazy='dynamic', order_by='CoachFeedback.created_at.desc()')

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method='pbkdf2:sha256')

    def check_password(self, pw):
        return self.password_hash and check_password_hash(self.password_hash, pw)

    @property
    def is_pending(self):
        return self.status == 'pending'

    @property
    def active_issues(self):
        return [i for i in self.issues if not i.is_resolved]

    @property
    def active_assignments(self):
        return [a for a in self.assignments if a.is_active]


class InviteToken(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    token      = db.Column(db.String(64), unique=True, nullable=False, index=True)
    player_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False)

    player = db.relationship('User', backref='invite_tokens')

    @property
    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at


class PhysicalData(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    player_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date           = db.Column(db.Date, nullable=False, default=date.today)
    height         = db.Column(db.Float)
    weight         = db.Column(db.Float)
    sprint_50m     = db.Column(db.Float)
    throw_distance = db.Column(db.Float)
    grip_r         = db.Column(db.Float)
    grip_l         = db.Column(db.Float)
    standing_jump  = db.Column(db.Float)
    broad_jump     = db.Column(db.Float)
    notes          = db.Column(db.Text)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)


class InBodyData(db.Model):
    id                    = db.Column(db.Integer, primary_key=True)
    player_id             = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date                  = db.Column(db.Date, nullable=False, default=date.today)
    weight                = db.Column(db.Float)
    skeletal_muscle_mass  = db.Column(db.Float)
    body_fat_mass         = db.Column(db.Float)
    body_fat_pct          = db.Column(db.Float)
    bmi                   = db.Column(db.Float)
    basal_metabolic_rate  = db.Column(db.Integer)
    visceral_fat          = db.Column(db.Float)
    total_body_water      = db.Column(db.Float)
    protein               = db.Column(db.Float)
    mineral               = db.Column(db.Float)
    right_arm_muscle      = db.Column(db.Float)
    left_arm_muscle       = db.Column(db.Float)
    trunk_muscle          = db.Column(db.Float)
    right_leg_muscle      = db.Column(db.Float)
    left_leg_muscle       = db.Column(db.Float)
    notes                 = db.Column(db.Text)
    created_at            = db.Column(db.DateTime, default=datetime.utcnow)


class RapsodoData(db.Model):
    id                 = db.Column(db.Integer, primary_key=True)
    player_id          = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date               = db.Column(db.Date, nullable=False, default=date.today)
    pitch_type         = db.Column(db.String(50))
    velocity_kmh       = db.Column(db.Float)
    spin_rate          = db.Column(db.Integer)
    spin_efficiency    = db.Column(db.Float)
    spin_axis          = db.Column(db.Integer)
    vert_break         = db.Column(db.Float)
    horz_break         = db.Column(db.Float)
    release_height     = db.Column(db.Float)
    release_side       = db.Column(db.Float)
    release_extension  = db.Column(db.Float)
    strike_pct         = db.Column(db.Float)
    pitch_count        = db.Column(db.Integer)
    notes              = db.Column(db.Text)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)


class VALDData(db.Model):
    id                    = db.Column(db.Integer, primary_key=True)
    player_id             = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date                  = db.Column(db.Date, nullable=False, default=date.today)
    test_type             = db.Column(db.String(50))
    jump_height           = db.Column(db.Float)
    jump_height_left      = db.Column(db.Float)
    jump_height_right     = db.Column(db.Float)
    peak_force            = db.Column(db.Float)
    peak_force_left       = db.Column(db.Float)
    peak_force_right      = db.Column(db.Float)
    relative_peak_force   = db.Column(db.Float)
    relative_force_left   = db.Column(db.Float)
    relative_force_right  = db.Column(db.Float)
    rfd                   = db.Column(db.Float)
    eccentric_peak_force  = db.Column(db.Float)
    concentric_impulse    = db.Column(db.Float)
    takeoff_velocity      = db.Column(db.Float)
    peak_power            = db.Column(db.Float)
    rsi                   = db.Column(db.Float)
    contact_time_ms       = db.Column(db.Float)
    flight_time_ms        = db.Column(db.Float)
    hop_leg               = db.Column(db.String(10))
    asymmetry_pct         = db.Column(db.Float)
    iso_force_left        = db.Column(db.Float)
    iso_force_right       = db.Column(db.Float)
    iso_relative_left     = db.Column(db.Float)
    iso_relative_right    = db.Column(db.Float)
    notes                 = db.Column(db.Text)
    created_at            = db.Column(db.DateTime, default=datetime.utcnow)


class Drill(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    category    = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    youtube_url = db.Column(db.String(500))
    video_file  = db.Column(db.String(300))
    image_file  = db.Column(db.String(300))
    notes       = db.Column(db.Text)
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    assignments = db.relationship('Assignment', backref='drill', lazy=True)


class Assignment(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    drill_id    = db.Column(db.Integer, db.ForeignKey('drill.id'), nullable=False)
    player_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coach_note  = db.Column(db.Text)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active   = db.Column(db.Boolean, default=True)


class Issue(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    player_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tag         = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)


class PlayerVideo(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    player_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title       = db.Column(db.String(200), nullable=False)
    video_file  = db.Column(db.String(300))
    youtube_url = db.Column(db.String(500))
    notes       = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    player      = db.relationship('User', backref='videos')


class CoachFeedback(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    player_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coach_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    is_read    = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ─── Helpers ─────────────────────────────────────────────────────────────────

def youtube_embed(url):
    if not url:
        return None
    m = re.search(r'(?:v=|youtu\.be/|embed/)([A-Za-z0-9_-]{11})', url)
    return f'https://www.youtube.com/embed/{m.group(1)}' if m else None


def to_float(v):
    try:
        return float(v) if v else None
    except (ValueError, TypeError):
        return None


def to_int(v):
    try:
        return int(v) if v else None
    except (ValueError, TypeError):
        return None


def allowed_file(filename, allowed):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def save_upload(file, subfolder, allowed):
    if not file or file.filename == '':
        return None
    if not allowed_file(file.filename, allowed):
        return None
    fname = secure_filename(file.filename)
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    fname = f'{ts}_{fname}'
    dest = os.path.join(UPLOAD_DIR, subfolder)
    os.makedirs(dest, exist_ok=True)
    file.save(os.path.join(dest, fname))
    return f'{subfolder}/{fname}'


def coach_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'coach':
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


def parse_date(s):
    try:
        return datetime.strptime(s, '%Y-%m-%d').date() if s else date.today()
    except ValueError:
        return date.today()


def velocity_grade(v):
    """球速から評価グレード (grade, color, pct) を返す"""
    if v is None:
        return ('未計測', '#94a3b8', 0)
    v = float(v)
    if v >= 150: return ('A', '#16a34a', 100)
    if v >= 140: return ('B', '#2563eb', 75)
    if v >= 130: return ('C', '#d97706', 50)
    if v >= 120: return ('D', '#ea580c', 28)
    return ('F', '#dc2626', 10)


app.jinja_env.globals['velocity_grade'] = velocity_grade


# ── Login rate limiting (session-based) ──────────────────────────────────────
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def check_rate_limit():
    now = datetime.utcnow()
    attempts = session.get('login_attempts', 0)
    locked_until = session.get('login_locked_until')
    if locked_until:
        locked_until_dt = datetime.fromisoformat(locked_until)
        if now < locked_until_dt:
            remaining = int((locked_until_dt - now).total_seconds() / 60) + 1
            return False, f'ログイン試行が上限に達しました。{remaining}分後に再試行してください。'
        else:
            session.pop('login_attempts', None)
            session.pop('login_locked_until', None)
    return True, None


def record_failed_login():
    attempts = session.get('login_attempts', 0) + 1
    session['login_attempts'] = attempts
    if attempts >= MAX_ATTEMPTS:
        session['login_locked_until'] = (
            datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        ).isoformat()


# ─── Constants ────────────────────────────────────────────────────────────────

PITCH_TYPES = ['フォーシーム', 'ツーシーム', 'スライダー', 'カーブ',
               'チェンジアップ', 'カットボール', 'スプリット', 'シュート', 'その他']

VALD_TESTS = [
    'Countermovement Jump', 'Squat Jump', 'Single Leg Jump',
    'Hop Test', 'Shoulder ISO-T', 'Shoulder ISO-Y', 'Shoulder ISO-I', 'その他',
]

CATEGORIES = ['投球', '打撃', 'スタビリティ', 'モビリティ', 'ストレングス', 'コンディショニング', 'その他']


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if current_user.is_authenticated:
        dest = 'coach_dashboard' if current_user.role == 'coach' else 'player_dashboard'
        return redirect(url_for(dest))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        ok, msg = check_rate_limit()
        if not ok:
            flash(msg, 'error')
            return render_template('login.html')

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()

        if user and user.status == 'active' and user.check_password(password):
            session.pop('login_attempts', None)
            session.pop('login_locked_until', None)
            session.permanent = True
            login_user(user)
            return redirect(url_for('index'))

        record_failed_login()
        flash('メールアドレスまたはパスワードが正しくありません', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))


# ─── Player self-registration via invite ──────────────────────────────────────

@app.route('/join/<token>', methods=['GET', 'POST'])
def join(token):
    inv = InviteToken.query.filter_by(token=token).first()
    if not inv or not inv.is_valid:
        return render_template('invite_expired.html')

    player = inv.player
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        if not email or not password:
            flash('メールアドレスとパスワードを入力してください', 'error')
        elif password != confirm:
            flash('パスワードが一致しません', 'error')
        elif len(password) < 8:
            flash('パスワードは8文字以上にしてください', 'error')
        elif User.query.filter_by(email=email).filter(User.id != player.id).first():
            flash('このメールアドレスはすでに使用されています', 'error')
        else:
            player.email  = email
            player.status = 'active'
            player.set_password(password)
            inv.used = True
            db.session.commit()
            login_user(player)
            flash(f'ようこそ、{player.name}さん！', 'success')
            return redirect(url_for('player_dashboard'))

    return render_template('register.html', player=player, token=token)


# ─── Coach: Players ───────────────────────────────────────────────────────────

@app.route('/coach/dashboard')
@login_required
@coach_required
def coach_dashboard():
    q    = request.args.get('q', '').strip()
    pos  = request.args.get('pos', '').strip()
    team = request.args.get('team', '').strip()
    page = request.args.get('page', 1, type=int)

    query = User.query.filter_by(role='player')
    if q:
        query = query.filter(User.name.ilike(f'%{q}%'))
    if pos:
        query = query.filter(User.position == pos)
    if team:
        query = query.filter(User.team.ilike(f'%{team}%'))

    pagination   = query.order_by(User.name).paginate(page=page, per_page=20, error_out=False)
    positions    = [r[0] for r in db.session.query(User.position).filter(
                       User.role == 'player', User.position != None).distinct().all() if r[0]]
    teams        = [r[0] for r in db.session.query(User.team).filter(
                       User.role == 'player', User.team != None).distinct().all() if r[0]]
    drills_count   = Drill.query.count()
    total_players  = User.query.filter_by(role='player').count()
    pending_count  = User.query.filter_by(role='player', status='pending').count()

    return render_template('coach/dashboard.html',
                           players=pagination.items, pagination=pagination,
                           drills_count=drills_count, total_players=total_players,
                           pending_count=pending_count,
                           positions=positions, teams=teams,
                           q=q, pos=pos, team=team)


@app.route('/coach/players/new', methods=['GET', 'POST'])
@login_required
@coach_required
def new_player():
    if request.method == 'POST':
        name  = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower() or None
        pw    = request.form.get('password', '').strip()

        if email and User.query.filter_by(email=email).first():
            flash('このメールアドレスはすでに登録されています', 'error')
            return render_template('coach/new_player.html')

        status = 'active' if email and pw else 'pending'
        u = User(name=name, email=email, role='player', status=status,
                 position=request.form.get('position') or None,
                 grade=request.form.get('grade') or None,
                 team=request.form.get('team') or None,
                 born_year=to_int(request.form.get('born_year')),
                 dominant_hand=request.form.get('dominant_hand') or None)
        if pw:
            u.set_password(pw)
        db.session.add(u)
        db.session.commit()
        flash(f'選手「{name}」を登録しました', 'success')
        return redirect(url_for('player_detail', player_id=u.id))

    return render_template('coach/new_player.html')


@app.route('/coach/players/<int:player_id>')
@login_required
@coach_required
def player_detail(player_id):
    player       = User.query.get_or_404(player_id)
    physical_list = PhysicalData.query.filter_by(player_id=player_id).order_by(PhysicalData.date.desc()).limit(20).all()
    inbody_list  = InBodyData.query.filter_by(player_id=player_id).order_by(InBodyData.date.desc()).limit(20).all()
    rapsodo_list = RapsodoData.query.filter_by(player_id=player_id).order_by(RapsodoData.date.desc()).limit(30).all()
    vald_list    = VALDData.query.filter_by(player_id=player_id).order_by(VALDData.date.desc()).limit(20).all()
    assignments  = Assignment.query.filter_by(player_id=player_id, is_active=True).all()
    issues       = Issue.query.filter_by(player_id=player_id, is_resolved=False).all()
    all_drills   = Drill.query.order_by(Drill.category, Drill.title).all()
    assigned_ids = {a.drill_id for a in assignments}
    today_str    = date.today().isoformat()

    active_invite   = InviteToken.query.filter_by(player_id=player_id, used=False).filter(
        InviteToken.expires_at > datetime.utcnow()).order_by(InviteToken.created_at.desc()).first()
    feedbacks       = CoachFeedback.query.filter_by(player_id=player_id)\
                                         .order_by(CoachFeedback.created_at.desc()).limit(20).all()
    player_videos   = PlayerVideo.query.filter_by(player_id=player_id)\
                                       .order_by(PlayerVideo.uploaded_at.desc()).all()

    return render_template('coach/player_detail.html',
                           player=player,
                           physical_list=physical_list, inbody_list=inbody_list,
                           rapsodo_list=rapsodo_list, vald_list=vald_list,
                           assignments=assignments, issues=issues,
                           all_drills=all_drills, assigned_ids=assigned_ids,
                           today_str=today_str, pitch_types=PITCH_TYPES,
                           vald_tests=VALD_TESTS, active_invite=active_invite,
                           feedbacks=feedbacks, player_videos=player_videos)


# ── Priority note ──

@app.route('/coach/players/<int:pid>/priority', methods=['POST'])
@login_required
@coach_required
def set_priority_note(pid):
    player = User.query.get_or_404(pid)
    player.priority_note = request.form.get('priority_note', '').strip() or None
    db.session.commit()
    flash('最優先課題を更新しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#issues')


# ── Invite ──

@app.route('/coach/players/<int:pid>/invite', methods=['POST'])
@login_required
@coach_required
def generate_invite(pid):
    player = User.query.get_or_404(pid)
    # 既存の未使用トークンを無効化
    InviteToken.query.filter_by(player_id=pid, used=False).update({'used': True})
    token = secrets.token_urlsafe(32)
    inv = InviteToken(token=token, player_id=pid,
                      expires_at=datetime.utcnow() + timedelta(days=7))
    db.session.add(inv)
    db.session.commit()
    flash(f'招待リンクを生成しました（7日間有効）', 'success')
    return redirect(url_for('player_detail', player_id=pid))


# ── Physical ──

@app.route('/coach/players/<int:pid>/physical/add', methods=['POST'])
@login_required
@coach_required
def add_physical(pid):
    db.session.add(PhysicalData(
        player_id=pid, date=parse_date(request.form.get('date')),
        height=to_float(request.form.get('height')),
        weight=to_float(request.form.get('weight')),
        sprint_50m=to_float(request.form.get('sprint_50m')),
        throw_distance=to_float(request.form.get('throw_distance')),
        grip_r=to_float(request.form.get('grip_r')),
        grip_l=to_float(request.form.get('grip_l')),
        standing_jump=to_float(request.form.get('standing_jump')),
        broad_jump=to_float(request.form.get('broad_jump')),
        notes=request.form.get('notes'),
    ))
    db.session.commit()
    flash('フィジカルデータを追加しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#physical')


# ── InBody ──

@app.route('/coach/players/<int:pid>/inbody/add', methods=['POST'])
@login_required
@coach_required
def add_inbody(pid):
    db.session.add(InBodyData(
        player_id=pid, date=parse_date(request.form.get('date')),
        weight=to_float(request.form.get('weight')),
        skeletal_muscle_mass=to_float(request.form.get('skeletal_muscle_mass')),
        body_fat_mass=to_float(request.form.get('body_fat_mass')),
        body_fat_pct=to_float(request.form.get('body_fat_pct')),
        bmi=to_float(request.form.get('bmi')),
        basal_metabolic_rate=to_int(request.form.get('basal_metabolic_rate')),
        visceral_fat=to_float(request.form.get('visceral_fat')),
        total_body_water=to_float(request.form.get('total_body_water')),
        protein=to_float(request.form.get('protein')),
        mineral=to_float(request.form.get('mineral')),
        right_arm_muscle=to_float(request.form.get('right_arm_muscle')),
        left_arm_muscle=to_float(request.form.get('left_arm_muscle')),
        trunk_muscle=to_float(request.form.get('trunk_muscle')),
        right_leg_muscle=to_float(request.form.get('right_leg_muscle')),
        left_leg_muscle=to_float(request.form.get('left_leg_muscle')),
        notes=request.form.get('notes'),
    ))
    db.session.commit()
    flash('InBodyデータを追加しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#inbody')


# ── Rapsodo ──

@app.route('/coach/players/<int:pid>/rapsodo/add', methods=['POST'])
@login_required
@coach_required
def add_rapsodo(pid):
    db.session.add(RapsodoData(
        player_id=pid, date=parse_date(request.form.get('date')),
        pitch_type=request.form.get('pitch_type'),
        velocity_kmh=to_float(request.form.get('velocity_kmh')),
        spin_rate=to_int(request.form.get('spin_rate')),
        spin_efficiency=to_float(request.form.get('spin_efficiency')),
        spin_axis=to_int(request.form.get('spin_axis')),
        vert_break=to_float(request.form.get('vert_break')),
        horz_break=to_float(request.form.get('horz_break')),
        release_height=to_float(request.form.get('release_height')),
        release_side=to_float(request.form.get('release_side')),
        release_extension=to_float(request.form.get('release_extension')),
        strike_pct=to_float(request.form.get('strike_pct')),
        pitch_count=to_int(request.form.get('pitch_count')),
        notes=request.form.get('notes'),
    ))
    db.session.commit()
    flash('Rapsodoデータを追加しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#rapsodo')


# ── VALD ──

@app.route('/coach/players/<int:pid>/vald/add', methods=['POST'])
@login_required
@coach_required
def add_vald(pid):
    db.session.add(VALDData(
        player_id=pid, date=parse_date(request.form.get('date')),
        test_type=request.form.get('test_type'),
        jump_height=to_float(request.form.get('jump_height')),
        jump_height_left=to_float(request.form.get('jump_height_left')),
        jump_height_right=to_float(request.form.get('jump_height_right')),
        peak_force=to_float(request.form.get('peak_force')),
        peak_force_left=to_float(request.form.get('peak_force_left')),
        peak_force_right=to_float(request.form.get('peak_force_right')),
        relative_peak_force=to_float(request.form.get('relative_peak_force')),
        relative_force_left=to_float(request.form.get('relative_force_left')),
        relative_force_right=to_float(request.form.get('relative_force_right')),
        rfd=to_float(request.form.get('rfd')),
        eccentric_peak_force=to_float(request.form.get('eccentric_peak_force')),
        concentric_impulse=to_float(request.form.get('concentric_impulse')),
        takeoff_velocity=to_float(request.form.get('takeoff_velocity')),
        peak_power=to_float(request.form.get('peak_power')),
        rsi=to_float(request.form.get('rsi')),
        contact_time_ms=to_float(request.form.get('contact_time_ms')),
        flight_time_ms=to_float(request.form.get('flight_time_ms')),
        hop_leg=request.form.get('hop_leg') or None,
        asymmetry_pct=to_float(request.form.get('asymmetry_pct')),
        iso_force_left=to_float(request.form.get('iso_force_left')),
        iso_force_right=to_float(request.form.get('iso_force_right')),
        iso_relative_left=to_float(request.form.get('iso_relative_left')),
        iso_relative_right=to_float(request.form.get('iso_relative_right')),
        notes=request.form.get('notes'),
    ))
    db.session.commit()
    flash('VALDデータを追加しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#vald')


# ── Issue ──

@app.route('/coach/players/<int:pid>/issue/add', methods=['POST'])
@login_required
@coach_required
def add_issue(pid):
    db.session.add(Issue(player_id=pid,
                         tag=request.form.get('tag', '').strip(),
                         description=request.form.get('description', '').strip()))
    db.session.commit()
    flash('課題を追加しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#issues')


@app.route('/coach/players/<int:pid>/issue/<int:iid>/resolve', methods=['POST'])
@login_required
@coach_required
def resolve_issue(pid, iid):
    i = Issue.query.get_or_404(iid)
    i.is_resolved = True
    db.session.commit()
    flash('課題を解決済みにしました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#issues')


# ── Drill assignment ──

@app.route('/coach/players/<int:pid>/assign', methods=['POST'])
@login_required
@coach_required
def assign_drill(pid):
    did = int(request.form.get('drill_id'))
    if Assignment.query.filter_by(drill_id=did, player_id=pid, is_active=True).first():
        flash('すでに割り当て済みです', 'error')
    else:
        db.session.add(Assignment(drill_id=did, player_id=pid,
                                  coach_note=request.form.get('coach_note', '')))
        db.session.commit()
        flash('ドリルを割り当てました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#drills')


@app.route('/coach/players/<int:pid>/unassign/<int:aid>', methods=['POST'])
@login_required
@coach_required
def unassign_drill(pid, aid):
    a = Assignment.query.get_or_404(aid)
    a.is_active = False
    db.session.commit()
    flash('割り当てを解除しました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#drills')


# ─── Coach: Drills ────────────────────────────────────────────────────────────

@app.route('/coach/drills')
@login_required
@coach_required
def coach_drills():
    cat  = request.args.get('category', '')
    q    = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    query = Drill.query
    if cat:
        query = query.filter_by(category=cat)
    if q:
        query = query.filter(Drill.title.ilike(f'%{q}%'))
    pagination = query.order_by(Drill.created_at.desc()).paginate(page=page, per_page=24, error_out=False)
    return render_template('coach/drills.html', drills=pagination.items,
                           pagination=pagination, current_category=cat, q=q,
                           categories=CATEGORIES)


@app.route('/coach/drills/new', methods=['GET', 'POST'])
@login_required
@coach_required
def new_drill():
    if request.method == 'POST':
        video_path = save_upload(request.files.get('video_file'), 'videos', ALLOWED_VIDEO)
        image_path = save_upload(request.files.get('image_file'), 'images', ALLOWED_IMAGE)
        db.session.add(Drill(
            title=request.form.get('title', '').strip(),
            category=request.form.get('category'),
            description=request.form.get('description', '').strip(),
            youtube_url=request.form.get('youtube_url', '').strip() or None,
            video_file=video_path, image_file=image_path,
            notes=request.form.get('notes', '').strip(),
            created_by=current_user.id,
        ))
        db.session.commit()
        flash('ドリルを登録しました', 'success')
        return redirect(url_for('coach_drills'))
    return render_template('coach/edit_drill.html', drill=None, categories=CATEGORIES)


@app.route('/coach/drills/<int:did>/edit', methods=['GET', 'POST'])
@login_required
@coach_required
def edit_drill(did):
    drill = Drill.query.get_or_404(did)
    if request.method == 'POST':
        new_video = save_upload(request.files.get('video_file'), 'videos', ALLOWED_VIDEO)
        new_image = save_upload(request.files.get('image_file'), 'images', ALLOWED_IMAGE)
        drill.title       = request.form.get('title', '').strip()
        drill.category    = request.form.get('category')
        drill.description = request.form.get('description', '').strip()
        drill.youtube_url = request.form.get('youtube_url', '').strip() or None
        drill.notes       = request.form.get('notes', '').strip()
        if new_video:
            drill.video_file = new_video
        if new_image:
            drill.image_file = new_image
        db.session.commit()
        flash('ドリルを更新しました', 'success')
        return redirect(url_for('coach_drills'))
    return render_template('coach/edit_drill.html', drill=drill, categories=CATEGORIES)


@app.route('/coach/drills/<int:did>/delete', methods=['POST'])
@login_required
@coach_required
def delete_drill(did):
    drill = Drill.query.get_or_404(did)
    Assignment.query.filter_by(drill_id=did).delete()
    db.session.delete(drill)
    db.session.commit()
    flash('ドリルを削除しました', 'success')
    return redirect(url_for('coach_drills'))


# ─── Player ───────────────────────────────────────────────────────────────────

@app.route('/player/dashboard')
@login_required
def player_dashboard():
    if current_user.role == 'coach':
        return redirect(url_for('coach_dashboard'))
    assignments   = Assignment.query.filter_by(player_id=current_user.id, is_active=True).all()
    latest_inbody = InBodyData.query.filter_by(player_id=current_user.id).order_by(InBodyData.date.desc()).first()
    latest_phys   = PhysicalData.query.filter_by(player_id=current_user.id).order_by(PhysicalData.date.desc()).first()
    issues        = Issue.query.filter_by(player_id=current_user.id, is_resolved=False).all()
    feedbacks     = CoachFeedback.query.filter_by(player_id=current_user.id)\
                                       .order_by(CoachFeedback.created_at.desc()).limit(10).all()
    unread_count  = CoachFeedback.query.filter_by(player_id=current_user.id, is_read=False).count()
    best_velocity = db.session.query(db.func.max(RapsodoData.velocity_kmh))\
                              .filter_by(player_id=current_user.id).scalar()
    return render_template('player/dashboard.html',
                           assignments=assignments,
                           latest_inbody=latest_inbody,
                           latest_phys=latest_phys,
                           issues=issues,
                           feedbacks=feedbacks,
                           unread_count=unread_count,
                           best_velocity=best_velocity)


@app.route('/player/drills/<int:aid>')
@login_required
def player_drill_detail(aid):
    a = Assignment.query.get_or_404(aid)
    if a.player_id != current_user.id and current_user.role != 'coach':
        return redirect(url_for('index'))
    return render_template('player/drill_detail.html', assignment=a,
                           embed_url=youtube_embed(a.drill.youtube_url))


@app.route('/player/profile')
@login_required
def player_profile():
    phys_list   = PhysicalData.query.filter_by(player_id=current_user.id).order_by(PhysicalData.date.asc()).all()
    inbody_list = InBodyData.query.filter_by(player_id=current_user.id).order_by(InBodyData.date.asc()).all()
    rap_list    = RapsodoData.query.filter_by(player_id=current_user.id).order_by(RapsodoData.date.asc()).all()
    vald_list   = VALDData.query.filter_by(player_id=current_user.id).order_by(VALDData.date.asc()).all()
    issues      = Issue.query.filter_by(player_id=current_user.id).all()
    return render_template('player/profile.html',
                           phys_list=phys_list, inbody_list=inbody_list,
                           rap_list=rap_list, vald_list=vald_list, issues=issues)


@app.route('/player/videos')
@login_required
def player_videos():
    if current_user.role == 'coach':
        return redirect(url_for('coach_dashboard'))
    videos = PlayerVideo.query.filter_by(player_id=current_user.id)\
                              .order_by(PlayerVideo.uploaded_at.desc()).all()
    return render_template('player/videos.html', videos=videos)


@app.route('/player/videos/upload', methods=['POST'])
@login_required
def upload_player_video():
    if current_user.role == 'coach':
        return redirect(url_for('coach_dashboard'))
    title       = request.form.get('title', '').strip()
    youtube_url = request.form.get('youtube_url', '').strip() or None
    notes       = request.form.get('notes', '').strip() or None
    video_path  = save_upload(request.files.get('video_file'), 'player_videos', ALLOWED_VIDEO)

    if not title:
        flash('タイトルを入力してください', 'error')
        return redirect(url_for('player_videos'))
    if not video_path and not youtube_url:
        flash('動画ファイルまたはYouTube URLを入力してください', 'error')
        return redirect(url_for('player_videos'))

    db.session.add(PlayerVideo(player_id=current_user.id, title=title,
                               video_file=video_path, youtube_url=youtube_url, notes=notes))
    db.session.commit()
    flash('動画をアップロードしました', 'success')
    return redirect(url_for('player_videos'))


@app.route('/player/videos/<int:vid>/delete', methods=['POST'])
@login_required
def delete_player_video(vid):
    v = PlayerVideo.query.get_or_404(vid)
    if v.player_id != current_user.id and current_user.role != 'coach':
        abort(403)
    db.session.delete(v)
    db.session.commit()
    flash('動画を削除しました', 'success')
    return redirect(url_for('player_videos'))


@app.route('/coach/players/<int:pid>/videos')
@login_required
@coach_required
def coach_player_videos(pid):
    player = User.query.get_or_404(pid)
    videos = PlayerVideo.query.filter_by(player_id=pid)\
                              .order_by(PlayerVideo.uploaded_at.desc()).all()
    return render_template('coach/player_videos.html', player=player, videos=videos)


@app.route('/coach/drills/<int:did>/bulk-assign', methods=['GET', 'POST'])
@login_required
@coach_required
def bulk_assign(did):
    drill   = Drill.query.get_or_404(did)
    players = User.query.filter_by(role='player', status='active').order_by(User.name).all()
    if request.method == 'POST':
        player_ids = request.form.getlist('player_ids')
        coach_note = request.form.get('coach_note', '').strip()
        count = 0
        for pid in player_ids:
            pid = int(pid)
            if not Assignment.query.filter_by(drill_id=did, player_id=pid, is_active=True).first():
                db.session.add(Assignment(drill_id=did, player_id=pid, coach_note=coach_note))
                count += 1
        db.session.commit()
        flash(f'{count}人の選手にドリルを割り当てました', 'success')
        return redirect(url_for('coach_drills'))
    already = {a.player_id for a in Assignment.query.filter_by(drill_id=did, is_active=True).all()}
    return render_template('coach/bulk_assign.html', drill=drill, players=players, already=already)


@app.route('/coach/players/<int:pid>/feedback', methods=['POST'])
@login_required
@coach_required
def add_feedback(pid):
    content = request.form.get('content', '').strip()
    if content:
        db.session.add(CoachFeedback(player_id=pid, coach_id=current_user.id, content=content))
        db.session.commit()
        flash('フィードバックを送りました', 'success')
    return redirect(url_for('player_detail', player_id=pid) + '#feedback')


@app.route('/player/feedback/<int:fid>/read', methods=['POST'])
@login_required
def mark_feedback_read(fid):
    f = CoachFeedback.query.get_or_404(fid)
    if f.player_id != current_user.id:
        abort(403)
    f.is_read = True
    db.session.commit()
    return ('', 204)


@app.route('/uploads/<path:filepath>')
def uploaded_file(filepath):
    return send_from_directory(UPLOAD_DIR, filepath)


# ─── Init ─────────────────────────────────────────────────────────────────────

def init_db():
    db.create_all()
    if not User.query.filter_by(role='coach').first():
        coach = User(name='福岡夏希', email='n.fukuoka@dimensioning.jp', role='coach', status='active')
        coach.set_password('Natsuki1023')
        db.session.add(coach)
        db.session.commit()
        print('✅ コーチアカウント作成: n.fukuoka@dimensioning.jp')


with app.app_context():
    init_db()


if __name__ == '__main__':
    app.run(debug=True, port=5001)
