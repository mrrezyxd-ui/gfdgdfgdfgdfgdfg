#!/usr/bin/env python3
"""
ChronoPlan — Personal Countdown & Goal Management Platform
Single-file Flask application (production-ready)
Run: python app.py  →  http://localhost:3000
"""

import os
import io
import ipaddress
import uuid
import atexit
import getpass
import smtplib
from datetime import datetime, timezone, timedelta
from functools import wraps
from threading import Thread
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlsplit

import pytz
from flask import (Flask, render_template, redirect, url_for, request, flash,
                   jsonify, abort, send_from_directory, get_flashed_messages)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         current_user, login_required)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (StringField, PasswordField, BooleanField, SubmitField,
                     TextAreaField, DateTimeLocalField, SelectField, ColorField,
                     FileField, IntegerField, ValidationError)
from wtforms.validators import (DataRequired, Email, Length, EqualTo,
                                Optional, URL, Regexp, NumberRange)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from PIL import Image
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
import click

# ════════════════════════════════════════════════════════════
# 1. CONFIGURATION
# ════════════════════════════════════════════════════════════
load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-change-me-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///chronoplan.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 86400
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
    MAIL_SERVER = os.environ.get('MAIL_SERVER', '')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', '')
    APP_URL = os.environ.get('APP_URL', 'http://localhost:3000')
    PORT = int(os.environ.get('PORT', 3000))
    WTF_CSRF_ENABLED = True
    THUMBNAIL_SIZE = (640, 360)
    PROFILE_SIZE = (256, 256)
    TESTING = False

# ════════════════════════════════════════════════════════════
# 2. APP + EXTENSIONS
# ════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

# ════════════════════════════════════════════════════════════
# 3. MODELS
# ════════════════════════════════════════════════════════════
event_tags = db.Table('event_tags',
    db.Column('event_id', db.Integer, db.ForeignKey('countdown_events.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True),
)

class Role:
    USER = 'user'
    ADMIN = 'admin'

def utcnow():
    return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=Role.USER, nullable=False)
    is_active_user = db.Column(db.Boolean, default=True, nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    preferences = db.relationship('UserPreference', uselist=False,
                                  back_populates='user', cascade='all, delete-orphan')
    events = db.relationship('CountdownEvent', back_populates='user',
                             cascade='all, delete-orphan', lazy='dynamic')
    notifications = db.relationship('Notification', back_populates='user',
                                    cascade='all, delete-orphan', lazy='dynamic')

    @property
    def is_active(self):
        return self.is_active_user

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    def set_password(self, password):
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self.password_hash = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=3600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='password-reset')
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=3600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='password-reset')
        try:
            data = s.loads(token, max_age=expires_sec)
            return User.query.get(data.get('user_id'))
        except (BadSignature, SignatureExpired):
            return None

    def __repr__(self):
        return f'<User {self.username}>'


class UserPreference(db.Model):
    __tablename__ = 'user_preferences'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    timezone = db.Column(db.String(50), default='UTC', nullable=False)
    date_format = db.Column(db.String(30), default='MMM d, yyyy', nullable=False)
    time_format = db.Column(db.String(30), default='HH:mm', nullable=False)
    theme = db.Column(db.String(10), default='dark', nullable=False)
    default_view = db.Column(db.String(10), default='grid', nullable=False)
    email_notifications = db.Column(db.Boolean, default=True)
    in_app_notifications = db.Column(db.Boolean, default=True)
    reminder_default = db.Column(db.Integer, default=60)
    user = db.relationship('User', back_populates='preferences')


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    slug = db.Column(db.String(80), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    is_global = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    events = db.relationship('CountdownEvent', back_populates='category')
    user = db.relationship('User')
    __table_args__ = (db.UniqueConstraint('slug', 'user_id', name='uq_cat_slug'),)


class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    events = db.relationship('CountdownEvent', secondary=event_tags, back_populates='tags')
    __table_args__ = (db.UniqueConstraint('name', 'user_id', name='uq_tag_name'),)


class CountdownEvent(db.Model):
    __tablename__ = 'countdown_events'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    subtitle = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'),
                            nullable=True, index=True)
    event_date = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    timezone_str = db.Column(db.String(50), default='UTC', nullable=False)
    start_date = db.Column(db.DateTime(timezone=True), nullable=True)
    thumbnail = db.Column(db.String(255), nullable=True)
    accent_color = db.Column(db.String(20), default='#7c3aed', nullable=False)
    location = db.Column(db.String(200), nullable=True)
    target_url = db.Column(db.String(500), nullable=True)
    priority = db.Column(db.String(10), default='normal', nullable=False)
    visibility = db.Column(db.String(10), default='private', nullable=False)
    recurrence = db.Column(db.String(10), nullable=True)
    is_archived = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    user = db.relationship('User', back_populates='events')
    category = db.relationship('Category', back_populates='events')
    tags = db.relationship('Tag', secondary=event_tags, back_populates='events')
    reminders = db.relationship('Reminder', back_populates='event',
                                cascade='all, delete-orphan')
    asset = db.relationship('UploadedAsset', back_populates='event',
                            uselist=False, cascade='all, delete-orphan')

    @property
    def target_timestamp(self):
        if self.event_date.tzinfo is None:
            tz = pytz.timezone(self.timezone_str or 'UTC')
            return tz.localize(self.event_date.replace(tzinfo=None)).timestamp()
        return self.event_date.astimezone(timezone.utc).timestamp()

    @property
    def has_started(self):
        return self.start_date is not None and utcnow() >= self.start_date

    @property
    def is_expired(self):
        return utcnow() >= self.event_date

    def progress_percent(self):
        if not self.start_date or self.is_expired:
            return 100.0 if self.is_expired else 0.0
        total = (self.event_date - self.start_date).total_seconds()
        elapsed = (utcnow() - self.start_date).total_seconds()
        if total <= 0:
            return 0.0
        return max(0.0, min(100.0, (elapsed / total) * 100.0))

    def duplicate(self, new_title=None):
        return CountdownEvent(
            user_id=self.user_id,
            title=new_title or f"{self.title} (Copy)",
            subtitle=self.subtitle, description=self.description,
            category_id=self.category_id, event_date=self.event_date,
            timezone_str=self.timezone_str, start_date=self.start_date,
            thumbnail=self.thumbnail, accent_color=self.accent_color,
            location=self.location, target_url=self.target_url,
            priority=self.priority, visibility=self.visibility,
            recurrence=self.recurrence,
        )


class Reminder(db.Model):
    __tablename__ = 'reminders'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('countdown_events.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    minutes_before = db.Column(db.Integer, nullable=False)
    channel = db.Column(db.String(10), default='in_app', nullable=False)
    sent = db.Column(db.Boolean, default=False, nullable=False, index=True)
    scheduled_for = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    event = db.relationship('CountdownEvent', back_populates='reminders')
    __table_args__ = (db.UniqueConstraint('event_id', 'minutes_before', 'channel',
                                           name='uq_reminder'),)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey('countdown_events.id', ondelete='SET NULL'),
                         nullable=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    user = db.relationship('User', back_populates='notifications')


class SiteSetting(db.Model):
    __tablename__ = 'site_settings'
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(120), default='ChronoPlan', nullable=False)
    site_tagline = db.Column(db.String(255), default='Plan ahead. Live in the moment.',
                             nullable=False)
    site_description = db.Column(db.Text,
        default='A personal countdown and goal management platform.', nullable=False)
    footer_text = db.Column(db.Text, default='', nullable=False)
    copyright_owner = db.Column(db.String(120), default='Md. Rakibul Hasan', nullable=False)
    logo_url = db.Column(db.String(255), default='', nullable=False)
    favicon_url = db.Column(db.String(255), default='', nullable=False)
    accent_color = db.Column(db.String(20), default='#7c3aed', nullable=False)
    default_theme = db.Column(db.String(10), default='dark', nullable=False)
    hero_title = db.Column(db.String(200), default='Count down to what matters.',
                           nullable=False)
    hero_subtitle = db.Column(db.Text,
        default="Track exams, deadlines, goals, and life's most important moments.",
        nullable=False)
    registration_enabled = db.Column(db.Boolean, default=True, nullable=False)
    maintenance_mode = db.Column(db.Boolean, default=False, nullable=False)
    default_timezone = db.Column(db.String(50), default='UTC', nullable=False)
    max_upload_mb = db.Column(db.Integer, default=16, nullable=False)
    contact_email = db.Column(db.String(120), default='', nullable=False)
    social_twitter = db.Column(db.String(255), default='', nullable=False)
    social_github = db.Column(db.String(255), default='', nullable=False)
    social_linkedin = db.Column(db.String(255), default='', nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    @classmethod
    def get(cls):
        s = cls.query.first()
        if not s:
            s = cls()
            db.session.add(s)
            db.session.commit()
        return s


class UploadedAsset(db.Model):
    __tablename__ = 'uploaded_assets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey('countdown_events.id', ondelete='CASCADE'),
                         nullable=True, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    size_bytes = db.Column(db.BigInteger, nullable=True)
    purpose = db.Column(db.String(20), default='thumbnail', nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    user = db.relationship('User')
    event = db.relationship('CountdownEvent', back_populates='asset')


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                         nullable=True)
    actor_username = db.Column(db.String(80), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    metadata_json = db.Column('metadata', db.JSON, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    actor = db.relationship('User')


class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), default='', nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                           nullable=True)
    actor = db.relationship('User')


# ════════════════════════════════════════════════════════════
# 4. FORMS
# ════════════════════════════════════════════════════════════
class LoginForm(FlaskForm):
    identifier = StringField('Email or Username',
                             validators=[DataRequired(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Sign in')


class RegistrationForm(FlaskForm):
    name = StringField('Full name', validators=[DataRequired(), Length(min=2, max=120)])
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=80),
        Regexp(r'^[A-Za-z0-9_.-]+$',
               message='Letters, numbers, dots, dashes, underscores only.')])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Password',
                             validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Create account')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username is already taken.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email is already registered.')


class ResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send reset link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New password',
                             validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset password')


class CountdownForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    subtitle = StringField('Subtitle', validators=[Optional(), Length(max=200)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=2000)])
    category_id = SelectField('Category', coerce=int, validators=[Optional()])
    event_date = DateTimeLocalField('Date & time', format='%Y-%m-%dT%H:%M',
                                    validators=[DataRequired()])
    start_date = DateTimeLocalField('Start date (for progress)',
                                    format='%Y-%m-%dT%H:%M', validators=[Optional()])
    timezone_str = SelectField(
        'Timezone',
        choices=[('Asia/Dhaka', 'Bangladesh Standard Time (Asia/Dhaka)')] +
                [(tz, tz) for tz in pytz.all_timezones if tz != 'Asia/Dhaka'],
        default='Asia/Dhaka')
    location = StringField('Location', validators=[Optional(), Length(max=200)])
    target_url = StringField('Target URL',
                              validators=[Optional(), URL(), Length(max=500)])
    accent_color = ColorField('Accent color', default='#7c3aed')
    priority = SelectField('Priority', choices=[
        ('low', 'Low'), ('normal', 'Normal'), ('high', 'High'), ('urgent', 'Urgent')],
        default='normal')
    visibility = SelectField('Visibility',
        choices=[('private', 'Private'), ('public', 'Public')], default='private')
    recurrence = SelectField('Repeat', choices=[
        ('', 'Does not repeat'), ('daily', 'Daily'), ('weekly', 'Weekly'),
        ('monthly', 'Monthly'), ('yearly', 'Yearly')], default='')
    thumbnail = FileField('Thumbnail', validators=[Optional()])
    tags = StringField('Tags (comma separated)',
                       validators=[Optional(), Length(max=200)])
    submit = SubmitField('Save')


class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=120)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Save profile')

    def __init__(self, *args, **kwargs):
        self._user_id = kwargs.pop('user_id', None)
        super().__init__(*args, **kwargs)

    def validate_username(self, field):
        q = User.query.filter(User.username == field.data)
        if self._user_id:
            q = q.filter(User.id != self._user_id)
        if q.first():
            raise ValidationError('Username is taken.')

    def validate_email(self, field):
        q = User.query.filter(User.email == field.data.lower())
        if self._user_id:
            q = q.filter(User.id != self._user_id)
        if q.first():
            raise ValidationError('Email already registered.')


class PreferencesForm(FlaskForm):
    timezone = SelectField(
        'Timezone',
        choices=[('Asia/Dhaka', 'Bangladesh Standard Time (Asia/Dhaka)')] +
                [(tz, tz) for tz in pytz.all_timezones if tz != 'Asia/Dhaka'])
    date_format = SelectField('Date format', choices=[
        ('MMM d, yyyy', 'Jan 5, 2026'),
        ('yyyy-MM-dd', '2026-01-05'),
        ('d MMM yyyy', '5 Jan 2026')])
    time_format = SelectField('Time format', choices=[
        ('HH:mm', '14:30'), ('h:mm a', '2:30 PM')])
    theme = SelectField('Theme', choices=[('dark', 'Dark'), ('light', 'Light')])
    default_view = SelectField('Default view',
        choices=[('grid', 'Grid'), ('list', 'List')])
    email_notifications = BooleanField('Email notifications')
    in_app_notifications = BooleanField('In-app notifications')
    reminder_default = SelectField('Default reminder', choices=[
        (0, 'At event time'), (5, '5 min before'), (15, '15 min before'),
        (60, '1 hour before'), (1440, '1 day before')], coerce=int)
    submit = SubmitField('Save preferences')


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current password', validators=[DataRequired()])
    new_password = PasswordField('New password',
                                 validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField('Change password')


class SiteSettingsForm(FlaskForm):
    site_name = StringField('Site name', validators=[DataRequired(), Length(max=120)])
    site_tagline = StringField('Tagline', validators=[Length(max=255)])
    site_description = TextAreaField('Description')
    hero_title = StringField('Hero title')
    hero_subtitle = TextAreaField('Hero subtitle')
    footer_text = TextAreaField('Footer text')
    copyright_owner = StringField('Copyright owner',
                                  validators=[DataRequired(), Length(max=120)])
    contact_email = StringField('Contact email', validators=[Optional(), Email()])
    accent_color = ColorField('Accent color', validators=[
        Regexp(r'^#[0-9A-Fa-f]{6}$',
               message='Enter a six-digit hex color, such as #7c3aed.')])
    default_theme = SelectField('Default theme',
        choices=[('dark', 'Dark'), ('light', 'Light')])
    default_timezone = SelectField('Default timezone')
    registration_enabled = BooleanField('Registration enabled')
    maintenance_mode = BooleanField('Maintenance mode')
    max_upload_mb = IntegerField('Max upload MB',
                                 validators=[NumberRange(min=1, max=50)])
    social_twitter = StringField('Twitter/X')
    social_github = StringField('GitHub')
    social_linkedin = StringField('LinkedIn')
    submit = SubmitField('Save settings')


class IPBlockForm(FlaskForm):
    address = StringField('IP address', validators=[
        DataRequired(), Length(max=45)])
    reason = StringField('Reason', validators=[Optional(), Length(max=255)])
    submit = SubmitField('Block IP')


class CategoryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=80)])
    description = TextAreaField('Description')
    submit = SubmitField('Save category')


class SMTPForm(FlaskForm):
    mail_server = StringField('SMTP server')
    mail_port = IntegerField('SMTP port')
    mail_username = StringField('SMTP username')
    mail_password = PasswordField('SMTP password (leave blank to keep)')
    mail_use_tls = BooleanField('Use TLS')
    mail_default_sender = StringField('Default sender')
    submit = SubmitField('Save SMTP')


# ════════════════════════════════════════════════════════════
# 5. HELPER FUNCTIONS & SERVICES
# ════════════════════════════════════════════════════════════
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def log_audit(action, target_type=None, target_id=None, metadata=None):
    entry = AuditLog(
        actor_id=current_user.id if current_user.is_authenticated else None,
        actor_username=current_user.username if current_user.is_authenticated else None,
        action=action, target_type=target_type, target_id=target_id,
        metadata_json=metadata or {},
        ip_address=request.remote_addr if request else None)
    db.session.add(entry)
    db.session.commit()
    return entry


def get_settings():
    return SiteSetting.get()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_IMAGE_EXTENSIONS']


def verify_image_content(file_storage):
    """Verify by reading actual bytes signature, not just filename."""
    file_storage.stream.seek(0)
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    signatures = [
        (b'\xff\xd8\xff', 'jpeg'),
        (b'\x89PNG\r\n\x1a\n', 'png'),
        (b'RIFF', 'webp'),
    ]
    for sig, _ in signatures:
        if head.startswith(sig):
            return True
    return False


def save_image(file_storage, user_id, purpose='thumbnail',
               event_id=None, size=None):
    """Save an uploaded image with full validation."""
    if not file_storage or not file_storage.filename:
        raise ValueError("No file provided")
    if not allowed_file(file_storage.filename):
        raise ValueError("Invalid file extension. Allowed: JPG, PNG, WebP")
    if not verify_image_content(file_storage):
        raise ValueError("File content does not match an allowed image type")

    file_storage.stream.seek(0, 2)
    size_bytes = file_storage.stream.tell()
    file_storage.stream.seek(0)
    max_bytes = app.config['MAX_CONTENT_LENGTH']
    if size_bytes > max_bytes:
        raise ValueError(f"File too large. Max {max_bytes // (1024*1024)}MB")

    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{datetime.utcnow().strftime('%Y%m%d')}_{uuid.uuid4().hex}.{ext}"
    upload_dir = app.config['UPLOAD_FOLDER']
    full_path = os.path.join(upload_dir, unique_name)

    if os.path.basename(full_path) != unique_name:
        raise ValueError("Invalid filename")

    try:
        img = Image.open(file_storage.stream)
        if img.mode in ('RGBA', 'P') and ext != 'png':
            img = img.convert('RGB')
        if size:
            img.thumbnail(size, Image.Resampling.LANCZOS)
        img.save(full_path, optimize=True, quality=85)
    except Exception as e:
        raise ValueError(f"Could not process image: {e}")

    asset = UploadedAsset(
        user_id=user_id, event_id=event_id, filename=unique_name,
        original_filename=secure_filename(file_storage.filename),
        mime_type=file_storage.mimetype, size_bytes=size_bytes,
        purpose=purpose)
    db.session.add(asset)
    db.session.commit()
    return asset


def delete_asset(asset):
    if asset is None:
        return
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], asset.filename)
    try:
        if os.path.exists(full_path):
            os.remove(full_path)
    except OSError:
        pass
    db.session.delete(asset)
    db.session.commit()


def is_email_configured():
    return bool(app.config.get('MAIL_SERVER') and app.config.get('MAIL_USERNAME'))


def send_async_email(subject, recipients, body=None, html=None):
    def send(flask_app):
        with flask_app.app_context():
            try:
                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = app.config['MAIL_DEFAULT_SENDER'] or \
                              app.config['MAIL_USERNAME']
                msg['To'] = ', '.join(recipients) if isinstance(recipients, list) \
                            else recipients
                if body:
                    msg.attach(MIMEText(body, 'plain'))
                if html:
                    msg.attach(MIMEText(html, 'html'))
                server = smtplib.SMTP(app.config['MAIL_SERVER'],
                                      app.config['MAIL_PORT'])
                if app.config['MAIL_USE_TLS']:
                    server.starttls()
                server.login(app.config['MAIL_USERNAME'],
                             app.config['MAIL_PASSWORD'])
                server.sendmail(msg['From'], recipients, msg.as_string())
                server.quit()
            except Exception as e:
                app.logger.exception(f"Email send failed: {e}")
    Thread(target=send, args=(app._get_current_object(),)).start()


def schedule_reminders(event):
    """Schedule reminders for an event based on user preferences."""
    Reminder.query.filter_by(event_id=event.id).delete()
    pref = event.user.preferences if event.user else None
    minutes_options = []
    if pref and pref.reminder_default:
        minutes_options.append(pref.reminder_default)
    minutes_options.append(0)

    for m in set(minutes_options):
        target = event.event_date - timedelta(minutes=m) if m > 0 \
                  else event.event_date
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        if target > datetime.now(timezone.utc):
            r = Reminder(
                event_id=event.id, minutes_before=m, channel='in_app',
                sent=False, scheduled_for=target)
            db.session.add(r)
    db.session.commit()


def process_pending_reminders():
    """Background job: fire any due reminders."""
    try:
        with app.app_context():
            now = datetime.now(timezone.utc)
            due = Reminder.query.filter(
                Reminder.sent == False,
                Reminder.scheduled_for <= now
            ).all()
            for r in due:
                event = r.event
                if not event:
                    r.sent = True
                    db.session.commit()
                    continue
                title = f"Reminder: {event.title}"
                minutes_label = "now" if r.minutes_before == 0 \
                                else f"in {r.minutes_before} minutes"
                message = f"'{event.title}' is happening {minutes_label}."
                notif = Notification(
                    user_id=event.user_id, event_id=event.id,
                    title=title, message=message, is_read=False)
                db.session.add(notif)
                pref = event.user.preferences
                if pref and pref.email_notifications and is_email_configured():
                    try:
                        send_async_email(subject=title,
                                         recipients=[event.user.email],
                                         body=message)
                    except Exception:
                        app.logger.exception("Email reminder failed")
                r.sent = True
                r.sent_at = now
            db.session.commit()
    except Exception as e:
        app.logger.exception(f"Reminder error: {e}")
        db.session.rollback()


# Start background scheduler (skip in testing)
if not app.config.get('TESTING'):
    try:
        _scheduler = BackgroundScheduler(daemon=True)
        _scheduler.start()
        atexit.register(lambda: _scheduler.shutdown(wait=False))
        _scheduler.add_job(
            process_pending_reminders,
            IntervalTrigger(minutes=1),
            id='process-reminders', replace_existing=True)
    except Exception:
        pass


# ════════════════════════════════════════════════════════════
# 6. USER LOADER
# ════════════════════════════════════════════════════════════
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ════════════════════════════════════════════════════════════
# 7. CONTEXT PROCESSOR
# ════════════════════════════════════════════════════════════
@app.context_processor
def inject_globals():
    try:
        s = get_settings()
        return {
            'site_name': s.site_name,
            'site_tagline': s.site_tagline,
            'site_description': s.site_description,
            'footer_text': s.footer_text,
            'copyright_owner': s.copyright_owner,
            'logo_url': s.logo_url,
            'favicon_url': s.favicon_url,
            'accent_color': s.accent_color,
            'default_theme': s.default_theme,
            'maintenance_mode': s.maintenance_mode,
            'registration_enabled': s.registration_enabled,
            'current_year': datetime.utcnow().year,
        }
    except Exception:
        return {
            'site_name': 'ChronoPlan', 'site_tagline': '',
            'site_description': '', 'footer_text': '',
            'copyright_owner': 'Md. Rakibul Hasan',
            'logo_url': '', 'favicon_url': '',
            'accent_color': '#7c3aed',
            'default_theme': 'dark',
            'maintenance_mode': False,
            'registration_enabled': True,
            'current_year': datetime.utcnow().year,
        }


@app.context_processor
def inject_unread_notifications():
    unread = 0
    if current_user.is_authenticated:
        unread = Notification.query.filter_by(
            user_id=current_user.id, is_read=False
        ).count()
    return {'unread_notifications': unread}


@app.before_request
def reject_blocked_ip():
    remote_addr = request.remote_addr
    if not remote_addr:
        return
    try:
        address = ipaddress.ip_address(remote_addr).compressed
    except ValueError:
        return
    if BlockedIP.query.filter_by(address=address).first():
        abort(403)


# ════════════════════════════════════════════════════════════
# 8. SECURITY HEADERS
# ════════════════════════════════════════════════════════════
@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('X-XSS-Protection', '1; mode=block')
    resp.headers.setdefault('Referrer-Policy',
                           'strict-origin-when-cross-origin')
    return resp


# ════════════════════════════════════════════════════════════
# 9. BEFORE-REQUEST HOOKS
# ════════════════════════════════════════════════════════════
@app.before_request
def check_maintenance():
    try:
        s = get_settings()
        if s.maintenance_mode:
            public = ['static', 'serve_upload', 'login']
            if request.endpoint and request.endpoint not in public:
                if not (current_user.is_authenticated and current_user.is_admin):
                    return render_template('errors/maintenance.html'), 503
    except Exception:
        pass


@app.before_request
def admin_gate():
    """Block non-admins from admin routes."""
    if request.endpoint and request.endpoint.startswith('admin_'):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if not current_user.is_admin:
            abort(403)


# ════════════════════════════════════════════════════════════
# 10. UPLOAD SERVING
# ════════════════════════════════════════════════════════════
@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    safe = os.path.basename(filename)
    if safe != filename:
        abort(404)
    full = os.path.join(app.config['UPLOAD_FOLDER'], safe)
    if not os.path.exists(full):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe)


# ════════════════════════════════════════════════════════════
# 11. AUTH ROUTES
# ════════════════════════════════════════════════════════════
@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_index'))
    s = get_settings()
    return render_template('landing.html', settings=s)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_index'))
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        user = User.query.filter(
            (User.email == identifier.lower()) |
            (User.username == identifier)
        ).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid credentials.', 'error')
            return render_template('auth/login.html', form=form)
        if not user.is_active_user:
            flash('Account suspended. Contact the administrator.', 'error')
            return render_template('auth/login.html', form=form)
        login_user(user, remember=form.remember.data)
        user.last_seen = datetime.now(timezone.utc)
        db.session.commit()
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('dashboard_index')
        flash(f'Welcome back, {user.name}!', 'success')
        return redirect(next_page)
    return render_template('auth/login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_index'))
    s = get_settings()
    if not s.registration_enabled:
        flash('Registration is currently disabled.', 'warning')
        return redirect(url_for('login'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data.lower(),
            email_verified=not is_email_configured())
        user.set_password(form.password.data)
        db.session.add(user)
        pref = UserPreference(user=user)
        db.session.add(pref)
        db.session.commit()
        flash('Account created. You can sign in now.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Signed out.', 'info')
    return redirect(url_for('landing'))


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_index'))
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.get_reset_token()
            if is_email_configured():
                reset_url = url_for('reset_password', token=token, _external=True)
                send_async_email(
                    subject='Password reset request',
                    recipients=[user.email],
                    body=f'Reset your password: {reset_url}\n'
                         f'This link expires in 1 hour.')
        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/reset_request.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_index'))
    user = User.verify_reset_token(token)
    if not user:
        flash('Reset link invalid or expired.', 'error')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Password updated. Sign in with your new password.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/reset_password.html', form=form, token=token)


# ════════════════════════════════════════════════════════════
# 12. DASHBOARD ROUTES
# ════════════════════════════════════════════════════════════
@app.route('/dashboard')
@login_required
def dashboard_index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '', type=str).strip()
    category_id = request.args.get('category', 0, type=int)
    sort = request.args.get('sort', 'date_asc')
    view = request.args.get(
        'view',
        current_user.preferences.default_view
        if current_user.preferences else 'grid')
    show_archived = request.args.get('archived', 'false') == 'true'

    q = CountdownEvent.query.filter_by(user_id=current_user.id)
    if not show_archived:
        q = q.filter_by(is_archived=False)
    if search:
        q = q.filter(CountdownEvent.title.ilike(f'%{search}%'))
    if category_id:
        q = q.filter_by(category_id=category_id)

    sort_map = {
        'date_asc': CountdownEvent.event_date.asc(),
        'date_desc': CountdownEvent.event_date.desc(),
        'created_desc': CountdownEvent.created_at.desc(),
    }
    q = q.order_by(sort_map.get(sort, CountdownEvent.event_date.asc()))
    pagination = q.paginate(page=page, per_page=12, error_out=False)
    categories = Category.query.filter(
        (Category.user_id == current_user.id) |
        (Category.is_global == True)
    ).all()

    now = datetime.now(timezone.utc)
    active_count = CountdownEvent.query.filter_by(
        user_id=current_user.id, is_archived=False
    ).filter(CountdownEvent.event_date > now).count()
    today_count = CountdownEvent.query.filter_by(
        user_id=current_user.id
    ).filter(db.func.date(CountdownEvent.event_date) == now.date()).count()
    completed_count = CountdownEvent.query.filter_by(
        user_id=current_user.id, is_completed=True
    ).count()
    unread = Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).count()

    return render_template('dashboard/index.html',
        events=pagination.items, pagination=pagination,
        categories=categories, search=search,
        selected_category=category_id, sort=sort, view=view,
        show_archived=show_archived,
        active_count=active_count, today_count=today_count,
        completed_count=completed_count, unread_notifications=unread)


@app.route('/dashboard/api/countdowns')
@login_required
def api_countdowns():
    events = CountdownEvent.query.filter_by(
        user_id=current_user.id, is_archived=False
    ).all()
    data = []
    for e in events:
        data.append({
            'id': e.id, 'title': e.title,
            'target': e.target_timestamp,
            'accent': e.accent_color,
            'progress': e.progress_percent() if e.start_date else None,
            'expired': e.is_expired,
        })
    return jsonify(data)


@app.route('/dashboard/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    notifs = Notification.query.filter_by(user_id=current_user.id) \
        .order_by(Notification.created_at.desc())
    pagination = notifs.paginate(page=page, per_page=20, error_out=False)
    return render_template('dashboard/notifications.html',
        notifications=pagination.items, pagination=pagination)


@app.route('/dashboard/notifications/<int:nid>/read', methods=['POST'])
@login_required
def mark_notification_read(nid):
    n = Notification.query.filter_by(
        id=nid, user_id=current_user.id
    ).first_or_404()
    n.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok'})


@app.route('/dashboard/notifications/read-all', methods=['POST'])
@login_required
def mark_all_read():
    Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).update({'is_read': True})
    db.session.commit()
    return jsonify({'status': 'ok'})


@app.route('/dashboard/settings', methods=['GET', 'POST'])
@login_required
def dashboard_settings():
    profile_form = ProfileForm(obj=current_user, user_id=current_user.id)
    pref_form = PreferencesForm(obj=current_user.preferences)
    pw_form = PasswordChangeForm()

    if request.method == 'POST':
        # Profile picture upload
        if request.files.get('profile_picture'):
            try:
                old = UploadedAsset.query.filter_by(
                    user_id=current_user.id, purpose='profile'
                ).first()
                if old:
                    delete_asset(old)
                asset = save_image(
                    request.files['profile_picture'],
                    current_user.id, purpose='profile',
                    size=app.config['PROFILE_SIZE'])
                current_user.profile_picture = asset.filename
                db.session.commit()
                flash('Profile picture updated.', 'success')
            except ValueError as e:
                flash(str(e), 'error')
            return redirect(url_for('dashboard_settings'))

        form_type = request.form.get('form_type')

        if form_type == 'profile' and profile_form.validate_on_submit():
            current_user.name = profile_form.name.data
            current_user.username = profile_form.username.data
            current_user.email = profile_form.email.data
            db.session.commit()
            flash('Profile updated.', 'success')
            return redirect(url_for('dashboard_settings'))

        if form_type == 'preferences' and pref_form.validate_on_submit():
            pref = current_user.preferences
            pref.timezone = pref_form.timezone.data
            pref.theme = pref_form.theme.data
            pref.default_view = pref_form.default_view.data
            pref.date_format = pref_form.date_format.data
            pref.time_format = pref_form.time_format.data
            pref.email_notifications = pref_form.email_notifications.data
            pref.in_app_notifications = pref_form.in_app_notifications.data
            pref.reminder_default = pref_form.reminder_default.data
            db.session.commit()
            flash('Preferences saved.', 'success')
            return redirect(url_for('dashboard_settings'))

        if form_type == 'password' and pw_form.validate_on_submit():
            if not current_user.check_password(pw_form.current_password.data):
                flash('Current password is incorrect.', 'error')
            else:
                current_user.set_password(pw_form.new_password.data)
                db.session.commit()
                flash('Password changed.', 'success')
                return redirect(url_for('dashboard_settings'))

    return render_template('dashboard/settings.html',
        profile_form=profile_form,
        pref_form=pref_form,
        pw_form=pw_form)


@app.route('/dashboard/profile/picture/delete', methods=['POST'])
@login_required
def delete_profile_picture():
    asset = UploadedAsset.query.filter_by(
        user_id=current_user.id, purpose='profile'
    ).first()
    if asset:
        delete_asset(asset)
        current_user.profile_picture = None
        db.session.commit()
    flash('Profile picture removed.', 'info')
    return redirect(url_for('dashboard_settings'))


@app.route('/dashboard/account/delete', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('confirm_password', '')
    if not current_user.check_password(password):
        flash('Incorrect password.', 'error')
        return redirect(url_for('dashboard_settings'))
    user = current_user
    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash('Account deleted.', 'info')
    return redirect(url_for('landing'))


# ════════════════════════════════════════════════════════════
# 13. COUNTDOWN ROUTES
# ════════════════════════════════════════════════════════════
def populate_categories(form):
    cats = Category.query.filter(
        (Category.user_id == current_user.id) |
        (Category.is_global == True)
    ).all()
    form.category_id.choices = [(0, '— No category —')] + \
        [(c.id, c.name) for c in cats]


@app.route('/events/new', methods=['GET', 'POST'])
@login_required
def new_event():
    form = CountdownForm()
    populate_categories(form)
    if form.validate_on_submit():
        tz = pytz.timezone(form.timezone_str.data)
        naive = form.event_date.data
        local_dt = tz.localize(naive) if naive.tzinfo is None else naive
        utc_dt = local_dt.astimezone(timezone.utc)

        start_utc = None
        if form.start_date.data:
            sn = form.start_date.data
            sl = tz.localize(sn) if sn.tzinfo is None else sn
            start_utc = sl.astimezone(timezone.utc)

        event = CountdownEvent(
            user_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            description=form.description.data,
            category_id=form.category_id.data or None,
            event_date=utc_dt,
            timezone_str=form.timezone_str.data,
            start_date=start_utc,
            location=form.location.data,
            target_url=form.target_url.data,
            accent_color=form.accent_color.data,
            priority=form.priority.data,
            visibility=form.visibility.data,
            recurrence=form.recurrence.data or None)
        db.session.add(event)
        db.session.flush()

        if form.tags.data:
            for name in [t.strip() for t in form.tags.data.split(',') if t.strip()]:
                tag = Tag.query.filter_by(name=name, user_id=current_user.id).first()
                if not tag:
                    tag = Tag(name=name, user_id=current_user.id)
                    db.session.add(tag)
                event.tags.append(tag)

        if form.thumbnail.data and form.thumbnail.data.filename:
            try:
                asset = save_image(
                    form.thumbnail.data, current_user.id,
                    purpose='thumbnail', event_id=event.id,
                    size=app.config['THUMBNAIL_SIZE'])
                event.thumbnail = asset.filename
            except ValueError as e:
                flash(f'Thumbnail error: {e}', 'warning')

        db.session.commit()
        schedule_reminders(event)
        flash('Event created.', 'success')
        return redirect(url_for('dashboard_index'))
    return render_template('countdowns/form.html', form=form, mode='new')


@app.route('/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = CountdownEvent.query.filter_by(
        id=event_id, user_id=current_user.id
    ).first_or_404()
    form = CountdownForm()
    populate_categories(form)

    if form.validate_on_submit():
        tz = pytz.timezone(form.timezone_str.data)
        naive = form.event_date.data
        local_dt = tz.localize(naive) if naive.tzinfo is None else naive
        event.event_date = local_dt.astimezone(timezone.utc)

        if form.start_date.data:
            sn = form.start_date.data
            sl = tz.localize(sn) if sn.tzinfo is None else sn
            event.start_date = sl.astimezone(timezone.utc)
        else:
            event.start_date = None

        event.title = form.title.data
        event.subtitle = form.subtitle.data
        event.description = form.description.data
        event.category_id = form.category_id.data or None
        event.timezone_str = form.timezone_str.data
        event.location = form.location.data
        event.target_url = form.target_url.data
        event.accent_color = form.accent_color.data
        event.priority = form.priority.data
        event.visibility = form.visibility.data
        event.recurrence = form.recurrence.data or None

        event.tags = []
        if form.tags.data:
            for name in [t.strip() for t in form.tags.data.split(',') if t.strip()]:
                tag = Tag.query.filter_by(name=name, user_id=current_user.id).first()
                if not tag:
                    tag = Tag(name=name, user_id=current_user.id)
                    db.session.add(tag)
                event.tags.append(tag)

        if form.thumbnail.data and form.thumbnail.data.filename:
            try:
                if event.asset:
                    delete_asset(event.asset)
                asset = save_image(
                    form.thumbnail.data, current_user.id,
                    purpose='thumbnail', event_id=event.id,
                    size=app.config['THUMBNAIL_SIZE'])
                event.thumbnail = asset.filename
            except ValueError as e:
                flash(f'Thumbnail error: {e}', 'warning')

        db.session.commit()
        schedule_reminders(event)
        flash('Event updated.', 'success')
        return redirect(url_for('dashboard_index'))

    if request.method == 'GET':
        tz = pytz.timezone(event.timezone_str or 'UTC')
        local_dt = event.event_date
        if event.event_date.tzinfo is None:
            local_dt = pytz.utc.localize(event.event_date)
        local_dt = local_dt.astimezone(tz)
        form.event_date.data = local_dt.replace(tzinfo=None)
        if event.start_date:
            sl = event.start_date
            if event.start_date.tzinfo is None:
                sl = pytz.utc.localize(event.start_date)
            sl = sl.astimezone(tz)
            form.start_date.data = sl.replace(tzinfo=None)
        form.title.data = event.title
        form.subtitle.data = event.subtitle
        form.description.data = event.description
        form.category_id.data = event.category_id or 0
        form.timezone_str.data = event.timezone_str
        form.location.data = event.location
        form.target_url.data = event.target_url
        form.accent_color.data = event.accent_color
        form.priority.data = event.priority
        form.visibility.data = event.visibility
        form.recurrence.data = event.recurrence or ''
        form.tags.data = ', '.join([t.name for t in event.tags])

    return render_template('countdowns/form.html', form=form,
                           mode='edit', event=event)


@app.route('/events/<int:event_id>/view')
@login_required
def view_event(event_id):
    event = CountdownEvent.query.filter_by(
        id=event_id, user_id=current_user.id
    ).first_or_404()
    return render_template('countdowns/view.html', event=event)


@app.route('/events/<int:event_id>/duplicate', methods=['POST'])
@login_required
def duplicate_event(event_id):
    event = CountdownEvent.query.filter_by(
        id=event_id, user_id=current_user.id
    ).first_or_404()
    clone = event.duplicate()
    db.session.add(clone)
    db.session.commit()
    schedule_reminders(clone)
    flash('Event duplicated.', 'success')
    return redirect(url_for('dashboard_index'))


@app.route('/events/<int:event_id>/archive', methods=['POST'])
@login_required
def archive_event(event_id):
    event = CountdownEvent.query.filter_by(
        id=event_id, user_id=current_user.id
    ).first_or_404()
    event.is_archived = not event.is_archived
    db.session.commit()
    flash('Event archived.' if event.is_archived else 'Event restored.', 'info')
    return redirect(url_for('dashboard_index'))


@app.route('/events/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    event = CountdownEvent.query.filter_by(
        id=event_id, user_id=current_user.id
    ).first_or_404()
    if event.asset:
        delete_asset(event.asset)
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted.', 'info')
    return redirect(url_for('dashboard_index'))


@app.route('/events/<int:event_id>/thumbnail/delete', methods=['POST'])
@login_required
def delete_thumbnail(event_id):
    event = CountdownEvent.query.filter_by(
        id=event_id, user_id=current_user.id
    ).first_or_404()
    if event.asset:
        delete_asset(event.asset)
        event.thumbnail = None
        db.session.commit()
        flash('Thumbnail removed.', 'info')
    return redirect(url_for('edit_event', event_id=event.id))


# ════════════════════════════════════════════════════════════
# 14. ADMIN ROUTES
# ════════════════════════════════════════════════════════════
@app.route('/admin')
@login_required
@admin_required
def admin_overview():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active_user=True).count()
    total_events = CountdownEvent.query.count()
    upcoming = CountdownEvent.query.filter(
        CountdownEvent.event_date > datetime.now(timezone.utc)
    ).count()
    recent = User.query.order_by(User.created_at.desc()).limit(5).all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('admin/overview.html',
        total_users=total_users, active_users=active_users,
        total_events=total_events, upcoming=upcoming,
        recent_users=recent, logs=logs)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '', type=str).strip()
    q = User.query
    if search:
        q = q.filter(User.username.ilike(f'%{search}%') |
                     User.email.ilike(f'%{search}%'))
    pagination = q.order_by(User.created_at.desc()) \
        .paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/users.html',
        users=pagination.items, pagination=pagination, search=search)


@app.route('/admin/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user_active(user_id):
    if user_id == current_user.id:
        flash("You can't suspend your own account.", 'error')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    user.is_active_user = not user.is_active_user
    db.session.commit()
    log_audit('toggle_user_active', 'user', user.id,
              {'active': user.is_active_user})
    flash(f"User {user.username} "
          f"{'activated' if user.is_active_user else 'suspended'}.", 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    if user_id == current_user.id:
        flash("You can't change your own role.", 'error')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    user.role = Role.ADMIN if user.role == Role.USER else Role.USER
    db.session.commit()
    log_audit('toggle_admin', 'user', user.id, {'role': user.role})
    flash(f"{user.username} role updated.", 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash("You can't delete your own account.", 'error')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    name = user.username
    db.session.delete(user)
    db.session.commit()
    log_audit('delete_user', 'user', user_id, {'username': name})
    flash(f"User {name} deleted.", 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/ip-blocks', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_ip_blocks():
    form = IPBlockForm()
    if form.validate_on_submit():
        try:
            address = ipaddress.ip_address(form.address.data.strip()).compressed
        except ValueError:
            flash('Enter a valid IPv4 or IPv6 address.', 'error')
        else:
            remote_addr = request.remote_addr
            try:
                current_address = (
                    ipaddress.ip_address(remote_addr).compressed
                    if remote_addr else None)
            except ValueError:
                current_address = None
            if address == current_address:
                flash("You can't block the IP address you're currently using.", 'error')
            elif BlockedIP.query.filter_by(address=address).first():
                flash('That IP address is already blocked.', 'warning')
            else:
                blocked = BlockedIP(
                    address=address,
                    reason=form.reason.data or '',
                    created_by=current_user.id)
                db.session.add(blocked)
                db.session.commit()
                log_audit('block_ip', 'ip_address', blocked.id,
                          {'address': address})
                flash(f'Blocked {address}.', 'success')
                return redirect(url_for('admin_ip_blocks'))
    blocks = BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()
    return render_template('admin/ip_blocks.html', form=form, blocks=blocks)


@app.route('/admin/ip-blocks/<int:block_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_unblock_ip(block_id):
    blocked = BlockedIP.query.get_or_404(block_id)
    address = blocked.address
    db.session.delete(blocked)
    db.session.commit()
    log_audit('unblock_ip', 'ip_address', block_id, {'address': address})
    flash(f'Unblocked {address}.', 'success')
    return redirect(url_for('admin_ip_blocks'))


@app.route('/admin/branding', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_branding():
    s = get_settings()
    form = SiteSettingsForm(obj=s)
    form.default_timezone.choices = [
        ('Asia/Dhaka', 'Bangladesh Standard Time (Asia/Dhaka)')] + [
            (tz, tz) for tz in pytz.all_timezones if tz != 'Asia/Dhaka']

    if request.method == 'POST':
        if form.validate_on_submit():
            s.site_name = form.site_name.data
            s.site_tagline = form.site_tagline.data
            s.site_description = form.site_description.data
            s.hero_title = form.hero_title.data
            s.hero_subtitle = form.hero_subtitle.data
            s.footer_text = form.footer_text.data
            s.copyright_owner = form.copyright_owner.data
            s.contact_email = form.contact_email.data
            s.accent_color = form.accent_color.data
            s.default_theme = form.default_theme.data
            s.default_timezone = form.default_timezone.data
            s.registration_enabled = form.registration_enabled.data
            s.maintenance_mode = form.maintenance_mode.data
            s.max_upload_mb = form.max_upload_mb.data
            s.social_twitter = form.social_twitter.data
            s.social_github = form.social_github.data
            s.social_linkedin = form.social_linkedin.data
            db.session.commit()
            log_audit('update_branding', 'site_setting', s.id)
            flash('Website settings saved.', 'success')

            uploads = (
                ('logo', 'logo', (300, 80), 'logo_url', 'Logo'),
                ('favicon', 'favicon', (64, 64), 'favicon_url', 'Favicon'),
            )
            for field_name, purpose, size, setting_name, label in uploads:
                uploaded_file = request.files.get(field_name)
                if not uploaded_file or not uploaded_file.filename:
                    continue
                try:
                    asset = save_image(
                        uploaded_file, current_user.id,
                        purpose=purpose, size=size)
                except ValueError as error:
                    flash(f'{label} upload failed: {error}', 'error')
                    continue

                old_asset = UploadedAsset.query.filter_by(
                    user_id=current_user.id, purpose=purpose
                ).filter(UploadedAsset.id != asset.id).first()
                setattr(s, setting_name, asset.filename)
                if old_asset:
                    delete_asset(old_asset)
                else:
                    db.session.commit()
                log_audit(f'upload_{purpose}', 'uploaded_asset', asset.id)
                flash(f'{label} updated.', 'success')

            return redirect(url_for('admin_branding'))
        flash('Please correct the highlighted settings and try again.', 'error')

    return render_template('admin/branding.html', form=form, settings=s)


@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_profile():
    if request.method == 'POST' and request.files.get('profile_picture'):
        try:
            old = UploadedAsset.query.filter_by(
                user_id=current_user.id, purpose='profile').first()
            if old:
                delete_asset(old)
            asset = save_image(
                request.files['profile_picture'], current_user.id,
                purpose='profile', size=app.config['PROFILE_SIZE'])
            current_user.profile_picture = asset.filename
            db.session.commit()
            log_audit('upload_admin_profile', 'uploaded_asset', asset.id)
            flash('Profile picture updated.', 'success')
        except ValueError as e:
            flash(str(e), 'error')
        return redirect(url_for('admin_profile'))
    return render_template('admin/profile.html')


@app.route('/admin/categories', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_categories():
    form = CategoryForm()
    if form.validate_on_submit():
        slug = form.name.data.lower().replace(' ', '-')
        existing = Category.query.filter_by(slug=slug, is_global=True).first()
        if existing:
            flash('Category already exists.', 'error')
        else:
            c = Category(name=form.name.data, slug=slug,
                        description=form.description.data, is_global=True)
            db.session.add(c)
            db.session.commit()
            log_audit('create_category', 'category', c.id, {'name': c.name})
            flash('Category created.', 'success')
        return redirect(url_for('admin_categories'))
    cats = Category.query.filter_by(is_global=True).all()
    return render_template('admin/categories.html', form=form, categories=cats)


@app.route('/admin/categories/<int:cat_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_category(cat_id):
    c = Category.query.get_or_404(cat_id)
    name = c.name
    db.session.delete(c)
    db.session.commit()
    log_audit('delete_category', 'category', cat_id, {'name': name})
    flash('Category deleted.', 'info')
    return redirect(url_for('admin_categories'))


@app.route('/admin/settings/smtp', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_smtp():
    form = SMTPForm()
    if form.validate_on_submit():
        if form.mail_password.data:
            app.config['MAIL_PASSWORD'] = form.mail_password.data
        app.config['MAIL_SERVER'] = form.mail_server.data
        app.config['MAIL_PORT'] = form.mail_port.data
        app.config['MAIL_USERNAME'] = form.mail_username.data
        app.config['MAIL_USE_TLS'] = form.mail_use_tls.data
        app.config['MAIL_DEFAULT_SENDER'] = form.mail_default_sender.data
        log_audit('update_smtp', 'app_config', None,
                  {'server': form.mail_server.data})
        flash('SMTP settings saved (configure .env for persistence).',
              'success')
        return redirect(url_for('admin_smtp'))
    if request.method == 'GET':
        form.mail_server.data = app.config.get('MAIL_SERVER', '')
        form.mail_port.data = app.config.get('MAIL_PORT', 587)
        form.mail_username.data = app.config.get('MAIL_USERNAME', '')
        form.mail_use_tls.data = app.config.get('MAIL_USE_TLS', True)
        form.mail_default_sender.data = app.config.get(
            'MAIL_DEFAULT_SENDER', '')
    return render_template('admin/smtp.html', form=form)


@app.route('/admin/audit-logs')
@login_required
@admin_required
def admin_audit_logs():
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()) \
        .paginate(page=page, per_page=50, error_out=False)
    return render_template('admin/audit_logs.html',
        logs=pagination.items, pagination=pagination)


@app.route('/admin/content')
@login_required
@admin_required
def admin_content():
    return render_template('admin/content.html')


# ════════════════════════════════════════════════════════════
# 15. CLI COMMANDS
# ════════════════════════════════════════════════════════════
DEFAULT_CATEGORIES = [
    ('Exams', 'exams', 'Academic examinations and tests'),
    ('Personal Goals', 'personal-goals', 'Personal milestones'),
    ('Work', 'work', 'Work-related deadlines'),
    ('Projects', 'projects', 'Project launches and milestones'),
    ('Travel', 'travel', 'Trips and travel plans'),
    ('Birthdays', 'birthdays', 'Birthday reminders'),
    ('Other', 'other', 'Miscellaneous events'),
]


@app.cli.command('init-db')
def init_db():
    """Initialize the database with tables and defaults."""
    db.create_all()
    SiteSetting.get()
    for name, slug, desc in DEFAULT_CATEGORIES:
        existing = Category.query.filter_by(slug=slug, is_global=True).first()
        if not existing:
            c = Category(name=name, slug=slug, description=desc,
                        is_global=True, user_id=None)
            db.session.add(c)
    db.session.commit()
    click.echo("Database initialized.")


@app.cli.command('create-admin')
@click.option('--username', prompt=True)
@click.option('--email', prompt=True)
@click.option('--name', prompt=True)
def create_admin(username, email, name):
    """Create an administrator account interactively."""
    if User.query.filter_by(username=username).first():
        click.echo("Username already taken.")
        return
    if User.query.filter_by(email=email).first():
        click.echo("Email already registered.")
        return
    password = getpass.getpass("Password (min 8 chars): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        click.echo("Passwords do not match.")
        return
    user = User(name=name, username=username, email=email,
               role=Role.ADMIN, email_verified=True)
    user.set_password(password)
    db.session.add(user)
    pref = UserPreference(user=user)
    db.session.add(pref)
    db.session.commit()
    click.echo(f"Admin {username} created successfully.")


# ════════════════════════════════════════════════════════════
# 16. ERROR HANDLERS
# ════════════════════════════════════════════════════════════
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(413)
def too_large(e):
    return render_template('errors/413.html'), 413


@app.errorhandler(429)
def too_many(e):
    return render_template('errors/429.html'), 429


@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500


# ════════════════════════════════════════════════════════════
# 17. MAIN
# ════════════════════════════════════════════════════════════
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=True)