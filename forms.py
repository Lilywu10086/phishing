from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Please enter username')])
    password = PasswordField('Password', validators=[DataRequired(message='Please enter password')])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Please enter username'),
        Length(min=3, max=20, message='Username must be between 3-20 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Please enter email'),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Please enter password'),
        Length(min=6, message='Password must be at least 6 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm password'),
        EqualTo('password', message='Passwords do not match')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken, please choose another one')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered, please use another email')

class BatchDetectionForm(FlaskForm):
    urls_text = TextAreaField('URL List', validators=[
        DataRequired(message='Please enter URLs to detect')
    ], description='One URL per line, supports up to 50 URLs')
    submit = SubmitField('Start Batch Detection')
    
    def validate_urls_text(self, urls_text):
        urls = urls_text.data.strip().split('\n')
        urls = [url.strip() for url in urls if url.strip()]
        
        if len(urls) == 0:
            raise ValidationError('Please enter at least one URL')
        
        if len(urls) > 50:
            raise ValidationError('Maximum 50 URLs can be detected at once')
        
        # Validate URL format
        import re
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        invalid_urls = []
        for url in urls:
            if not url_pattern.match(url):
                invalid_urls.append(url)
        
        if invalid_urls:
            raise ValidationError(f'Invalid URL format: {", ".join(invalid_urls[:5])}') 