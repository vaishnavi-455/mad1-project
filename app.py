from sqlite3 import IntegrityError
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iitmtest.db'
app.config['SECRET_KEY'] = 'iitm'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    industry = db.Column(db.String(100))  
    niche = db.Column(db.String(100))  
    followers = db.Column(db.Integer) 
    flagged = db.Column(db.Boolean, default=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sponsorid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    budget = db.Column(db.Float, nullable=False) 
    visibility = db.Column(db.String(100), nullable=False)  
    goals = db.Column(db.Text, nullable=False) 
    ad_requests = db.relationship('AdRequest', backref='campaign', lazy=True)
    startdate = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    enddate = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencerid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requirements = db.Column(db.String(255), nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    proposed_amount = db.Column(db.Float)
    status = db.Column(db.String(50), nullable=False)
    influencer = db.relationship('User', foreign_keys=[influencerid], backref='ad_requests')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password, role=role)
        if role == 'sponsor':
            user.industry = request.form['industry']
        elif role == 'influencer':
            user.niche = request.form['niche']
            user.followers = request.form['followers']
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'sponsor':
                return redirect(url_for('sponsor_dashboard'))
            elif user.role == 'influencer':
                return redirect(url_for('influencer_dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/home')
@login_required
def homepage():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'sponsor':
        return redirect(url_for('sponsor_dashboard'))
    elif current_user.role == 'influencer':
        return redirect(url_for('influencer_dashboard'))
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    users = User.query.all()
    campaigns = Campaign.query.all()
    ad_requests = db.session.query(AdRequest, User.username).join(User, AdRequest.influencerid == User.id).all()
    accepted_influencers = {}
    for campaign in campaigns:
        accepted = db.session.query(User.username, AdRequest.payment_amount).join(AdRequest, AdRequest.influencerid == User.id).filter(
            AdRequest.campaign_id == campaign.id,
            AdRequest.status == 'accepted'
        ).all()
        accepted_influencers[campaign.id] = accepted

    return render_template('admin_dashboard.html', users=users, campaigns=campaigns, ad_requests=ad_requests, accepted_influencers=accepted_influencers)
@app.route('/sponsor_dashboard')
@login_required
def sponsor_dashboard():
    if current_user.role != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))
    campaigns = Campaign.query.filter_by(sponsorid=current_user.id).all()
    
    campaign_id = request.args.get('campaign_id')
    if campaign_id:
        ad_requests = db.session.query(AdRequest, User.username).join(User, AdRequest.influencerid == User.id).filter(AdRequest.campaign_id == campaign_id).all()
    else:
        ad_requests = db.session.query(AdRequest, User.username).join(User, AdRequest.influencerid == User.id).filter(AdRequest.campaign_id.in_([c.id for c in campaigns])).all()
    accepted_influencers = {}
    for campaign in campaigns:
        accepted = db.session.query(User.username).join(AdRequest, AdRequest.influencerid == User.id).filter(
            AdRequest.campaign_id == campaign.id,
            AdRequest.status == 'accepted'
        ).all()
        accepted_influencers[campaign.id] = [a[0] for a in accepted]

    return render_template('sponsor_dashboard.html', campaigns=campaigns, ad_requests=ad_requests, accepted_influencers=accepted_influencers)

@app.route('/influencer_dashboard')
@login_required
def influencer_dashboard():
    if current_user.role != 'influencer':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))
    
    ad_requests = AdRequest.query.filter_by(influencerid=current_user.id).all()
    return render_template('influencer_dashboard.html', ad_requests=ad_requests)

@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
def create_campaign():
    if current_user.role != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        budget = request.form['budget']
        visibility = request.form['visibility']
        goals = request.form['goals']
        startdate = datetime.strptime(request.form['startdate'],'%Y-%m-%d')
        enddate = datetime.strptime(request.form['enddate'],'%Y-%m-%d')

        campaign = Campaign(name=name, sponsorid=current_user.id, budget=budget, visibility=visibility, goals=goals, startdate=startdate, enddate=enddate)
        db.session.add(campaign)
        db.session.commit()

        flash('Campaign created successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('create_campaign.html')

@app.route('/search_campaigns', methods=['GET', 'POST'])
def search_campaigns():
    if request.method == 'POST':
        search_query = request.form['search']
        campaigns = Campaign.query.filter(Campaign.name.contains(search_query)).all()
    else:
        campaigns = Campaign.query.all()
    return render_template('search_campaigns.html', campaigns=campaigns)

@app.route('/update_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def update_campaign(campaign_id):
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))
    
    if current_user.role != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsorid != current_user.id:
        flash('Cannot enter this page.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    if request.method == 'POST':
        campaign.name = request.form['name']
        campaign.budget = request.form['budget']
        campaign.visibility = request.form['visibility']
        campaign.goals = request.form['goals']
        campaign.startdate = datetime.strptime(request.form['startdate'],'%Y-%m-%d')
        campaign.enddate = datetime.strptime(request.form['enddate'],'%Y-%m-%d')
        db.session.commit()
        flash('Campaign updated successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('update_campaign.html', campaign=campaign)


@app.route('/delete_campaign/<int:campaign_id>')
@login_required
def delete_campaign(campaign_id):
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))
    campaign = Campaign.query.get_or_404(campaign_id)
    if current_user.role != 'admin' and campaign.sponsorid != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    ad_requests = AdRequest.query.filter_by(campaign_id=campaign.id).all()
    for ad_request in ad_requests:
        db.session.delete(ad_request)

    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign and associated ad requests deleted successfully!', 'success')
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('sponsor_dashboard'))



@app.route('/send_request/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def send_request(campaign_id):
    
    if current_user.role != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsorid != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    influencers = User.query.filter_by(role='influencer').all()

    if request.method == 'POST':
        influencer_id = request.form['influencer_id']
        requirements = request.form['requirements']
        payment_amount = request.form['payment_amount']

        ad_request = AdRequest(campaign_id=campaign_id, influencerid=influencer_id, requirements=requirements, payment_amount=payment_amount, status='pending')
        db.session.add(ad_request)
        db.session.commit()

        flash('Ad request sent!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('send_request.html', campaign=campaign, influencers=influencers)

@app.route('/respond_request/<int:ad_request_id>/<string:action>', methods=['GET', 'POST'])
@login_required
def respond_request(ad_request_id, action):
    if current_user.role != 'influencer':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))

    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.influencerid != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('influencer_dashboard'))

    if request.method == 'POST':
        new_payment_amount = request.form.get('new_payment_amount')
        if new_payment_amount:
            ad_request.proposed_amount = float(new_payment_amount)
            ad_request.status = 'under_negotiation'
            db.session.commit()
            flash('Payment negotiation initiated!', 'success')
        return redirect(url_for('influencer_dashboard'))

    if action == 'accept':
        ad_request.status = 'accepted'
    elif action == 'reject':
        ad_request.status = 'rejected'
    db.session.commit()
    flash(f'Ad request {action}ed!', 'success')
    return redirect(url_for('influencer_dashboard'))

@app.route('/propose_payment/<int:ad_request_id>', methods=['POST'])
@login_required
def propose_payment(ad_request_id):
    if current_user.role != 'influencer':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))

    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.influencerid != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('influencer_dashboard'))

    proposed_amount = request.form['proposed_amount']
    ad_request.proposed_amount = proposed_amount
    ad_request.status = 'under_negotiation' 
    db.session.commit()

    flash('Payment proposal sent!', 'success')
    return redirect(url_for('influencer_dashboard'))

@app.route('/accept_payment_proposal/<int:ad_request_id>')
@login_required
def accept_payment_proposal(ad_request_id):
    if current_user.role != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))

    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.campaign.sponsorid != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    ad_request.payment_amount = ad_request.proposed_amount
    ad_request.status = 'accepted'
    db.session.commit()
    flash('Payment proposal accepted!', 'success')
    return redirect(url_for('sponsor_dashboard'))

@app.route('/reject_payment_proposal/<int:ad_request_id>')
@login_required
def reject_payment_proposal(ad_request_id):
    if current_user.role != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))

    ad_request = AdRequest.query.get_or_404(ad_request_id)
    if ad_request.campaign.sponsorid != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    ad_request.status = 'rejected'
    db.session.commit()
    flash('Payment proposal rejected!', 'success')
    return redirect(url_for('sponsor_dashboard'))

@app.route('/viewinfluencers', methods=['GET', 'POST'])
def viewinfluencers():
    if request.method == 'POST':
        search = request.form.get('search', '')
        min_followers = request.form.get('min_followers', 0, type=int)
        max_followers = request.form.get('max_followers', None, type=int)
        influencers = User.query.filter(User.role == 'influencer',db.or_(User.username.contains(search),User.niche.contains(search)),User.followers >= min_followers,(User.followers <= max_followers if max_followers is not None else True)).all()
    else:
        influencers = User.query.filter_by(role='influencer').all()
    return render_template('viewinfluencers.html', influencers=influencers)


@app.route('/stats')
@login_required
def stats():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    sponsors = User.query.filter_by(role='sponsor').count()
    print(sponsors)
    influencers = User.query.filter_by(role='influencer').count()
    print(influencers)
    accepted = AdRequest.query.filter_by(status='accepted').count()
    rejected = AdRequest.query.filter_by(status='rejected').count()
    return render_template('stats.html', sponsors=sponsors, influencers=influencers, accepted=accepted, rejected=rejected)


@app.route('/flag_user/<int:user_id>')
@login_required
def flag_user(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    user.flagged = True
    db.session.commit()
    flash(f'{user.username} has been flagged.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/unflag_user/<int:user_id>')
@login_required
def unflag_user(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    if current_user.flagged == True:
        flash('You have been flagged.Contact administration for more details', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    user.flagged = False
    db.session.commit()
    flash(f'{user.username} has been unflagged.', 'success')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)