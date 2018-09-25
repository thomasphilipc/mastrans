#===================
# Imports
#===================
import babel
from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import *
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import os, random, string, datetime, json, httplib2, requests
# Import login_required from login_decorator.py
from login_decorator import login_required
from datetime import datetime
from babel.dates import format_timedelta
import json

#===================
# Flask instance
#===================
app = Flask(__name__)

#===================
# GConnect CLIENT_ID being read from the json file generated from google dev
#===================
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item-Catalog"

#===================
# DB
#===================
# Connect to database - removing thread check to fix an issue with threads
engine = create_engine('sqlite:///catalog.db?check_same_thread=False')
Base.metadata.bind = engine
# Create session
DBSession = sessionmaker(bind=engine)
session = DBSession()
session.rollback()

#===================
# Login Routing
#===================
# Login - Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

# GConnect method for OAuth
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Check  anti-forgery state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    try:
        user = session.query(User).filter_by(id=user_id).one()
        return user
    except:
        return None

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        # response = make_response(json.dumps('Successfully disconnected.'), 200)
        # response.headers['Content-Type'] = 'application/json'
        response = redirect(url_for('showmastrans'))
        flash("You are now logged out.")
        return response
    else:
        # For whatever reason, the given token was invalid.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash("Please Login Again, it appears your session timed out.")
        return render_template('catalog.html')

#===================
# Flask Routing
#===================
# Homepage
@app.route('/')
@app.route('/mastrans/',methods=['GET', 'POST'])
def showmastrans():
    warehouse="off"
    offer="none"
    text="0"
    cost=0
    if request.method == 'POST':
        if request.form['weight']:
            text = request.form['weight']
        if request.form['optradio_1']:
            port=request.form['optradio_1']
        if request.form['dd_1']:
            mode=request.form['dd_1']
        if request.form['dd_2']:
            dest=request.form['dd_2']
        if request.form['dd_3']:
            fcl20item=request.form['dd_3']
        if request.form['dd_4']:
            fcl40item=request.form['dd_4']
        if request.form['offer']:
            offer=request.form['offer']
        if request.form.get('warehouse'):
            warehouse=request.form.get('warehouse')

        weight=int(text)
        mode = int(mode)
        port = int(port)
        dest = int (dest)
        fcl20item= int(fcl20item)
        fcl40item = int (fcl40item)
        print("weight {} / type {} / port {} / dest {}/ offer {} / warehouse {} ".format(weight,mode,port,dest,offer,warehouse))
        if mode == 1:
            if weight<=750:
                cost=750*36
            elif weight<1000:
                cost=weight*36
            elif weight <2000:
                cost=weight*30
            elif weight<3000:
                cost=weight*24
            elif weight<5000:
                cost=weight*22
            else:
                cost=weight*20
        elif mode==2:
            if weight<1000:
                cost=350000
            elif weight <2000:
                cost=weight*30
                if cost<350000:
                    cost=35000
            elif weight<3000:
                cost=weight*27
            elif weight<5000:
                cost=weight*23
            else:
                cost=weight*21
        elif mode==3:
            if port==1 and dest==1:
                if fcl20item==2:
                    cost=95000
                elif fcl20item==3:
                    cost=145000
                else:
                    cost=120000
            elif port ==1 and dest==2:
                cost=150000
            elif port == 2 and dest==2:
                cost=140000
        else:
            if port==1 and dest==1:
                cost=140000
            elif port==2 and dest==2:
                cost=170000
            else:
                cost=100000

        #build json to pass to webpage
        data = {}
        data['cost'] = (cost)/100
        data['comment'] = "edited from platform"
        data['port'] = request.form['optradio_1']
        data['dd_1']=request.form['dd_1']
        data['dd_2']=request.form['dd_2']
        data['offer']=request.form['offer']
        json_data = json.dumps(data)
        result = json.loads(json_data)
        print("Need to do stuff once i read the data")
        print(text)
        return render_template('mastrans/mastransresult.html',
                            result = result , text=text)
    else:
        return render_template('mastrans/mastrans.html',logged_session= login_session)



def format_datetime(value):
    print(value)
    tdelta = value - datetime.now()
    difference =babel.dates.format_timedelta(tdelta, add_direction=True, locale='en_US')
    return difference

app.jinja_env.filters['datetime'] = format_datetime


# url_for static path processor
# remove when deployed
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)





# Always at end of file !Important!
if __name__ == '__main__':
    app.secret_key = 'DEV_SECRET_KEY'

    app.run(debug = True,host = '0.0.0.0', port = 5002)
