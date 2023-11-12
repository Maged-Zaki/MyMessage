from flask import Flask, render_template, redirect, flash, request, session, url_for
from flask_session import Session
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit
from itsdangerous import URLSafeSerializer
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash


from datetime import datetime
import re 
from PIL import Image
import os
import shutil


#google login imports
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from google.auth.transport.requests import Request

# local
from helpers import login_required, get_date_time, format_timestamp, validate_timestamp, generate_kay_pair, encrypt_message, decrypt_message
from config import GOOGLE_CLIENT_ID, CLIENT_SECRET_FILE_PATH, SECRET_KEY, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER


flow = Flow.from_client_secrets_file(
    client_secrets_file=CLIENT_SECRET_FILE_PATH,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/login/callback"
)


#so we dont get error about HTTP and not HTTPS
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


#Configure application
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

#Configure socketio with app
socketio = SocketIO(app, ping_interval=30, ping_timeout=120)

    
# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465 
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER


mail = Mail(app)
s = URLSafeSerializer(SECRET_KEY)


#Configuration so whenever we update html code while flask running the page gets updated
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False      
# app.config["PERMANENT_SESSION_LIFETIME"] = 30   #after 30secs of inactivity user is logged out and session_permanent should be set to true

app.config["SESSION_TYPE"] = "filesystem"  

#Configure Uploads Directory
Session(app)


#Open database
db = SQL("sqlite:///mymessage.db")


connected_users = {}

@socketio.on("connect")
def handle_connect():

    user_id = session["user_id"]

    if session["user_id"]:
        connected_users[user_id] = request.sid

    print("client connected!")
    db.execute("UPDATE users SET online = True WHERE user_id = ?", user_id)


@socketio.on("disconnect")
def handle_disconnect():
    user_id = session["user_id"]

    #after disconnection delete from connected users dict
    if user_id in connected_users:
        del connected_users[user_id]

    print('Client disconnected')
    db.execute("UPDATE users SET online = False WHERE user_id = ?", user_id)


@socketio.on("new_message")
def handle_new_message(data):
    message = data["message"]
    sender_id = session["user_id"]
    recipient_id = data["recipient_id"]
    conversation_id = data["conversation_id"]

    current_time = get_date_time()
    formatted_timestamp = format_timestamp(current_time)
    
    #get sender socket id
    int_sender_id = int(sender_id)
    sender_socket_id = connected_users.get(int_sender_id)

    #get recipient socket id
    int_recipient_id = int(recipient_id)
    recipient_socket_id = connected_users.get(int_recipient_id)

    if sender_socket_id:
        emit('send_message', {'message': message, 'sender_id': sender_id, 'conversation_id': conversation_id, "timestamp": formatted_timestamp}, room=sender_socket_id)

    if recipient_socket_id:
        emit('receive_message', {'message': message, 'sender_id': session['user_id'], 'conversation_id': conversation_id, "timestamp": formatted_timestamp}, room=recipient_socket_id)




@app.route('/')
def home():
     return render_template("home.html")

@app.route('/features/end-to-end-encryption')
def feature_end_to_end():
     return render_template("feature-end-to-end.html")

@app.route('/features/money-transfer')
def feature_money_transfer():
     return render_template("feature-money-transfer.html")

@app.route('/about')
def about():
     return render_template("about.html")

@app.route('/help')
def help():
     return render_template("help.html")

@app.route('/terms')
def terms():
     return render_template("terms.html")



@app.route("/login/google")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    
    return redirect(authorization_url)


@app.route("/login/callback")
def google_callback():
    flow.fetch_token(authorization_response=request.url)

    if  session["state"] != request.args["state"]:
        return ("state doesnt match!")

    credentials = flow.credentials
    request_session = requests.session()
    
    cached_session = cachecontrol.CacheControl(request_session)

    token_request = Request(session=cached_session)

    #Ensure the token is valid
    try:
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )
    except ValueError:
        flash("Invalid token")
        return render_template("login.html")
    
    google_id = id_info.get("sub")
    first_name = id_info.get("given_name")
    last_name = id_info.get("family_name")
    email = id_info.get("email")
    picture_url = id_info.get("picture")
    print("picture url >>>>>>", picture_url)
    #check if user is already registed
    rows = db.execute("SELECT * FROM users WHERE email = ?", email)
    db_user = rows[0] if rows else None

    if db_user:
        if db_user["activated"] == False:
            flash("Email already exists!")
            return render_template("login.html")
        # if registed already login the user
        else:
            session["user_id"] = db_user["user_id"]
            session["first_name"] = db_user["first_name"]
            session["last_name"] = db_user["last_name"]
            session["email"] = db_user["email"]
            session["wallet"] = db_user["wallet"]
            return redirect("/")
        

    #Generate private key and public key for user
    public_key, private_key = generate_kay_pair()

    #if not registered insert into db
    db.execute("INSERT INTO users(first_name, last_name, username, email, public_key, private_key, activated) VALUES(?, ?, ?, ?, ?, ?, ?)", first_name, last_name, google_id, email, public_key, private_key, True)

    

    #get recetnly added data and login session
    rows = db.execute("SELECT * FROM users WHERE email = ?", email)
    db_user = rows[0]

    session["user_id"] = db_user["user_id"]
    session["first_name"] = db_user["first_name"]
    session["last_name"] = db_user["last_name"]
    session["email"] = db_user["email"]
    session["wallet"] = db_user["wallet"]

    #save google image with his ID to display it later
    filename = f"{db_user['user_id']}.png"

    user_picture_path = os.path.join('static\\images\\uploaded_images', filename)   

    with open(user_picture_path, 'wb') as file:
        response = requests.get(picture_url)
        file.write(response.content)

    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Put the users' input in variables
        username = request.form.get("username")
        password = request.form.get("password")


        # Ensure username was submitted
        if not username:
            flash("must provide username")
            return render_template("login.html")

        # Ensure password was submitted
        if not password:    
            flash("must provide password")
            return render_template("login.html")


        # Query database for username
        rows= db.execute("SELECT * FROM users WHERE username = ?", username)

        #Ensure username exists and db returned anything 
        if len(rows) == 0 :
            flash("invalid username and/or password", 403)
            return render_template("login.html")

        db_user = rows[0]

        # Ensure password is correct
        if not check_password_hash(db_user["password"], password):
            flash("invalid username or password")
            return render_template("login.html")


        # Remember which user has logged in_
        session["user_id"] = db_user["user_id"]
        session["first_name"] = db_user["first_name"]
        session["last_name"] = db_user["last_name"]
        session["email"] = db_user["email"]
        session["wallet"] = db_user["wallet"]

        #Ensure user activated email
        if db.execute("SELECT * FROM users WHERE username= ? AND activated = False", username):
            flash("Account isn't activated yet!")
            return render_template("login.html")



        # direct user to home page
        return render_template("/home.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    return redirect("/")


@app.route('/forget_password', methods=["GET", "POST"])
def forget_password():
     if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")

        if not username:
            flash("must provide username")
            return render_template("forget-password.html")


        if not email:
            flash("must provide email")
            return render_template("forget-password.html")


        db_user = db.execute("SELECT * FROM users WHERE username = ? AND email = ?", username, email)

        if not db_user:
            flash("Couldn't find account")
            return render_template("forget-password.html")
        
        #generate a token for user email activation
        token = s.dumps(email)

        # Send email to the user
        msg = Message("MyMessage Reset Password", recipients=[email])
        link = url_for('reset_password_validator', token=token, _external=True)
        msg.body = f'Hello User, Rest Password link: {link}'  
        mail.send(msg)

        #change in the DB token to be true
        db.execute("UPDATE users SET password_reset_token= True WHERE username = ?", username)

        flash("password has been reset. Check email for reset link")
        return render_template("forget-password.html")

     return render_template("forget-password.html")

@app.route("/reset_password_validator/<token>")
def reset_password_validator(token):

    try:
        email = s.loads(token, max_age=3600)
    except:
        return ('Invalid or expired Reset password token.')
    

    
    return render_template("reset-password.html", email=email, token=token)


@app.route("/reset_password", methods=["POST"])
def rest_password():
    #save input into varaibles           
    new_password = request.form.get("new_password")
    new_password_again = request.form.get("new_password_again")
    email = request.form.get("email")
    token = request.form.get("token")

    #Ensure the user token not used before
    db_user= db.execute("SELECT password_reset_token FROM users WHERE email = ?", email)
    
    password_reset_token = db_user[0]["password_reset_token"]
    
    if password_reset_token == False:
        flash("Invalid or link used already")
        return redirect(f"/reset_password_validator/{token}")

    if not new_password:
        flash("must provide new password")
        return redirect(f"/reset_password_validator/{token}")

    if not new_password_again:
        flash("must provide new password again")
        return redirect(f"/reset_password_validator/{token}")
    
    # Ensure Password meets the requirments 

    if len(new_password) < 4:
        flash("password should be more than 4 characters")
        return redirect(f"/reset_password_validator/{token}")
    
    if len(new_password) > 20:
        flash("password shouldn't be more than 20 characters")
        return redirect(f"/reset_password_validator/{token}")
    
    if new_password != new_password_again:
        flash("New passwords don't match")
        return redirect(f"/reset_password_validator/{token}")
    
    hashed_password = generate_password_hash(new_password)

    db.execute("UPDATE users SET password = ? WHERE email = ?", hashed_password, email)

    #send a message to the user that password  reset
    msg = Message("MyMessage Confirmation", recipients=[email])
    msg.body = f'Hello , Your password has been reset '  
    mail.send(msg)

    #update token to be false so user doesnt change password again from same token
    db.execute("UPDATE users SET password_reset_token= False WHERE email = ?", email)

    flash("Password changed successfully!")
    return redirect(f"/reset_password_validator/{token}")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        #users' input in variables
        username = request.form.get("username")
        password = request.form.get("password")
        first_name = request.form.get("first_name").title()
        last_name = request.form.get("last_name").title()
        email = request.form.get("email")

        

        #Ensure name was submitted
        if not first_name or not last_name:
            flash("First and last names are required")
            return render_template("register.html")

        # Ensure password was submitted
        if not username:
           flash("No username")
           return render_template("register.html")
        
        # Ensure password was submitted
        if not password:
            flash("No password")
            return render_template("register.html")


        # Ensure username meets the requirments 
        if not re.search(r"^[a-zA-Z0-9_-]{3,20}$", username):
            flash("Username should be letter and number only")
            return render_template("register.html")


        if db.execute("SELECT * FROM users WHERE username = ?", username):
                flash("Username already exists!")
                return render_template("register.html")

        
        #Ensure email meets the requirments 
        if not email:
            flash("No email provided!")
            return render_template("register.html")
        
        #^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ another one
        if not re.search(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", email):
            flash("Email invalid!")
            return render_template("register.html")


        if db.execute("SELECT * FROM users WHERE email = ?", email):
            db_user = db.execute("SELECT * FROM users WHERE email = ? ", email)

            account_status = db_user[0]["activated"]
            registeration_timestamp = db_user[0]["registration_timestamp"]

            #check if user is activated or no
            if account_status == False:
                if validate_timestamp(registeration_timestamp):       #function returns true if less than an hour passed and it returns false an hour or + passed
                    flash("Email registered But it needs verifiying, please check your email")
                    return render_template("register.html")
                else:
                    #delete the current user 
                    db.execute("DELETE FROM users WHERE username= ? ", username)
            else:
                flash("Email already exists!")
                return render_template("register.html")


        # Ensure Password meets the requirments 
        if len(password) < 4:
            flash("password should be more than 4 characters")
            return render_template("register.html")
        
        if len(password) > 20:
          flash("password shouldn't be more than 20 characters")
          return render_template("register.html")

        #hash the password  
        hashed_password = generate_password_hash(password)

        #Generate private key and public key for user
        public_key, private_key = generate_kay_pair()
        
        #generate a token for user email activation
        token = s.dumps(email)
        
        # Send email to the user
        msg = Message("MyMessage Confirm Email", sender='ricardo103333@gmail.com', recipients=[email])
        link = url_for('verifiy', token=token, _external=True)
        msg.body = f'Hello {first_name}, Verification link: {link}'  
        mail.send(msg)
 
        #add user to Datebase
        current_time = get_date_time()
        db.execute("INSERT INTO users(first_name, last_name, username, email, password, public_key, private_key, registration_timestamp) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", first_name, last_name, username, email, hashed_password,public_key, private_key, current_time)

        flash('Registration successful! Check your email for verification.')
        return render_template("register.html")

    else:
        return render_template("register.html")


@app.route("/verifiy/<token>")
def verifiy(token):
    try:
        email = s.loads(token, max_age=3600)
    except:
        flash('Invalid or expired verification token.')
        return render_template("register.html")


    # Mark the user as activated and set the pub and private keys in the database
    db.execute("UPDATE users SET activated = True WHERE email = ?", email)


    #set default picture for user
    db_user = db.execute("SELECT user_id FROM users WHERE email = ?", email)

    user_id = db_user[0]["user_id"]

    #save default picture in the uploaded images folder

    filename = f"{user_id}.png"
    user_picture_path = os.path.join('static\\images\\uploaded_images', filename)   

    default_picture_path = 'static\\images\\default_profile_picture.png'

    # Save the image to the specified path
    shutil.copy(default_picture_path, user_picture_path)

    flash('Email verified successfully! You can now log in.')
    return render_template("login.html")

    

@app.route('/chat')
@login_required
def chat():

    chat_data = []


    current_id = session["user_id"]

    #get all conversations where current logged in user is set to True
    all_conversations = db.execute("SELECT * FROM conversations WHERE (conversation_initiator = ? AND active_on_initiator = True) OR (recipient_id = ? AND active_on_recipient = True)", current_id, current_id)

    conversation_ids_timestamps = []
    #temp list to store in all the conversations

    for i, each in enumerate(all_conversations):
        conversation_ids_timestamps.append({
            "conversation_id": each["conversation_id"]
        })

        if each["conversation_initiator"] == current_id: 
            timestamp = each["initiator_timestamp"]
            recipient_id = each["recipient_id"]

            conversation_ids_timestamps[i]["timestamp"] = timestamp
            conversation_ids_timestamps[i]["recipient_id"] = recipient_id

        
        else:
            timestamp = each["recipient_timestamp"]
            recipient_id = each["conversation_initiator"]
 
            conversation_ids_timestamps[i]["timestamp"] = timestamp
            conversation_ids_timestamps[i]["recipient_id"] = recipient_id


    #sort the list in a new list in Descending  order by timestamp so the newest table is listed first in the chat
    conversation_ids_timestamps_sorted = sorted(conversation_ids_timestamps, key=lambda each: each['timestamp'], reverse=True) 

    conversation_ids_timestamps_names = []

    for each in conversation_ids_timestamps_sorted:
        rows = db.execute("SELECT first_name, last_name, online FROM users WHERE user_id= ?", each["recipient_id"])
        db_user = rows[0] if rows else None

        status = db_user["online"]
        recipient_name = f"{db_user['first_name']} {db_user['last_name']}"

        conversation_ids_timestamps_names.append({
            "conversation_id": each["conversation_id"],
            "recipient_id": each["recipient_id"],
            "recipient_name": recipient_name,
            "status": status,
            "timestamp": each["timestamp"]
            })
        

    #get all the messages for the sorted conversations and add them to chat data
    for each in conversation_ids_timestamps_names:
        conversation_id = each["conversation_id"]
        recipient_id = each["recipient_id"]
        recipient_name = each["recipient_name"]
        status = each["status"]

        messages_in_conversation = db.execute("SELECT * FROM messages WHERE conversation_id= ? ORDER BY timestamp DESC", conversation_id)
        
        #loop over all the timestamps for messages to format the timestamp
        for i in range(len(messages_in_conversation)):
            messages_in_conversation[i]['timestamp'] = format_timestamp(messages_in_conversation[i]['timestamp'])
            
            #decrypt messages
            db_user = db.execute("SELECT private_key FROM users WHERE user_id = ?", messages_in_conversation[i]["recipient_id"])
            private_key = db_user[0]["private_key"]

            decrypted_message = decrypt_message(messages_in_conversation[i]['message_content'], private_key)

            messages_in_conversation[i]['message_content'] = decrypted_message.decode()

        chat_data.append({
            "conversation_id": conversation_id,
            "recipient_id": recipient_id,
            "recipient_name": recipient_name,
            "status": status,
            "messages": messages_in_conversation
        })



    #get all conversations that has messages and get timestamps for the last message sent in the conversation


    # return chat page with the chat data to load it 
    return render_template("chat.html", chat_data=chat_data)


@app.route('/me')
@login_required
def me():   
     rows = db.execute("SELECT * FROM users WHERE user_id= ?", session["user_id"])
     db_user = rows[0]

     return render_template("profile.html", db_user=db_user)

@app.route('/users/<int:id>')
@login_required
def other_profiles(id):
    #if search for same user return profile
    if id == session["user_id"]:
        return redirect("/me")
    
    rows = db.execute("SELECT * FROM users WHERE user_id= ?", id)

    if len(rows) == 0:
        return ("User not found 404")
    
    db_user = rows[0]
    return render_template("others.html", db_user=db_user)




@app.route('/me/settings', methods=["GET", "POST"])
@login_required
def settings():
     if request.method == "POST":
         first_name = request.form.get("first_name").title()
         last_name = request.form.get("last_name").title()

         if not first_name or not last_name:
             flash('First Name and Last Name are required!')
             return redirect("/me/settings")
         
         #Ensure name meets the requirments 
         if len(first_name) > 30 or len(last_name) > 30:
             flash("30 characters per name at most!")
             return redirect("/me/settings")

         #add name to db
         db.execute("UPDATE users SET first_name= ?, last_name= ? WHERE user_id= ?", first_name, last_name, session["user_id"])

         #Update session with the new name
         session["first_name"] = first_name
         session["last_name"] = last_name

         flash("Name changed successfully!")
         return redirect("/me/settings")
     
     else:
        return render_template("settings.html")

        
     

@app.route('/me/settings/upload-image', methods=["POST"])
@login_required
def upload_image():
    uploaded_image = request.files["uploaded_image"]

    if not uploaded_image:
        flash("Couldn't find image")  
        return redirect("/me/settings")
    
    
    # Use the user's ID as the filename
    filename = f"{session['user_id']}.png"

    # Construct the complete image path
    image_path = os.path.join('static\\images\\uploaded_images', filename)

    try:
        with Image.open(uploaded_image) as img:
            img_resized = img.resize((150, 150))
    except:
        flash("File is not an image!")
        return redirect("/me/settings")
    # Save the image to the specified path
    img_resized.save(image_path)

    flash("Profile picture changed successfully!")
    return redirect("/me/settings")



@app.route('/me/settings/security', methods=["GET", "POST"])
@login_required
def security():
     if request.method == "POST":
        #Ensure user isn't a 3rd party user
        db_user = db.execute("SELECT registration_timestamp FROM users WHERE user_id = ?", session["user_id"])
        if not db_user[0]["registration_timestamp"]:
            flash("No password avilable as you are a 3rd party user")
            return redirect("/me/settings/security")

        #save user input in variables
        old_pass = request.form.get("old_password")
        new_pass = request.form.get("new_password")
        new_pass_again = request.form.get("new_password_again")


        #get user's current hash
        current_hash = db.execute("SELECT password FROM users WHERE user_id= ?", session["user_id"])
        current_hash = current_hash[0]["password"]

        #check db hash with user password input
        if not check_password_hash(current_hash, old_pass):
            flash("Invalid old password")
            return redirect("/me/settings/security")


        #Ensure  new pass requirements 
        if new_pass != new_pass_again:
            flash("New passwords don't match")
            return redirect("/me/settings/security")

        if len(new_pass) < 4:
            flash("Password should be more than 4 characters")
            return redirect("/me/settings/security")

        if len(new_pass) > 20:
            flash("Password shouldn't be more than 20 characters")
            return redirect("/me/settings/security")

        #hash the new pass and add to db
        new_hashed_password = generate_password_hash(new_pass)
        db.execute("UPDATE users SET password= ? WHERE user_id= ?", new_hashed_password, session["user_id"])

        flash("Password changed successfully!")
        return redirect("/me/settings/security")


     else:
         return render_template("security.html")


@app.route('/me/send-money', methods=["GET", "POST"])
@login_required
def send_money():
     if request.method == "POST":
        #variables for users input
        recipient_username = request.form.get("recipient_username")
        amount = request.form.get("amount") 
        
        #ensure recipient  username exits
        if not recipient_username:
             flash("Username missing!")
             return redirect("/me/send-money")
        
        #ensure amount   exits
        if not amount:
            flash("Amount missing!")
            return redirect("/me/send-money")
        #change string amount to float and ensure it's decimal
        try:
            amount = float(amount)
        except:
            flash("Amount should be number!")
            return redirect("/me/send-money")


        #ensure amount not less than 0.01
        if amount < 0.01:
             flash("Amount should be 0.01 or more!")
             return redirect("/me/send-money")
        #get sender data from db
        db_sender = db.execute("SELECT * FROM users WHERE user_id= ?",session["user_id"])
        sender_current_cash = db_sender[0]["wallet"]

        if sender_current_cash < amount:
            flash("Not enough money available!")
            return redirect("/me/send-money")

        db_recipient = db.execute("SELECT * FROM users WHERE username= ?", recipient_username)
        
        #ensure username exists
        if not db_recipient:
            flash("Username doesn't exist!")
            return redirect("/me/send-money")
        
        #Ensure user isnt sending money to themself
        if db_recipient[0]["user_id"] == session["user_id"]:
            flash("Can't send money to yourself!")
            return redirect("/me/send-money")
        
        recipient_id =  db_recipient[0]["user_id"]
        
        sender_cash_after = sender_current_cash - amount


        #substract the amount that needs to be sent from db
        db.execute("UPDATE users SET wallet= wallet - ?  WHERE user_id= ?", amount, session["user_id"])

        #update the recipient current cash and add the money sent
        db.execute("UPDATE users SET wallet= wallet + ?  WHERE user_id= ?", amount, recipient_id)

        #get current time
        current_time = datetime.now()

        # Format the current time as a string
        formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
        
        #insert transaction into db
        db.execute("INSERT INTO transactions(sender_id, recipient_id, amount, timestamp) VALUES(?, ?, ?, ?)", session["user_id"], recipient_id, amount, formatted_time)

        #update current user's session wallet
        session["wallet"] = sender_cash_after
        flash("Money sent successfully!")
        return redirect("/me/send-money")


     else:
         return render_template("send-money.html")
     


@app.route('/search')
@login_required
def search():

    user_input = request.args.get("q")
    db_users = db.execute("SELECT * FROM users WHERE username LIKE ?", f"%{user_input}%")

    return render_template("search.html", db_users=db_users, results=len(db_users))

@app.route('/me/transaction-history')
@login_required
def transaction_history():

    #Get all transactions that current user is involved in 
    user_transactions = db.execute("SELECT * FROM transactions WHERE sender_id= ? OR recipient_id= ? ORDER BY timestamp DESC",session["user_id"], session["user_id"])

    #initiate a list to store dicts in it
    data = []
    
    #iterate over all the transcations from DB
    for transaction in user_transactions:

        #initiate a temporary dictionary to store the  data in
        temp_dict = {}
        temp_dict["transaction_id"] = transaction["transaction_id"]
        temp_dict["date"] = transaction["timestamp"]
        temp_dict["amount"] = transaction["amount"]

        #check if the user is the sender and if not get name of the user from DB 
        if transaction["sender_id"] == session["user_id"]:
            temp_dict["sender"] = "You"
        else:
            sender_data = db.execute("SELECT * FROM users WHERE user_id= ?", transaction["sender_id"])
            sender_first_name = sender_data[0]['first_name']
            sender_last_name = sender_data[0]['last_name']

            temp_dict["sender"] = f"{sender_first_name} {sender_last_name}"

        #append dict 
        data.append(temp_dict)

    return render_template("transaction-history.html", data=data)

@app.route("/start-a-conversation", methods=["GET", "POST"])
@login_required
def conversation():
    recipient_id = request.form.get("recipient_id")
    sender_id = session["user_id"]
    current_date_time = get_date_time()

    # Check if there's an existing conversation initiated by the sender with the recipient
    existing_conversation_sender = db.execute("SELECT * FROM conversations WHERE conversation_initiator = ? AND recipient_id = ? ", sender_id, recipient_id)

    # Check if there's an existing conversation initiated by the recipient with the sender
    existing_conversation_recipient = db.execute("SELECT * FROM conversations WHERE conversation_initiator = ? AND recipient_id = ? ", recipient_id, sender_id)

    if existing_conversation_sender:
        # Conversation initiated by the sender with the recipient already exists
        conversation_id = existing_conversation_sender[0]["conversation_id"]

        # Update timestamp for the sender
        db.execute("UPDATE conversations SET initiator_timestamp = ?, active_on_initiator= ? WHERE conversation_id = ?", current_date_time, True,  conversation_id)
        return redirect("/chat")
    
    if existing_conversation_recipient:
        # Conversation initiated by the recipient with the sender already exists
        conversation_id = existing_conversation_recipient[0]["conversation_id"]
    
        # Update timestamp for the recipient
        db.execute("UPDATE conversations SET recipient_timestamp = ?, active_on_recipient = ? WHERE conversation_id = ?", current_date_time, True, conversation_id)
        return redirect("/chat")
    

    # No existing conversation, create a new one initiated by the sender
    db.execute("INSERT INTO conversations (conversation_initiator, recipient_id, initiator_timestamp, active_on_initiator) VALUES (?, ?, ?, ?)",sender_id, recipient_id, current_date_time, True)
    return redirect("/chat")



@app.route("/chat/send-message", methods=["POST"])
@login_required
def send_message():
    data = request.json
    message_content = data.get("message")
    sender_id = session["user_id"]
    recipient_id = data.get("recipient_id")
    conversation_id = data.get("conversation_id")

    #check if message is empty
    if not message_content:
        return


    #get recipient public key to encrypt message
    db_user = db.execute("SELECT public_key FROM users WHERE user_id= ? ", recipient_id)
    public_key = db_user[0]["public_key"]

    #pass the message to the function in bytes with the public kew to encrypt it
    encrypted_message = encrypt_message(message_content.encode(), public_key)

    

    current_date_time = get_date_time()

    db.execute("INSERT INTO messages(conversation_id, sender_id, recipient_id, message_content, timestamp) VALUES(?, ?, ?, ?, ?)", conversation_id, sender_id, recipient_id, encrypted_message, current_date_time)

    #set the actives to True as a text has been already sent
    db.execute("UPDATE conversations SET active_on_initiator= ?, active_on_recipient= ?, initiator_timestamp= ?, recipient_timestamp= ?  WHERE conversation_id= ?", True, True, current_date_time, current_date_time, conversation_id)
        

@app.route('/delete-conversation/<int:id>')
@login_required
def delete_conversation(id):
    recipient_id = id
    current_user = session["user_id"]

    #get conversation table from db
    rows = db.execute("SELECT * FROM conversations WHERE conversation_initiator IN (?,?) AND recipient_id IN (?,?) ", current_user, recipient_id, current_user, recipient_id)
    db_user = rows[0]

    #ensure the sender is the conversation initiator or recipient
    if current_user == db_user["conversation_initiator"]:
        db.execute("UPDATE conversations SET active_on_initiator = False WHERE conversation_id = ?", db_user["conversation_id"])

    if current_user == db_user["recipient_id"]:
        db.execute("UPDATE conversations SET active_on_recipient = False WHERE conversation_id = ?", db_user["conversation_id"])

    return redirect("/chat")


if __name__ == '__main__':
    socketio.run(app, debug=True)






