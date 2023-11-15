# MyMessage
MyMessage is a web-based WhatsApp-like application.
## Description:
MyMessage app is the final project for CS50. It enables users to send and receive messages in a real-time chat environment and was built using the Flask framewok, also it includes 3rd party logging in with google and all messages are encrypted using asymmetric encryption. The project took approximately 3 weeks to complete and was both exciting and occasionally challenging 😅.
## Screenshot
![](https://github.com/Maged-Zaki/MyMessage/blob/main/static/images/GitHubImage.PNG)

## Technologies and Libraries used
- **Sqlite:** Used as a database engine.
- **Docker:** Used for containerization.
- **cs50.SQL:** Used for database querying and management.
- **flask_session.Session:** Used for session handling within the application.
- **flask_socketio.SocketIO and emit:** Used to establish connections between the server and users, facilitating real-time communication.
- **itsdangerous.URLSafeSerializer:** Used for generating one-time tokens for tasks such as email verification and password reset.
- **werkzeug.security:** Used for hashing and verifying user passwords during the login process.
- **google.oauth2.id_token:** Used for Google authentication.
- **google_auth_oauthlib.flow.Flow:** Used for Google OAuth flow.
- **pip._vendor.cachecontrol:** Used as A dependency for managing caching.
- **google.auth.transport.requests.Request:** Used for handling requests in the Google authentication process.
- **cryptography.hazmat:** Used for encryption and decryption of sensitive data.
- **cryptography.hazmat.backends:** Used the default backend for cryptographic operations.
- **cryptography.hazmat.primitives.asymmetric.rsa:** Used for RSA encryption.
- **cryptography.hazmat.primitives.serialization:** Used for serializing cryptographic objects.
-**cryptography.hazmat.primitives.asymmetric.padding:** Used for padding during encryption and decryption.
- **cryptography.hazmat.primitives.hashes:** Used for handling cryptographic hashes.

# Getting started
```
git clone https://github.com/Maged-Zaki/MyMessage.git
```

```
cd MyMessage

```

```
python -m venv venv

```
**On Windows**
```
venv\Scripts\activate

```
```
pip install -r windows_requirements.txt

```
**On MacOS**
```
source venv/bin/activate

```
```
pip install -r macOs_requirements.txt
```

**At this moment before we run the server we need download the secret_client file from google console.**
1. After we create our google credentials, Download the secret_client file.
2. copy and paste the file into the root of the project.

**Now we need to create config.py file at the root of the project**
1. at the root of the project, create config.py
2. copy and paste the following then fill in the required configuration

```
# google client id from google_client_secret file
GOOGLE_CLIENT_ID = " 
CLIENT_SECRET_FILE_PATH = ""

# app secret
SECRET_KEY = "" 

# mail configuration
MAIL_USERNAME = ''
MAIL_PASSWORD = ''
MAIL_DEFAULT_SENDER = ''

```

**Now we can start the server with the following command**

```
flask run
```

**Now the server is running**
Head to http://localhost:5000

**That's it, we are done, we can now create an account and start messaging people!**



