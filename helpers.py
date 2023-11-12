from flask import redirect, session
from functools import wraps
from datetime import datetime, timedelta

#encryption 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64


def login_required(f):
    """
    Decorate routes to require login.
    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def get_date_time():
    #get current time
    current_time = datetime.now()

    # Format the current time as a string
    formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    
    return formatted_time




def format_timestamp(timestamp_str):
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    current_time = datetime.now()
    today = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday = today - timedelta(days=1)
    two_days_ago = today - timedelta(days=2)



    if timestamp >= today:
        # It's today, display the time in hours and minutes with AM/PM
        formatted_time = timestamp.strftime("%I:%M %p")
        return formatted_time
    elif timestamp >= yesterday:
        # It's yesterday, display only the time (e.g., 9:30 PM)
        formatted_time = timestamp.strftime("%I:%M %p")
        return f"Yesterday {formatted_time}"
    elif timestamp >= two_days_ago:
        formatted_time = timestamp.strftime("%I:%M %p")
        return f"2 days ago {formatted_time}"
    else:
        # Display the full date and time (e.g., Jul 21, 2023 9:30 PM)
        return timestamp.strftime("%b %d, %Y %I:%M %p")





def validate_timestamp(db_timestamp_str):
    """"functions checks if there's an hour difference   """


    # Parse the timestamp string into a datetime object using the same format
    db_timestamp = datetime.strptime(db_timestamp_str, '%Y-%m-%d %H:%M:%S')
    

    # Get the current time as a datetime object
    current_time = datetime.now()

    # Calculate the time difference between the database timestamp and the current time
    time_difference = current_time - db_timestamp

    # Get the difference in hours
    hours_difference = time_difference.total_seconds() / 3600

    # Check if the time difference is within one hour
    if abs(hours_difference) < 1:
        return True
    else:
        return False
    

def generate_kay_pair():
    # generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # get public key from private_key using public_key method
    public_key = private_key.public_key()

    # convert the generated private and public keys into PEM-encoded strings
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_pem, private_key_pem



def encrypt_message(message, recipient_public_key_pem):
    # Load the recipient's public key from PEM format
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem, backend=default_backend())

    encrypted_message = recipient_public_key.encrypt(
        message, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode the encrypted message in base64 for storage in the database
    return base64.b64encode(encrypted_message)



def decrypt_message(encrypted_message, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    decrypted_message = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message
