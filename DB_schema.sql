CREATE TABLE users (
    user_id  INTEGER NOT NULL PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT,
    wallet NUMERIC DEFAULT 10000,
    public_key TEXT,
    private_key TEXT,
    online BOOLEAN DEFAULT 0,
    password_reset_token BOOLEAN DEFAULT 0,
    activated BOOLEAN DEFAULT 0,
    registration_timestamp TIMESTAMP
);
CREATE TABLE conversations (
    conversation_id INTEGER NOT NULL PRIMARY KEY ,
    conversation_initiator INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    initiator_timestamp TEXT NOT NULL ,
    recipient_timestamp TEXT,
    active_on_initiator BOOLEAN DEFAULT 0,
    active_on_recipient BOOLEAN DEFAULT 0,
    FOREIGN KEY (conversation_initiator) REFERENCES users(user_id),
    FOREIGN KEY (recipient_id) REFERENCES users(user_id)
);
CREATE TABLE messages (
    message_id INTEGER NOT NULL PRIMARY KEY,
    conversation_id INTEGER,
    sender_id INTEGER,
    recipient_id INTEGER,
    message_content TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id),
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (recipient_id) REFERENCES users(user_id)
);
CREATE TABLE transactions (
    transaction_id INTEGER NOT NULL PRIMARY KEY,
    sender_id INTEGER,
    recipient_id INTEGER,
    amount NUMERIC NOT NULL,
    timestamp TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id)
    FOREIGN KEY (recipient_id) REFERENCES users(user_id)

);
