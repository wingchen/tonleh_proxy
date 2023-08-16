-- Add migration script here
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    created_at INT NOT NULL,
    removed BOOL
);
