import sqlite3
import os
import datetime

DB_PATH = "ids.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def log_event(src_ip, attack_type, action_taken, severity):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO events (timestamp, src_ip, attack_type, action_taken, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, attack_type, action_taken, severity))
    conn.commit()
    conn.close()

def get_events(limit=50, offset=0):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?', (limit, offset))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats_24h():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    time_24h_ago = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
    cursor.execute('SELECT attack_type, COUNT(*) FROM events WHERE timestamp > ? GROUP BY attack_type', (time_24h_ago,))
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}
