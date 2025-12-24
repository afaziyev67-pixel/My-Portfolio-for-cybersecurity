import oracledb

class Database:
    def __init__(self):
        self.conn = oracledb.connect(
            user="AMIL",
            password="1234",
            dsn="localhost:1521/freepdb1"
        )
        self.cursor = self.conn.cursor()

    def add_user(self, email, password_hash, mfa_secret):
        try:
            sql = "INSERT INTO users (email, password_hash, mfa_secret) VALUES (:1, :2, :3)"
            self.cursor.execute(sql, (email, password_hash, mfa_secret))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

    def get_user(self, email):
        sql = "SELECT email, password_hash, mfa_secret FROM users WHERE email = :1"
        self.cursor.execute(sql, (email,))
        return self.cursor.fetchone()
