# email_utils.py
import smtplib
from email.mime.text import MIMEText
from config import GMAIL_EMAIL, GMAIL_PASSWORD

def send_otp_email(to_email, otp_code):
    subject = "Your DeceptiBank OTP Verification Code"
    body = f"Your OTP code is: {otp_code}\nValid for 5 minutes."
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = GMAIL_EMAIL
    msg['To'] = to_email
    
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
        server.sendmail(GMAIL_EMAIL, [to_email], msg.as_string())
        server.quit()
        print(f"OTP sent to {to_email}")
        return True
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return False
