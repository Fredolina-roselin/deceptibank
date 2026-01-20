from honeypot_logger import HoneypotLoggingSystem
import time
import signal
import sys

def main():
    honeypot = None

    def handle_sigint(signum, frame):
        nonlocal honeypot
        print("\nReceived interrupt, stopping honeypot...")
        if honeypot:
            honeypot.stop_monitoring()
        sys.exit(0)

    # Install signal handler for Ctrl+C
    signal.signal(signal.SIGINT, handle_sigint)

    try:
        # === Configure your MySQL connection here ===
        honeypot = HoneypotLoggingSystem(
            host='localhost',
            user='newuser1',
            password='StrongPassword123!',
            database='deceptibank'
        )

        honeypot.start_monitoring()
        print("Honeypot is running... Press Ctrl+C to stop.")

        # Keep the script alive; sleep prevents busy-waiting
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        # fallback if signal not caught
        if honeypot:
            honeypot.stop_monitoring()
        print("Honeypot stopped safely.")

    except Exception as e:
        print(f"Error starting honeypot: {e}")
        if honeypot:
            honeypot.stop_monitoring()

if __name__ == "__main__":
    main()
