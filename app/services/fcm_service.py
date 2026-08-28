"""
ThreatForge FCM Service
========================
Sends Firebase Cloud Messaging push notifications for new alerts.
Fire-and-forget: never blocks or fails alert creation if FCM is
unavailable or the send fails.
"""

import os
import logging
import time

logger = logging.getLogger("fcm_service")

_firebase_app = None
_init_attempted = False


def _init_firebase():
    global _firebase_app, _init_attempted
    if _firebase_app is not None or _init_attempted:
        return _firebase_app

    _init_attempted = True
    try:
        import firebase_admin
        from firebase_admin import credentials

        cred_path = os.getenv("FIREBASE_CREDENTIALS_PATH", "./firebase-admin.json")
        if not os.path.exists(cred_path):
            logger.warning(f"FCM: credentials file not found at {cred_path} — FCM disabled")
            print(f"FCM: credentials file not found at {cred_path} — FCM disabled")
            return None

        cred = credentials.Certificate(cred_path)
        _firebase_app = firebase_admin.initialize_app(cred)
        logger.info("FCM: Firebase Admin initialized successfully")
        print("FCM: Firebase Admin initialized successfully")
        return _firebase_app
    except Exception as exc:
        logger.warning(f"FCM: Firebase initialization failed: {exc}")
        print(f"FCM: Firebase initialization failed: {exc}")
        return None


def send_alert(fcm_token: str, title: str, body: str, data: dict) -> bool:
    if not fcm_token:
        return False

    app = _init_firebase()
    if app is None:
        return False

    from firebase_admin import messaging

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        data={k: str(v) for k, v in data.items()},
        token=fcm_token,
        android=messaging.AndroidConfig(priority="high"),
    )

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            response = messaging.send(message)
            logger.info(f"FCM: sent successfully, message_id={response}")
            print(f"FCM: sent successfully, message_id={response}")
            return True
        except Exception as exc:
            logger.warning(f"FCM: send attempt {attempt}/{max_attempts} failed: {exc}")
            print(f"FCM: send attempt {attempt}/{max_attempts} failed: {exc}")
            if attempt < max_attempts:
                time.sleep(1.5)
            else:
                logger.warning(f"FCM: all {max_attempts} attempts failed, giving up")
                print(f"FCM: all {max_attempts} attempts failed, giving up")
                return False
