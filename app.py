import base64
import json
from datetime import datetime
from typing import List, Optional, Type
from uuid import uuid4

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

from config import Config

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

try:
    from webauthn.helpers.structs import AuthenticatorTransport
except ImportError:  # pragma: no cover - 古いバージョンの互換性確保
    AuthenticatorTransport = None


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128), nullable=False)
    user_handle = db.Column(db.LargeBinary(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")


class Credential(db.Model):
    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    transports = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="credentials")


class ChallengeSession:
    """Utility helpers for storing and retrieving challenges in the session."""

    challenge_key = "webauthn_challenge"
    username_key = "pending_username"
    display_name_key = "pending_display_name"
    user_handle_key = "pending_user_handle"

    @staticmethod
    def store(challenge: str, username: str, display_name: str, user_handle: bytes) -> None:
        session[ChallengeSession.challenge_key] = challenge
        session[ChallengeSession.username_key] = username
        session[ChallengeSession.display_name_key] = display_name
        session[ChallengeSession.user_handle_key] = base64.urlsafe_b64encode(user_handle).decode("utf-8")

    @staticmethod
    def store_authentication(challenge: str) -> None:
        session[ChallengeSession.challenge_key] = challenge

    @staticmethod
    def pop_challenge() -> Optional[str]:
        return session.pop(ChallengeSession.challenge_key, None)

    @staticmethod
    def pending_username() -> Optional[str]:
        return session.get(ChallengeSession.username_key)

    @staticmethod
    def pending_display_name() -> Optional[str]:
        return session.get(ChallengeSession.display_name_key)

    @staticmethod
    def pending_user_handle() -> Optional[bytes]:
        encoded = session.get(ChallengeSession.user_handle_key)
        if not encoded:
            return None
        return base64.urlsafe_b64decode(encoded.encode("utf-8"))

    @staticmethod
    def clear_pending_user() -> None:
        session.pop(ChallengeSession.username_key, None)
        session.pop(ChallengeSession.display_name_key, None)
        session.pop(ChallengeSession.user_handle_key, None)


def create_app(config_class: Type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET"])
    def register_page():
        return render_template("register.html")

    @app.route("/login", methods=["GET"])
    def login_page():
        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard():
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        user = User.query.get(user_id)
        return render_template("dashboard.html", user=user)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/register/options", methods=["POST"])
    def register_options():
        data = request.get_json(force=True)
        username = data.get("username", "").strip()
        display_name = data.get("displayName", "").strip()
        if not username or not display_name:
            return jsonify({"error": "username と表示名は必須です"}), 400

        user = User.query.filter_by(username=username).first()
        if user:
            user_handle = user.user_handle
            exclude_credentials: List[PublicKeyCredentialDescriptor] = [
                PublicKeyCredentialDescriptor(
                    id=base64.urlsafe_b64decode(c.credential_id.encode("utf-8")),
                    type="public-key",
                )
                for c in user.credentials
            ]
        else:
            user_handle = uuid4().bytes
            exclude_credentials = []

        options = generate_registration_options(
            rp_id=app.config["WEBAUTHN_RP_ID"],
            rp_name=app.config["WEBAUTHN_RP_NAME"],
            user_id=user_handle,
            user_name=username,
            user_display_name=display_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED,
                resident_key=ResidentKeyRequirement.PREFERRED,
            ),
            attestation="none",
            exclude_credentials=exclude_credentials,
        )

        ChallengeSession.store(options.challenge, username, display_name, user_handle)
        return jsonify(json.loads(options.model_dump_json()))

    @app.route("/register/verify", methods=["POST"])
    def register_verify():
        challenge = ChallengeSession.pop_challenge()
        if not challenge:
            return jsonify({"error": "チャレンジの有効期限が切れています"}), 400
        try:
            credential = RegistrationCredential.parse_raw(request.data)
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=app.config["WEBAUTHN_RP_ID"],
                expected_origin=app.config["WEBAUTHN_ORIGIN"],
                require_user_verification=True,
            )
        except InvalidRegistrationResponse as exc:
            ChallengeSession.clear_pending_user()
            return jsonify({"error": f"登録の検証に失敗しました: {exc}"}), 400
        except Exception as exc:  # pragma: no cover - 予期しないエラー
            ChallengeSession.clear_pending_user()
            return jsonify({"error": f"登録時に予期しないエラーが発生しました: {exc}"}), 400

        username = ChallengeSession.pending_username()
        display_name = ChallengeSession.pending_display_name()
        user_handle = ChallengeSession.pending_user_handle()

        if not username or not display_name or not user_handle:
            return jsonify({"error": "ユーザー情報の取得に失敗しました"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(
                username=username,
                display_name=display_name,
                user_handle=user_handle,
            )
            db.session.add(user)
            db.session.flush()

        credential_id = base64.urlsafe_b64encode(verification.credential_id).decode("utf-8")
        public_key = base64.b64encode(verification.credential_public_key).decode("utf-8")
        transports = None
        if credential.response.transports:
            transports = ",".join(
                getattr(t, "value", t) for t in credential.response.transports
            )

        existing_credential = Credential.query.filter_by(credential_id=credential_id).first()
        if existing_credential:
            existing_credential.public_key = public_key
            existing_credential.sign_count = verification.sign_count
            existing_credential.transports = transports
        else:
            db.session.add(
                Credential(
                    credential_id=credential_id,
                    public_key=public_key,
                    sign_count=verification.sign_count,
                    transports=transports,
                    user=user,
                )
            )
        db.session.commit()

        ChallengeSession.clear_pending_user()
        session["user_id"] = user.id

        return jsonify({"verified": True})

    @app.route("/login/options", methods=["POST"])
    def login_options():
        data = request.get_json(force=True)
        username = data.get("username", "").strip()
        if not username:
            return jsonify({"error": "username は必須です"}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not user.credentials:
            return jsonify({"error": "該当するユーザーが見つかりません"}), 404

        allow_credentials = []
        for cred in user.credentials:
            transports = None
            if cred.transports and AuthenticatorTransport:
                transports = [AuthenticatorTransport(t) for t in cred.transports.split(",")]
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64.urlsafe_b64decode(cred.credential_id.encode("utf-8")),
                    type="public-key",
                    transports=transports,
                )
            )

        options = generate_authentication_options(
            rp_id=app.config["WEBAUTHN_RP_ID"],
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        ChallengeSession.store_authentication(options.challenge)
        session["login_username"] = username

        return jsonify(json.loads(options.model_dump_json()))

    @app.route("/login/verify", methods=["POST"])
    def login_verify():
        challenge = ChallengeSession.pop_challenge()
        username = session.pop("login_username", None)
        if not challenge or not username:
            return jsonify({"error": "チャレンジの有効期限が切れています"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "ユーザーが存在しません"}), 400

        try:
            credential = AuthenticationCredential.parse_raw(request.data)
            raw_id = base64.urlsafe_b64encode(credential.raw_id).decode("utf-8")
            stored_credential = next(
                (cred for cred in user.credentials if cred.credential_id == raw_id),
                None,
            )
            if not stored_credential:
                return jsonify({"error": "証明書情報が見つかりません"}), 404

            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=app.config["WEBAUTHN_RP_ID"],
                expected_origin=app.config["WEBAUTHN_ORIGIN"],
                credential_public_key=base64.b64decode(stored_credential.public_key.encode("utf-8")),
                credential_current_sign_count=stored_credential.sign_count,
                require_user_verification=True,
            )
        except InvalidAuthenticationResponse as exc:
            return jsonify({"error": f"認証に失敗しました: {exc}"}), 400
        except Exception as exc:  # pragma: no cover - 予期しないエラー
            return jsonify({"error": f"認証で予期しないエラーが発生しました: {exc}"}), 400

        stored_credential.sign_count = verification.new_sign_count
        db.session.commit()

        session["user_id"] = user.id

        return jsonify({"verified": True})

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True)