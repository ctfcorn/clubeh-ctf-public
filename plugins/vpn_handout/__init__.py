"""
CTFd plugin: per-user OpenVPN profile handout.

CTFd has no native per-user file delivery. Challenge files and Pages both serve
one identical artifact to everyone, which would let any player download all 51
profiles and would destroy the VPN-IP -> player mapping that the gateway's
nftables ACLs and the Wazuh audit trail depend on.

This plugin binds exactly one pre-generated profile to one CTFd account, for
the life of the event:

  * A logged-in user visiting /vpn atomically claims the lowest unassigned
    profile. Revisiting always returns the same one.
  * The claim is a single UPDATE ... WHERE user_id IS NULL ORDER BY id LIMIT 1,
    so concurrent registrations at CTF open cannot double-allocate. A UNIQUE
    constraint on user_id is the second line of defence.
  * Every claim and download is written to /var/log/CTFd/vpn_handout.log for
    Wazuh, giving you  account -> profile -> 10.8.0.x -> traffic  attribution.
  * Admins get /admin/vpn showing the full allocation table, which is what you
    use to identify whose certificate to revoke when you spot flag sharing.
"""

import datetime
import hmac
import os

from flask import Blueprint, abort, jsonify, render_template, request, send_file
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from CTFd.models import Users, db
from CTFd.plugins import register_user_page_menu_bar
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.user import get_current_user

PROFILE_DIR = os.environ.get("VPN_PROFILE_DIR", "/opt/ctf/vpn_profiles")
LOG_PATH = os.environ.get("VPN_LOG_PATH", "/var/log/CTFd/vpn_handout.log")
# Shared secret the gateway presents to read the isolation map. Unset = feature off.
ISOLATION_TOKEN = os.environ.get("VPN_ISOLATION_TOKEN", "")


class VPNProfile(db.Model):
    __tablename__ = "vpn_profiles"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(191), unique=True, nullable=False)
    vpn_ip = db.Column(db.String(45))
    # UNIQUE: one profile per account, enforced by the database rather than by
    # application logic that a race could slip past.
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), unique=True, nullable=True
    )
    assigned_at = db.Column(db.DateTime, nullable=True)


def _audit(message):
    """Append-only audit line. Wazuh tails this file via a localfile stanza."""
    stamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as handle:
            handle.write("%s ctfd-vpn %s\n" % (stamp, message))
    except OSError:
        pass


def _vpn_ip_for(filename):
    """player07.ovpn -> 10.8.0.106. Mirrors the ccd map built on the gateway."""
    base = os.path.basename(filename)
    if base.startswith("admin"):
        return os.environ.get("VPN_ADMIN_IP", "10.8.0.50")
    digits = "".join(ch for ch in base if ch.isdigit())
    if not digits:
        return None
    octets = os.environ.get("VPN_OCTETS", "10.8.0")
    base_last = int(os.environ.get("VPN_PLAYER_BASE", "100"))
    return "%s.%d" % (octets, base_last + int(digits) - 1)


def _seed_pool():
    """Register any profile file not yet known. Idempotent, so it is safe to
    call on every boot and again lazily once ctf_manager.sh has SCP'd the
    profiles in (which happens after this container first starts)."""
    if not os.path.isdir(PROFILE_DIR):
        return 0
    known = {row.filename for row in VPNProfile.query.all()}
    added = 0
    for name in sorted(os.listdir(PROFILE_DIR)):
        # Admin profile is handed out by the operator, never through CTFd.
        if not name.endswith(".ovpn") or name.startswith("admin"):
            continue
        if name in known:
            continue
        db.session.add(VPNProfile(filename=name, vpn_ip=_vpn_ip_for(name)))
        added += 1
    if added:
        db.session.commit()
        _audit("POOL_SEED added=%d total=%d" % (added, VPNProfile.query.count()))
    return added


def _claim_for(user):
    """Return this user's profile, allocating one on first request."""
    existing = VPNProfile.query.filter_by(user_id=user.id).first()
    if existing:
        return existing

    _seed_pool()

    # Atomic in MariaDB/MySQL: the UPDATE takes a row lock, so two players
    # hitting this at the same instant cannot receive the same profile.
    try:
        db.session.execute(
            text(
                "UPDATE vpn_profiles SET user_id = :uid, assigned_at = :ts "
                "WHERE user_id IS NULL ORDER BY id LIMIT 1"
            ),
            {"uid": user.id, "ts": datetime.datetime.utcnow()},
        )
        db.session.commit()
    except IntegrityError:
        # Lost a race with another request from this same account.
        db.session.rollback()

    claimed = VPNProfile.query.filter_by(user_id=user.id).first()
    if claimed:
        _audit(
            "ASSIGN user_id=%s name=%s profile=%s vpn_ip=%s"
            % (user.id, user.name, claimed.filename, claimed.vpn_ip)
        )
    else:
        _audit("POOL_EXHAUSTED user_id=%s name=%s" % (user.id, user.name))
    return claimed


def load(app):
    app.db.create_all()

    blueprint = Blueprint(
        "vpn_handout", __name__, template_folder="templates", static_folder="assets"
    )

    with app.app_context():
        try:
            _seed_pool()
        except Exception:
            db.session.rollback()

    @blueprint.route("/vpn", methods=["GET"])
    @authed_only
    def vpn_page():
        user = get_current_user()
        profile = _claim_for(user)
        remaining = VPNProfile.query.filter_by(user_id=None).count()
        return render_template("vpn.html", profile=profile, remaining=remaining)

    @blueprint.route("/vpn/download", methods=["GET"])
    @authed_only
    def vpn_download():
        user = get_current_user()
        profile = _claim_for(user)
        if not profile:
            abort(503, "No VPN profiles remain. Contact an organiser.")

        # Path is rebuilt from a basename of a DB-held value and confined to
        # PROFILE_DIR: a tampered row still cannot escape the directory.
        safe = os.path.basename(profile.filename)
        path = os.path.join(PROFILE_DIR, safe)
        if os.path.dirname(os.path.abspath(path)) != os.path.abspath(PROFILE_DIR):
            abort(400)
        if not os.path.isfile(path):
            abort(404, "Profile missing on disk. Contact an organiser.")

        _audit(
            "DOWNLOAD user_id=%s name=%s profile=%s vpn_ip=%s"
            % (user.id, user.name, safe, profile.vpn_ip)
        )
        return send_file(path, as_attachment=True, download_name=safe)

    @blueprint.route("/admin/vpn", methods=["GET"])
    @admins_only
    def vpn_admin():
        # Profiles arrive over SSH after the container first starts, so make
        # the admin view pick up any new files rather than showing "0 of 0".
        try:
            _seed_pool()
        except Exception:
            db.session.rollback()
        rows = VPNProfile.query.order_by(VPNProfile.id).all()
        uids = [r.user_id for r in rows if r.user_id]
        users = (
            {u.id: u for u in Users.query.filter(Users.id.in_(uids)).all()}
            if uids
            else {}
        )
        assigned = len(uids)
        return render_template(
            "admin_vpn.html", rows=rows, users=users, assigned=assigned, total=len(rows)
        )

    @blueprint.route("/vpn/isolation-map", methods=["GET"])
    def vpn_isolation_map():
        """Who may reach which per-player instance port.

        The gateway polls this and turns it into nftables rules, so that a
        team can reach its own instances and nobody else's. Read-only, and
        guarded by a shared token rather than a login, because the caller is
        the gateway, not a person.

        Returns [{"ip": "10.8.0.106", "port": 10043}, ...] - one entry per
        (allowed source address, instance port) pair.
        """
        if not ISOLATION_TOKEN:
            abort(503, "isolation map disabled")
        sent = request.headers.get("Authorization", "")
        expected = "Bearer " + ISOLATION_TOKEN
        # constant-time compare: this endpoint is reachable on the public port
        if not hmac.compare_digest(sent, expected):
            abort(403)

        # whale's table. Query it raw so this plugin never imports whale and
        # keeps working if whale is absent or upgraded.
        try:
            rows = db.session.execute(
                text(
                    "SELECT user_id, port FROM whale_container "
                    "WHERE port IS NOT NULL AND port > 0"
                )
            ).fetchall()
        except Exception:
            db.session.rollback()
            return jsonify([])

        pairs = []
        for user_id, port in rows:
            owner = Users.query.filter_by(id=user_id).first()
            if owner is None:
                continue
            # teams mode -> the whole team may reach it. users mode (team_id is
            # NULL) -> only the owner. Same code path serves both.
            if getattr(owner, "team_id", None):
                allowed = Users.query.filter_by(team_id=owner.team_id).all()
            else:
                allowed = [owner]
            for member in allowed:
                assignment = VPNProfile.query.filter_by(user_id=member.id).first()
                if assignment and assignment.vpn_ip:
                    pairs.append({"ip": assignment.vpn_ip, "port": int(port)})
        return jsonify(pairs)

    app.register_blueprint(blueprint)
    register_user_page_menu_bar("VPN", "/vpn")
