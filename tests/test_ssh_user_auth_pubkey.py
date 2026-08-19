from pathlib import Path
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


def _ticket_request_parameters(**overrides):
    defaults = dict(
        allow_own_credential_management=True,
        minimize_password_login=False,
        rate_limit_bytes_per_second=None,
        ssh_client_auth_keyboard_interactive=True,
        ssh_client_auth_password=True,
        ssh_client_auth_publickey=True,
        ticket_self_service_enabled=True,
        ticket_auto_approve_existing_access=False,
        ticket_require_description=True,
        ticket_request_show_all_targets=True,
    )
    defaults.update(overrides)
    return sdk.ParameterUpdate(**defaults)


class Test:
    def test_ed25519(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            # 'sh', '-c', '"ls /bin/sh;sleep 1"',
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0

    def test_active_self_service_ticket_grants_public_key_user(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """An activated ticket grants an authenticated SSH user target access.

        The user has no target role. Their signed public-key authentication
        establishes the identity, then the server-side active ticket supplies
        the time-bounded target grant. This is distinct from ticket-secret SSH
        authentication, whose secret is the credential itself.
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
                ),
            )
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.update_parameters(_ticket_request_parameters())

        try:
            ticket_session = requests.Session()
            ticket_session.verify = False
            login = ticket_session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
            )
            assert login.status_code // 100 == 2

            request = ticket_session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": ssh_target.name,
                    "duration_seconds": 3600,
                    "description": "SSH JIT grant",
                },
            )
            assert request.status_code == 201, request.text
            request_id = request.json()["request"]["id"]

            with admin_client(url) as api:
                api.approve_ticket_request(request_id)

            activation = ticket_session.post(
                f"{url}/@warpgate/api/ticket-requests/{request_id}/activate"
            )
            assert activation.status_code == 200, activation.text

            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "-o",
                "PreferredAuthentications=publickey",
                "ls",
                "/bin/sh",
            )
            assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
            assert ssh_client.returncode == 0
        finally:
            with admin_client(url) as api:
                api.update_parameters(
                    _ticket_request_parameters(
                        ticket_self_service_enabled=False,
                        ticket_request_show_all_targets=False,
                    )
                )

    def test_rsa(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_rsa.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="localhost",
                        port=ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            ))
            api.add_target_role(ssh_target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-v",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0
