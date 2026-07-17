from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from imprint.capture.schema import build_capture_envelope, new_urn
from imprint.authority import AuthorityService, ChallengeRequest
from imprint.errors import ValidationError
from imprint.store.service import ImprintStore


class _TestNativeConsole:
    """Deterministic native-console double for exercising the real key APIs."""

    def __init__(self, *, enrollment: bool = False):
        self._lines = iter(("ENROLL DECLINE-RECOVERY",) if enrollment else ("APPROVE",))
        self._secrets = iter(("test authority passphrase", "test authority passphrase")
                             if enrollment else ("test authority passphrase",))

    def require_native(self):
        return None

    def write(self, _value):
        return None

    def read_line(self, _prompt):
        if "SIGN SNAPSHOT" in _prompt:
            return "SIGN SNAPSHOT"
        return next(self._lines)

    def read_secret(self, _prompt):
        return next(self._secrets)


class SignedStoreHarness:
    """An enrolled store plus exact, command-bound approval-token issuance.

    ``call`` deliberately asks the production writer for its exact proposal,
    approves that proposal through ``AuthorityService``, then retries with the
    resulting token.  There is no test bypass and both attempts execute the
    same public method.
    """

    def __init__(self, path: Path, operator_id: str, *, initialize: bool = True):
        self.store = ImprintStore(path, expected_operator_id=operator_id)
        if initialize:
            self.store.initialize()
        self.service = AuthorityService(path.parent, self.store, operator_id=operator_id)
        self.service.enroll(console=_TestNativeConsole(enrollment=True))

    @staticmethod
    def _request(exc: ValidationError) -> ChallengeRequest:
        prefix = "E_AUTH_APPROVAL_REQUIRED approval_request="
        message = str(exc)
        if not message.startswith(prefix):
            raise exc
        value = json.loads(message[len(prefix):])
        return ChallengeRequest(
            operation_id=value["operation_id"], purpose=value["purpose"],
            payload_sha256=value["payload_sha256"],
            prior_state_sha256=value["prior_state_sha256"],
            execution_fields_sha256=value["execution_fields_sha256"],
            authority_transition=value["authority_transition"],
            subject_ids=tuple(value["subject_ids"]), source_ids=tuple(value["source_ids"]),
            target_ids=tuple(value["target_ids"]), proposal_ids=tuple(value["proposal_ids"]),
            result_version_ids=tuple(value["result_version_ids"]),
            scope=tuple(value["scope"]), field_paths=tuple(value["field_paths"]),
        )

    def token_for(self, function, /, *args, **kwargs) -> dict:
        try:
            function(*args, **kwargs)
        except ValidationError as exc:
            request = self._request(exc)
        else:
            raise AssertionError("operation did not request signed authority")
        return self.approve_request(request)

    def approve_request(self, request: ChallengeRequest | dict) -> dict:
        if isinstance(request, dict):
            request = ChallengeRequest(
                operation_id=request["operation_id"], purpose=request["purpose"],
                payload_sha256=request["payload_sha256"],
                prior_state_sha256=request["prior_state_sha256"],
                execution_fields_sha256=request["execution_fields_sha256"],
                authority_transition=request["authority_transition"],
                subject_ids=tuple(request.get("subject_ids", ())),
                source_ids=tuple(request.get("source_ids", ())),
                target_ids=tuple(request.get("target_ids", ())),
                proposal_ids=tuple(request.get("proposal_ids", ())),
                result_version_ids=tuple(request.get("result_version_ids", ())),
                scope=tuple(request.get("scope", ())),
                field_paths=tuple(request.get("field_paths", ())),
            )
        return self.service.approve(request, console=_TestNativeConsole()).as_dict()

    def call(self, function, /, *args, **kwargs):
        token = self.token_for(function, *args, **kwargs)
        return function(*args, **kwargs, approval_token=token)

    def signed_backup(self, root: Path):
        from imprint.backup import create_backup
        result = create_backup(
            self.store, root, authority_service=self.service,
            signing_console=_TestNativeConsole(),
        )
        assert result["authenticity"] == "signed-authority-snapshot"
        assert result["signature_b64"]
        assert result["authority_checkpoint"]
        assert Path(result["authority_checkpoint_path"]).exists()
        return result


@pytest.fixture
def signed_store():
    def create(path, operator_id, *, initialize=True):
        return SignedStoreHarness(Path(path), operator_id, initialize=initialize)
    return create


@pytest.fixture
def signed_cli(tmp_path):
    """Run one CLI mutation through proposal -> real signature -> execution."""
    counter = 0

    def run(main, argv, capsys, authority):
        nonlocal counter
        assert main(argv) == 2
        failed = json.loads(capsys.readouterr().out)
        prefix = "E_AUTH_APPROVAL_REQUIRED approval_request="
        error = failed["error"]
        assert error.startswith(prefix), error
        token = authority.approve_request(json.loads(error[len(prefix):]))
        counter += 1
        path = tmp_path / f"approval-token-{counter}.json"
        path.write_text(json.dumps(token), encoding="utf-8")
        return main([*argv, "--approval-token", str(path)])

    return run


@pytest.fixture
def capture_envelope():
    text = "Do not hide a failed source; say which source failed because missing evidence changes the conclusion."
    envelope = build_capture_envelope(
        operator_id=new_urn("operator"),
        session_id=new_urn("session"),
        node_id="workstation-a",
        case_description="Reviewing a multi-source research synthesis",
        raw_operator_text=text,
        call_type="correct",
        capture_mechanism="explicit_cli",
        captured_by="imprint-test",
        reason="Missing evidence changes the conclusion.",
        captured_at="2026-07-14T18:00:00Z",
    )
    return deepcopy(envelope)
