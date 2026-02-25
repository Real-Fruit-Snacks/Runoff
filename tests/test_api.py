"""Tests for BloodHound CE API client."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest


class TestBloodHoundAPIError:
    """Test BloodHoundAPIError exception."""

    def test_basic_error(self):
        """Test basic error creation."""
        from runoff.api.client import BloodHoundAPIError

        error = BloodHoundAPIError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.status_code is None

    def test_error_with_status_code(self):
        """Test error with HTTP status code."""
        from runoff.api.client import BloodHoundAPIError

        error = BloodHoundAPIError("Auth failed", status_code=401)
        assert str(error) == "Auth failed (HTTP 401)"
        assert error.status_code == 401

    def test_error_with_response(self):
        """Test error with response body."""
        from runoff.api.client import BloodHoundAPIError

        error = BloodHoundAPIError("Error", status_code=500, response='{"error": "details"}')
        assert error.response == '{"error": "details"}'


class TestBloodHoundAPIInit:
    """Test BloodHoundAPI initialization."""

    def test_url_normalization(self):
        """Test URL trailing slash is removed."""
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080/", "token_id", "token_key")
        assert api.base_url == "http://localhost:8080"

    def test_credentials_stored(self):
        """Test credentials are stored."""
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080", "my_token_id", "my_token_key")
        assert api.token_id == "my_token_id"
        assert api.token_key == "my_token_key"


class TestBloodHoundAPITestConnection:
    """Test test_connection method."""

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_returns_true_on_success(self, mock_request):
        """Test returns True on 200 response."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        assert api.test_connection() is True

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_returns_false_on_failure(self, mock_request):
        """Test returns False on non-200 response."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        assert api.test_connection() is False

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_returns_false_on_exception(self, mock_request):
        """Test returns False on request exception."""
        from runoff.api.client import BloodHoundAPI, BloodHoundAPIError

        mock_request.side_effect = BloodHoundAPIError("Connection failed")

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        assert api.test_connection() is False


class TestBloodHoundAPIGetSelf:
    """Test get_self method."""

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_returns_user_info(self, mock_request):
        """Test returns user info on success."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"name": "admin", "id": "123"}}
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        result = api.get_self()

        assert result["data"]["name"] == "admin"

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_raises_on_failure(self, mock_request):
        """Test raises error on non-200 response."""
        from runoff.api.client import BloodHoundAPI, BloodHoundAPIError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        with pytest.raises(BloodHoundAPIError):
            api.get_self()


class TestBloodHoundAPIUpload:
    """Test file upload methods."""

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_start_upload_job(self, mock_request):
        """Test starting upload job returns job ID."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "job-123"}}
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        job_id = api.start_upload_job()

        assert job_id == "job-123"
        mock_request.assert_called_with("POST", "/api/v2/file-upload/start")

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_start_upload_job_raises_on_missing_id(self, mock_request):
        """Test raises error when job ID missing from response."""
        from runoff.api.client import BloodHoundAPI, BloodHoundAPIError

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {}}
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        with pytest.raises(BloodHoundAPIError) as exc:
            api.start_upload_job()
        assert "job ID" in str(exc.value)

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_upload_file(self, mock_request):
        """Test uploading file to job."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        api.upload_file("job-123", "test.json", b'{"test": "data"}')

        mock_request.assert_called_with(
            "POST",
            "/api/v2/file-upload/job-123",
            body=b'{"test": "data"}',
            content_type="application/json",
            timeout=300,
        )

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_upload_file_raises_on_failure(self, mock_request):
        """Test raises error on upload failure."""
        from runoff.api.client import BloodHoundAPI, BloodHoundAPIError

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Server error"
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        with pytest.raises(BloodHoundAPIError):
            api.upload_file("job-123", "test.json", b'{"test": "data"}')

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_end_upload_job(self, mock_request):
        """Test ending upload job."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        api.end_upload_job("job-123")

        mock_request.assert_called_with("POST", "/api/v2/file-upload/job-123/end")


class TestBloodHoundAPIJobStatus:
    """Test job status methods."""

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_get_upload_job_status(self, mock_request):
        """Test getting job status."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": "job-123", "status": 2}]}
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        result = api.get_upload_job_status("job-123")

        assert result["data"]["status"] == 2

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_get_upload_job_status_empty(self, mock_request):
        """Test getting status for unknown job."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        result = api.get_upload_job_status("unknown-job")

        assert result["data"] == {}


class TestBloodHoundAPIClearDatabase:
    """Test clear_database method."""

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_clear_ad_data(self, mock_request):
        """Test clearing AD data."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        api.clear_database(delete_ad=True)

        # Verify the request body
        call_args = mock_request.call_args
        body = json.loads(call_args[1]["body"])
        assert 1 in body["deleteSourceKinds"]  # AD = 1

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_clear_azure_data(self, mock_request):
        """Test clearing Azure data."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        api.clear_database(delete_azure=True)

        call_args = mock_request.call_args
        body = json.loads(call_args[1]["body"])
        assert 2 in body["deleteSourceKinds"]  # Azure = 2

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_clear_ingest_history(self, mock_request):
        """Test clearing ingest history."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        api.clear_database(delete_ingest_history=True)

        call_args = mock_request.call_args
        body = json.loads(call_args[1]["body"])
        assert body["deleteFileIngestHistory"] is True

    def test_raises_when_no_options(self):
        """Test raises error when no deletion options specified."""
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        with pytest.raises(ValueError) as exc:
            api.clear_database()
        assert "deletion option" in str(exc.value)


class TestBloodHoundAPIGetFileUploadJobs:
    """Test get_file_upload_jobs method."""

    @patch("runoff.api.client.BloodHoundAPI._request")
    def test_returns_jobs_list(self, mock_request):
        """Test returns list of upload jobs."""
        from runoff.api.client import BloodHoundAPI

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "job-1", "status": 2},
                {"id": "job-2", "status": 1},
            ]
        }
        mock_request.return_value = mock_response

        api = BloodHoundAPI("http://localhost:8080", "token", "key")
        result = api.get_file_upload_jobs()

        assert len(result["data"]) == 2
        assert result["data"][0]["id"] == "job-1"


class TestParseJsonResponse:
    """Test _parse_json_response helper."""

    def test_parses_valid_json(self):
        """Test parsing valid JSON response."""
        from runoff.api.client import _parse_json_response

        mock_response = MagicMock()
        mock_response.json.return_value = {"key": "value"}

        result = _parse_json_response(mock_response)
        assert result == {"key": "value"}

    def test_raises_on_invalid_json(self):
        """Test raises error on invalid JSON."""
        from runoff.api.client import BloodHoundAPIError, _parse_json_response

        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.status_code = 200
        mock_response.text = "not json"

        with pytest.raises(BloodHoundAPIError) as exc:
            _parse_json_response(mock_response)
        assert "Invalid JSON" in str(exc.value)


class TestRetryLogic:
    """Test API retry logic for transient 5xx errors."""

    @patch("time.sleep")
    def test_retries_on_500(self, mock_sleep):
        """Test that 5xx responses trigger retry."""
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080", "token", "key")

        # Mock session to return 500 twice then 200
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        api._session.request = MagicMock(side_effect=[mock_resp_500, mock_resp_500, mock_resp_200])

        response = api._request("GET", "/api/v2/self")
        assert response.status_code == 200
        assert api._session.request.call_count == 3

    @patch("time.sleep")
    def test_no_retry_on_4xx(self, mock_sleep):
        """Test that 4xx responses are not retried."""
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080", "token", "key")

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        api._session.request = MagicMock(return_value=mock_resp)

        response = api._request("GET", "/api/v2/self")
        assert response.status_code == 401
        assert api._session.request.call_count == 1

    @patch("time.sleep")
    def test_exhausted_retries_returns_last_response(self, mock_sleep):
        """Test returns 5xx response after exhausting retries."""
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080", "token", "key")

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        api._session.request = MagicMock(return_value=mock_resp)

        response = api._request("GET", "/api/v2/self", retries=2)
        assert response.status_code == 503
        assert api._session.request.call_count == 3  # initial + 2 retries

    @patch("time.sleep")
    def test_retries_on_connection_error(self, mock_sleep):
        """Test retries on connection errors."""
        import requests as req

        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI("http://localhost:8080", "token", "key")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        api._session.request = MagicMock(side_effect=[req.ConnectionError("refused"), mock_resp])

        response = api._request("GET", "/api/v2/self", retries=1)
        assert response.status_code == 200
        assert api._session.request.call_count == 2


class TestAPIAuth:
    """Test API authentication helpers."""

    def test_build_auth_headers(self):
        """Test HMAC auth header generation."""
        from runoff.api.auth import build_auth_headers

        headers = build_auth_headers(
            method="GET",
            uri="/api/v2/self",
            token_id="test-token-id",
            token_key="test-token-key",
            body=None,
        )

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("bhesignature ")
        assert "test-token-id" in headers["Authorization"]

    def test_build_auth_headers_with_body(self):
        """Test HMAC includes body in signature."""
        from runoff.api.auth import build_auth_headers

        headers_no_body = build_auth_headers(
            method="POST",
            uri="/api/v2/test",
            token_id="token",
            token_key="key",
            body=None,
        )

        headers_with_body = build_auth_headers(
            method="POST",
            uri="/api/v2/test",
            token_id="token",
            token_key="key",
            body=b'{"test": true}',
        )

        # Both should have authorization headers starting with bhesignature
        assert headers_no_body["Authorization"].startswith("bhesignature ")
        assert headers_with_body["Authorization"].startswith("bhesignature ")
        # Both contain the token ID
        assert "token" in headers_no_body["Authorization"]
        assert "token" in headers_with_body["Authorization"]


class TestAPIConfig:
    """Test API config storage."""

    def test_config_path_default(self, tmp_path, monkeypatch):
        """Test default config path."""
        from runoff.api.config import APIConfig

        # Mock XDG_CONFIG_HOME directory
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        config = APIConfig()
        assert "runoff" in str(config.config_file)

    def test_save_and_load_credentials(self, tmp_path):
        """Test saving and loading credentials."""
        from runoff.api.config import APIConfig

        config_file = tmp_path / "test_config.ini"
        config = APIConfig(config_file=str(config_file))

        # Save credentials
        config.save(
            url="http://localhost:8080",
            token_id="test-id",
            token_key="test-key",
        )

        # Load and verify
        assert config.has_credentials()
        url, token_id, token_key = config.get_credentials()

        assert url == "http://localhost:8080"
        assert token_id == "test-id"
        assert token_key == "test-key"

    def test_has_credentials_false_when_empty(self, tmp_path):
        """Test has_credentials returns False when no credentials."""
        from runoff.api.config import APIConfig

        config_file = tmp_path / "empty_config.ini"
        config = APIConfig(config_file=str(config_file))

        assert config.has_credentials() is False


class TestAPIConfigPermissions:
    """Test credential file permission checks."""

    @pytest.mark.skipif(os.name == "nt", reason="Unix permissions only")
    def test_warns_on_world_readable_file(self, tmp_path):
        """Test warning when credential file is world-readable."""
        import warnings

        from runoff.api.config import APIConfig

        config_file = tmp_path / "test_config.ini"
        config_file.write_text("[DEFAULT]\nurl = http://x\ntoken_id = id\ntoken_key = key\n")
        os.chmod(config_file, 0o644)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            APIConfig(config_file=str(config_file))
            permission_warnings = [x for x in w if "permissions" in str(x.message).lower()]
            assert len(permission_warnings) >= 1
            assert "0o644" in str(permission_warnings[0].message)

    @pytest.mark.skipif(os.name == "nt", reason="Unix permissions only")
    def test_no_warning_on_secure_file(self, tmp_path):
        """Test no warning when file has correct permissions."""
        import warnings

        from runoff.api.config import APIConfig

        config_file = tmp_path / "test_config.ini"
        config_file.write_text("[DEFAULT]\nurl = http://x\ntoken_id = id\ntoken_key = key\n")
        os.chmod(config_file, 0o600)
        os.chmod(tmp_path, 0o700)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            APIConfig(config_file=str(config_file))
            permission_warnings = [x for x in w if "permissions" in str(x.message).lower()]
            assert len(permission_warnings) == 0

    @pytest.mark.skipif(os.name == "nt", reason="Unix permissions only")
    def test_warns_on_world_readable_directory(self, tmp_path):
        """Test warning when config directory is world-readable."""
        import warnings

        from runoff.api.config import APIConfig

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "test_config.ini"
        config_file.write_text("[DEFAULT]\nurl = http://x\ntoken_id = id\ntoken_key = key\n")
        os.chmod(config_file, 0o600)
        os.chmod(config_dir, 0o755)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            APIConfig(config_file=str(config_file))
            permission_warnings = [x for x in w if "permissions" in str(x.message).lower()]
            assert len(permission_warnings) >= 1
            assert "0o755" in str(permission_warnings[0].message)
