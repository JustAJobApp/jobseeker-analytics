from unittest.mock import patch
from utils.config_utils import get_settings
from config import Settings
import pytest
import json
import os
from routes.email_routes import fetch_emails_to_db
from fastapi.responses import JSONResponse


@pytest.fixture(scope="session", autouse=True)
def setup_static_directory():
    static_dir = os.path.join(os.path.dirname(__file__), "../static")
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)


@patch("utils.config_utils.config.ConfigSettings")
def test_get_settings_only_called_once_with_lru(mock_settings_call):
    get_settings.cache_clear()
    get_settings()
    get_settings()
    # Ensure the Settings constructor is called only once due to lru_cache
    mock_settings_call.assert_called_once()
    get_settings.cache_clear()


def test_import_settings_does_not_raise_error():
    import utils.llm_utils  # noqa: F401
    import utils.auth_utils  # noqa: F401


def test_decode_scopes_valid_json():
    input_str = '["https://www.googleapis.com/auth/gmail.readonly", "openid"]'
    expected_output = ["https://www.googleapis.com/auth/gmail.readonly", "openid"]
    assert Settings.decode_scopes(input_str) == expected_output


def test_decode_scopes_with_extra_quotes():
    input_str = '\'["https://www.googleapis.com/auth/gmail.readonly", "openid"]\''
    expected_output = ["https://www.googleapis.com/auth/gmail.readonly", "openid"]
    assert Settings.decode_scopes(input_str) == expected_output


def test_decode_scopes_invalid_json():
    input_str = '["https://www.googleapis.com/auth/gmail.readonly", "openid"'
    with pytest.raises(json.JSONDecodeError):
        Settings.decode_scopes(input_str)


def test_decode_scopes_empty_string():
    input_str = ""
    with pytest.raises(json.JSONDecodeError):
        Settings.decode_scopes(input_str)


def test_prod_is_publicly_deployed_true():
    settings = Settings(ENV="prod")
    assert settings.is_publicly_deployed


def test_dev_is_publicly_deployed_false():
    settings = Settings(ENV="dev")
    assert not settings.is_publicly_deployed


def test_staging_is_publicly_deployed_true():
    settings = Settings(ENV="staging")
    assert settings.is_publicly_deployed


def test_batch_size_ends_email_processing_early(
    task_with_300_processed_emails, mock_request, mock_authenticated_user, db_session
):
    """
    Using a test user with a task run that has already reached the batch size,
    we should return a processing complete message.
    The get_email_ids function should not be called because we return early due to batch size limit.
    The user will not be able to fetch any more emails until the next day.
    This is needed due to free tier limits of LLM calls like Gemini, which has a limit of 200 calls per day.
    """
    settings = Settings(
        ENV="prod", BATCH_SIZE=300
    )  # Set batch size equal to processed emails
    user = task_with_300_processed_emails.user
    # The task should already have processed_emails >= batch_size (300 >= 200)
    assert task_with_300_processed_emails.processed_emails >= settings.batch_size_by_env
    with patch("routes.email_routes.get_email_ids") as mock_get_email_ids:
        result = fetch_emails_to_db(
            mock_authenticated_user,
            request=mock_request,
            user_id=user.user_id,
            db_session=db_session,
        )
        # Should return a JSONResponse with processing complete message
        assert isinstance(result, JSONResponse)
        assert (
            result.body.decode()
            == '{"message":"Processing complete"}'
        )
        # The get_email_ids function should not be called because we return early due to batch size limit
        assert mock_get_email_ids.call_count == 0
