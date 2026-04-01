from unittest import mock
from fastapi import Request
from sqlmodel import select

from db import processing_tasks as task_models
from routes.email_routes import fetch_emails_to_db


def test_processing(logged_in_client, started_task):
    # make request to check on processing status
    resp = logged_in_client.get("/processing/status", follow_redirects=False)
    # assert response
    assert resp.status_code == 200, resp.headers
    assert resp.json()["processed_emails"] == 0


def test_processing_idle(logged_in_client):
    # No task exists, should return idle status
    resp = logged_in_client.get("/processing/status", follow_redirects=False)
    assert resp.status_code == 200
    assert resp.json()["status"] == "idle"


def test_processing_unauthenticated(incognito_client):
    resp = incognito_client.get("/processing/status", follow_redirects=False)
    # Unauthenticated users get 401
    assert resp.status_code == 401


def test_fetch_emails_to_db(logged_in_user, db_session, mock_authenticated_user):
    with mock.patch("routes.email_routes.get_email_ids", return_value=[]):
        fetch_emails_to_db(
            mock_authenticated_user,
            Request({"type": "http", "session": {}}),
            user_id=logged_in_user.user_id,
            gmail_query="after:2026/01/01 -from:me -in:sent AND (subject:interview)",
        )

        process_task_run: task_models.TaskRuns = db_session.exec(
            select(task_models.TaskRuns).where(
                task_models.TaskRuns.user_id == logged_in_user.user_id,
                task_models.TaskRuns.status == task_models.STARTED,
            )
        ).one_or_none()
        assert process_task_run is None


def test_fetch_emails_to_db_in_progress_no_new_scan(
    logged_in_user, started_task, db_session, mock_authenticated_user
):
    """When a scan is already in progress, no new scan should start."""
    with mock.patch(
        "routes.email_routes.get_email_ids", return_value=[]
    ) as mock_get_email_ids:
        fetch_emails_to_db(
            mock_authenticated_user,
            Request({"type": "http", "session": {}}),
            user_id=logged_in_user.user_id,
            gmail_query="after:2026/01/01 -from:me -in:sent AND (subject:interview)",
        )

        # Should not attempt to fetch emails since scan already in progress
        mock_get_email_ids.assert_not_called()

        # The existing task should remain in STARTED status (unchanged)
        db_session.refresh(started_task)
        assert started_task.status == task_models.STARTED
