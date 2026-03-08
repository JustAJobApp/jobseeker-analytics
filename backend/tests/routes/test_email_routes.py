import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from fastapi import Request
from db import processing_tasks as task_models
from db.users import Users
from routes.email_routes import processing_status, start_processing, _fetch_emails_to_db_impl
from sqlmodel import select

@pytest.fixture
def mock_request():
    request = MagicMock(spec=Request)
    request.session = {"start_date": "2024/01/01"}
    return request

@pytest.fixture
def mock_bg_tasks():
    return MagicMock()

class TestEmailRoutes:

    @patch("routes.email_routes.validate_session")
    def test_processing_status_returns_latest_task(self, mock_val, db_session, logged_in_user):
        """Verify that the status endpoint always retrieves the most recent historical run."""
        mock_val.return_value = logged_in_user.user_id
        
        # Create two historical runs
        old_run = task_models.TaskRuns(
            user_id=logged_in_user.user_id, 
            status=task_models.FINISHED,
            updated=datetime.now(timezone.utc) - timedelta(hours=2)
        )
        new_run = task_models.TaskRuns(
            user_id=logged_in_user.user_id, 
            status=task_models.STARTED,
            updated=datetime.now(timezone.utc)
        )
        db_session.add_all([old_run, new_run])
        db_session.commit()

        response = pytest.asyncio.run(processing_status(MagicMock(), db_session, logged_in_user.user_id))
        
        # Should return 'processing' based on the newest run
        assert response["status"] == "processing"
        assert response["total_emails"] == 0

    @patch("routes.email_routes.get_credentials_for_background_task")
    @patch("routes.email_routes.BackgroundTasks.add_task")
    def test_start_processing_prevents_duplicates(self, mock_add, mock_creds, db_session, logged_in_user):
        """Verify that a new scan cannot start if an 'active' task already exists."""
        # Create an existing active task
        active_task = task_models.TaskRuns(user_id=logged_in_user.user_id, status=task_models.STARTED)
        db_session.add(active_task)
        db_session.commit()

        with pytest.raises(Exception) as excinfo:
            pytest.asyncio.run(start_processing(MagicMock(), MagicMock(), db_session, logged_in_user.user_id))
        
        assert excinfo.value.status_code == 409
        assert excinfo.value.detail == "already_processing"

    @patch("routes.email_routes.get_email_ids")
    @patch("routes.email_routes.SyncPolicy")
    def test_fetch_impl_creates_unique_historical_record(self, mock_policy, mock_get_ids, db_session, logged_in_user, mock_request):
        """Verify that every fetch attempt creates a brand new TaskRuns record for auditing."""
        mock_get_ids.return_value = [] # No emails found
        
        # Setup policy to allow start
        policy_inst = mock_policy.return_value
        policy_inst.can_start_new_task.return_value = True
        policy_inst.get_effective_start_date.return_value = datetime.now(timezone.utc)
        policy_inst.get_batch_limit.return_value = 100

        auth_user = MagicMock()
        _fetch_emails_to_db_impl(auth_user, mock_request, user_id=logged_in_user.user_id)

        # Check that a new record exists in DB
        tasks = db_session.exec(select(task_models.TaskRuns).where(task_models.TaskRuns.user_id == logged_in_user.user_id)).all()
        assert len(tasks) == 1
        assert tasks[0].status == task_models.FINISHED

    @patch("routes.email_routes.get_email_ids")
    @patch("routes.email_routes.SyncPolicy")
    @patch("routes.email_routes.fetch_emails_to_db")
    def test_premium_user_triggers_immediate_chaining(self, mock_fetch, mock_policy, mock_get_ids, db_session, logged_in_user, mock_request, mock_bg_tasks):
        """Verify that premium users trigger the next batch immediately if safety limits are hit."""
        # Simulate finding 500 emails
        mock_get_ids.return_value = [{"id": f"msg_{i}"} for i in range(500)]
        
        # Mock policy to trigger chaining
        policy_inst = mock_policy.return_value
        policy_inst.can_start_new_task.return_value = True
        policy_inst.get_batch_limit.return_value = 100
        policy_inst.should_chain.return_value = True # Important: Force chain
        policy_inst.get_effective_start_date.return_value = datetime.now(timezone.utc)

        auth_user = MagicMock()
        _fetch_emails_to_db_impl(
            auth_user, 
            mock_request, 
            user_id=logged_in_user.user_id, 
            background_tasks=mock_bg_tasks
        )

        # Ensure the next batch was added to the background task queue
        assert mock_bg_tasks.add_task.called
        assert mock_bg_tasks.add_task.call_args[0][0] == mock_fetch

    @patch("routes.email_routes.SyncPolicy")
    def test_fetch_impl_enforces_quota_denial(self, mock_policy, db_session, logged_in_user, mock_request):
        """Verify that a task is not even created if the policy denies it (Quota reached)."""
        policy_inst = mock_policy.return_value
        policy_inst.can_start_new_task.return_value = False # Quota full
        
        auth_user = MagicMock()
        _fetch_emails_to_db_impl(auth_user, mock_request, user_id=logged_in_user.user_id)

        # No tasks should have been created in the database
        tasks = db_session.exec(select(task_models.TaskRuns).where(task_models.TaskRuns.user_id == logged_in_user.user_id)).all()
        assert len(tasks) == 0