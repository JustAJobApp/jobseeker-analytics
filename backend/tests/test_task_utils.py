from datetime import datetime, timezone, timedelta
from db import processing_tasks as task_models
from utils.task_utils import get_lifetime_processed_count, get_active_task

class TestTaskUtils:

    def test_get_lifetime_processed_count_sums_history(self, db_session, logged_in_user):
        """Verify that email counts are summed correctly across all historical records."""
        user_id = logged_in_user.user_id
        
        # Create multiple historical runs with different email counts
        run1 = task_models.TaskRuns(
            user_id=user_id, 
            status=task_models.FINISHED, 
            processed_emails=150,
            updated=datetime.now(timezone.utc) - timedelta(days=2)
        )
        run2 = task_models.TaskRuns(
            user_id=user_id, 
            status=task_models.FINISHED, 
            processed_emails=250,
            updated=datetime.now(timezone.utc) - timedelta(days=1)
        )
        # An unfinished/cancelled run should still contribute its processed count
        run3 = task_models.TaskRuns(
            user_id=user_id, 
            status=task_models.CANCELLED, 
            processed_emails=50,
            updated=datetime.now(timezone.utc)
        )
        
        db_session.add_all([run1, run2, run3])
        db_session.commit()

        # Total should be 150 + 250 + 50 = 450
        total = get_lifetime_processed_count(user_id, db_session)
        assert total == 450

    def test_get_lifetime_processed_count_returns_zero_for_new_user(self, db_session):
        """Verify that a user with no task history returns a count of zero."""
        total = get_lifetime_processed_count("non_existent_user", db_session)
        assert total == 0

    def test_get_active_task_finds_started_record(self, db_session, logged_in_user):
        """Verify that a task in the 'started' state is correctly identified."""
        user_id = logged_in_user.user_id
        
        # Create a finished task and a started task
        finished_task = task_models.TaskRuns(user_id=user_id, status=task_models.FINISHED)
        active_task = task_models.TaskRuns(user_id=user_id, status=task_models.STARTED)
        
        db_session.add_all([finished_task, active_task])
        db_session.commit()

        found_task = get_active_task(user_id, db_session)
        assert found_task is not None
        assert found_task.status == task_models.STARTED
        assert found_task.id == active_task.id

    def test_get_active_task_returns_none_when_all_finished(self, db_session, logged_in_user):
        """Verify that get_active_task returns None if all historical tasks are finished or cancelled."""
        user_id = logged_in_user.user_id
        
        finished_task = task_models.TaskRuns(user_id=user_id, status=task_models.FINISHED)
        cancelled_task = task_models.TaskRuns(user_id=user_id, status=task_models.CANCELLED)
        
        db_session.add_all([finished_task, cancelled_task])
        db_session.commit()

        found_task = get_active_task(user_id, db_session)
        assert found_task is None

    def test_task_runs_updated_column_is_refreshed(self, db_session, logged_in_user):
        """Verify the fix for the 'updated' column bug. 
        
        This confirms that the timestamp changes when the record is modified in the DB.
        """
        user_id = logged_in_user.user_id
        task = task_models.TaskRuns(user_id=user_id, status=task_models.STARTED)
        db_session.add(task)
        db_session.commit()
        db_session.refresh(task)
        
        initial_time = task.updated
        
        # Simulate processing an email and updating the record
        task.processed_emails = 10
        db_session.add(task)
        db_session.commit()
        db_session.refresh(task)
        
        # The updated timestamp must be later than the initial creation time
        assert task.updated > initial_time