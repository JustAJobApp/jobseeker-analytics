import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from db.users import Users
from utils.billing_utils import SyncPolicy, BATCH_SAFETY_LIMIT, FREE_LOOKBACK_DAYS

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def free_user():
    return Users(
        user_id="free_user_123",
        sync_tier="none",
        start_date=datetime.now(timezone.utc) - timedelta(days=60) # Older than 30 days
    )

@pytest.fixture
def premium_user():
    return Users(
        user_id="premium_user_456",
        sync_tier="premium",
        start_date=datetime.now(timezone.utc) - timedelta(days=60)
    )

class TestSyncPolicy:
    
    @patch("utils.billing_utils.get_lifetime_processed_count")
    def test_free_user_lookback_enforcement(self, mock_count, free_user, mock_db):
        """Verify free users are capped at 30 days lookback."""
        mock_count.return_value = 0
        policy = SyncPolicy(free_user, mock_db)
        
        effective_start = policy.get_effective_start_date()
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=FREE_LOOKBACK_DAYS)
        
        # Should be shifted to 30 days ago because original start was 60 days ago
        assert (thirty_days_ago - effective_start).total_seconds() < 1
        
    @patch("utils.billing_utils.get_lifetime_processed_count")
    def test_premium_user_lookback_bypass(self, mock_count, premium_user, mock_db):
        """Verify premium users keep their original start date."""
        mock_count.return_value = 0
        policy = SyncPolicy(premium_user, mock_db)
        
        effective_start = policy.get_effective_start_date()
        # Should remain the original 60 days ago
        assert (premium_user.start_date - effective_start).total_seconds() < 1

    @patch("utils.billing_utils.get_lifetime_processed_count")
    def test_free_user_lifetime_limit(self, mock_count, free_user, mock_db):
        """Verify free user stops exactly at 1000 emails."""
        # User has already processed 950 emails
        mock_count.return_value = 950
        policy = SyncPolicy(free_user, mock_db)
        
        # Batch limit should be 50 (1000 - 950), not the 100 safety limit
        assert policy.get_batch_limit() == 50
        
        # User has processed 1000 emails
        mock_count.return_value = 1000
        assert policy.get_batch_limit() == 0

    @patch("utils.billing_utils.get_lifetime_processed_count")
    def test_premium_user_safety_batch(self, mock_count, premium_user, mock_db):
        """Verify premium users always stop at the safety batch size."""
        mock_count.return_value = 500
        policy = SyncPolicy(premium_user, mock_db)
        
        # Even with high quota, batch is capped at 100 for hardware safety
        assert policy.get_batch_limit() == BATCH_SAFETY_LIMIT

    def test_premium_chaining_logic(self, premium_user, mock_db):
        """Verify premium users trigger chaining when more emails exist."""
        policy = SyncPolicy(premium_user, mock_db)
        
        # Case: Safety limit hit, 500 total messages found
        # Should chain because 100 < 500
        assert policy.should_chain(processed_this_run=100, total_found=500) is True
        
        # Case: Task finished naturally (only 50 messages found)
        # Should NOT chain
        assert policy.should_chain(processed_this_run=50, total_found=50) is False

    @patch("utils.billing_utils.get_lifetime_processed_count")
    def test_free_user_no_chaining(self, mock_count, free_user, mock_db):
        """Verify free users never auto-chain tasks."""
        mock_count.return_value = 0
        policy = SyncPolicy(free_user, mock_db)
        
        # Even if safety limit hit, free users do not chain
        assert policy.should_chain(processed_this_run=100, total_found=500) is False