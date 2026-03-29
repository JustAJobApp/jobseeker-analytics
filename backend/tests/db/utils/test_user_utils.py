from db.utils.user_utils import user_exists


def test_user_exists_returns_user(logged_in_user, db_session):
    user_object, _ = user_exists(logged_in_user, db_session)
    assert user_object is not None
    assert user_object.user_id == logged_in_user.user_id
