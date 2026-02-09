from db.user_emails import UserEmails
from datetime import datetime

def test_coach_list_clients(logged_in_coach_client, coach_client_link):
    resp = logged_in_coach_client.get("/coach/clients")
    assert resp.status_code == 200
    data = resp.json()
    assert any(c["user_id"] == coach_client_link.client_id for c in data)


def test_coach_view_client_emails(logged_in_coach_client, coach_client_link, db_session, client_user):
    # create an email/application for client
    email = UserEmails(
        id="email1",
        user_id=client_user.user_id,
        company_name="Acme Corp",
        application_status="application confirmation",
        received_at=datetime.now(),
        subject="Your application",
        job_title="Software Engineer",
        email_from="hr@acme.com"
    )
    db_session.add(email)
    db_session.commit()

    resp = logged_in_coach_client.get("/get-emails", headers={"X-View-As": client_user.user_id})
    assert resp.status_code == 200
    data = resp.json()
    # Should see client's email
    assert any(item["id"] == "email1" for item in data)


def test_coach_cannot_delete_client_email(logged_in_coach_client, coach_client_link, db_session, client_user):
    email = UserEmails(
        id="email2",
        user_id=client_user.user_id,
        company_name="Beta Inc",
        application_status="application confirmation",
        received_at=datetime.now(),
        subject="We got it",
        job_title="Designer",
        email_from="hr@beta.com"
    )
    db_session.add(email)
    db_session.commit()

    # Coach tries to delete client's email (should 404 because deletion requires ownership)
    resp = logged_in_coach_client.delete("/delete-email/email2")
    assert resp.status_code in (403, 404)