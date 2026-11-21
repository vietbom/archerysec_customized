"""Real request regressions for profile and API password changes (isolated DB)."""
from bs4 import BeautifulSoup
from django.contrib.auth import authenticate
from django.test import Client, TestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from authentication.password_views import UpdatePassword
from user_management.models import Organization, UserProfile, UserRoles


@override_settings(ROOT_URLCONF="user_management.test_profile_urls")
class ProfilePasswordTests(TestCase):
    old_password = "OldSecret!7942"
    new_password = "BlueOrchid!4829"
    profile_url = "/users/profile/"

    @classmethod
    def setUpTestData(cls):
        org = Organization.objects.create(name="Password tests")
        cls.user = UserProfile.objects.create_user("profile@example.test", "Analyst",
            UserRoles.objects.create(role="Analyst").pk, org.pk, cls.old_password)
        cls.other = UserProfile.objects.create_user("other@example.test", "Other",
            cls.user.role_id, org.pk, "OtherSecret!7492")

    def setUp(self):
        self.client.force_login(self.user)

    def data(self, **changes):
        return {"old_password": self.old_password, "new_password1": self.new_password,
                "new_password2": self.new_password, **changes}

    def test_profile_renders_password_form_and_never_exposes_password_hash(self):
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        soup = BeautifulSoup(response.content, "html.parser")
        fields = soup.select('form input[type="password"]')
        self.assertEqual([field["name"] for field in fields], ["old_password", "new_password1", "new_password2"])
        self.assertEqual(fields[0]["autocomplete"], "current-password")
        self.assertTrue(all(field.get("class") == ["form-control"] for field in fields))
        self.assertNotContains(response, self.user.password)

    def test_success_changes_password_and_keeps_current_session(self):
        response = self.client.post(self.profile_url, self.data(), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.redirect_chain, [(self.profile_url, 302)])
        self.assertContains(response, "Your password has been changed successfully.")
        self.assertEqual(response.wsgi_request.user.pk, self.user.pk)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertFalse(self.user.check_password(self.old_password))
        self.assertIsNone(authenticate(username=self.user.email, password=self.old_password))
        self.assertEqual(authenticate(username=self.user.email, password=self.new_password).pk, self.user.pk)

    def test_wrong_current_password_mismatch_and_missing_field_do_not_save(self):
        for data, error_field in ((self.data(old_password="wrong"), "old_password"),
                                  (self.data(new_password2="does-not-match"), "new_password2"),
                                  (self.data(new_password1="", new_password2=""), "new_password1")):
            with self.subTest(field=error_field):
                response = self.client.post(self.profile_url, data)
                self.assertEqual(response.status_code, 200)
                self.assertIn(error_field, response.context["password_form"].errors)
                self.assertContains(response, "Your password was not changed.")
                self.user.refresh_from_db()
                self.assertTrue(self.user.check_password(self.old_password))
                soup = BeautifulSoup(response.content, "html.parser")
                self.assertTrue(all(not field.get("value") for field in soup.select('input[type="password"]')))

    def test_api_policy_rejections_return_400_instead_of_unbound_user_500(self):
        for password in ("tiny", "password123", "123456789012345"):
            with self.subTest(password_policy=password):
                response = self.client.post("/api/v1/auth/update-pass/", self.data(
                    new_password1=password, new_password2=password), content_type="application/json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("new_password2", response.json())
                self.assertNotContains(response, password, status_code=400)
                self.user.refresh_from_db()
                self.assertTrue(self.user.check_password(self.old_password))

    def test_api_wrong_old_password_and_mismatch_are_field_errors(self):
        for changes, field in (({"old_password": "incorrect"}, "old_password"),
                               ({"new_password2": "different"}, "new_password2")):
            response = self.client.post("/auth/update-pass/", self.data(**changes), content_type="application/json")
            self.assertEqual(response.status_code, 400)
            self.assertIn(field, response.json())

    def test_password_spaces_are_preserved_through_serializer(self):
        old, new = "  OldSecret!7942  ", "  BlueOrchid!4829  "
        self.user.set_password(old)
        self.user.save()
        self.client.force_login(self.user)
        response = self.client.post("/api/v1/auth/update-pass/", self.data(
            old_password=old, new_password1=new, new_password2=new), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new))
        self.assertFalse(self.user.check_password(new.strip()))
        self.assertEqual(self.client.get(self.profile_url).status_code, 200)

    def test_profile_put_has_no_uuid_argument_and_cannot_target_another_user(self):
        before_other = self.other.password
        response = self.client.put("/api/v1/users/profile/", self.data(
            uu_id=str(self.other.uu_id), name="Do not overwrite name"), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.other.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertEqual(self.user.name, "Analyst")
        self.assertEqual(self.other.password, before_other)

    def test_profile_api_get_serializes_the_user_not_a_queryset(self):
        response = self.client.get("/api/v1/users/profile/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], self.user.email)
        self.assertNotIn("password", response.json())

    def test_profile_name_edit_with_missing_blank_or_old_hash_preserves_password(self):
        encoded = self.user.password
        for password_data in ({}, {"password": ""}, {"password": encoded}):
            with self.subTest(password_field=list(password_data)):
                response = self.client.put("/api/v1/users/profile/", {
                    "name": "Updated profile", "uu_id": str(self.other.uu_id), **password_data,
                }, content_type="application/json")
                self.assertEqual(response.status_code, 200)
                self.user.refresh_from_db()
                self.other.refresh_from_db()
                self.assertEqual(self.user.password, encoded)
                self.assertEqual(self.user.name, "Updated profile")
                self.assertEqual(self.other.name, "Other")
                self.assertEqual(authenticate(username=self.user.email, password=self.old_password).pk, self.user.pk)
                self.assertEqual(self.client.get(self.profile_url).status_code, 200)

    def test_profile_legacy_plaintext_password_cannot_silently_replace_password(self):
        encoded = self.user.password
        response = self.client.put("/api/v1/users/profile/", {
            "name": "Should not save", "password": self.new_password,
        }, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertEqual(self.user.password, encoded)
        self.assertEqual(self.user.name, "Analyst")

    def test_success_invalidates_other_session_but_not_current(self):
        other_session = Client()
        other_session.force_login(self.user)
        self.assertEqual(other_session.get(self.profile_url).status_code, 200)
        self.assertEqual(self.client.post(self.profile_url, self.data()).status_code, 302)
        self.assertEqual(self.client.get(self.profile_url).status_code, 200)
        self.assertEqual(other_session.get(self.profile_url).status_code, 403)

    def test_anonymous_and_missing_csrf_cannot_change_password(self):
        anonymous = Client()
        self.assertEqual(anonymous.post(self.profile_url, self.data()).status_code, 403)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        csrf_client.get(self.profile_url)
        self.assertEqual(csrf_client.post(self.profile_url, self.data()).status_code, 403)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.old_password))
        response = csrf_client.post(self.profile_url, self.data(), HTTP_X_CSRFTOKEN=csrf_client.cookies["csrftoken"].value)
        self.assertEqual(response.status_code, 302)

    def test_authenticated_api_request_does_not_require_a_session(self):
        factory = APIRequestFactory()
        request = factory.post("/api/v1/auth/update-pass/", self.data(), format="json")
        force_authenticate(request, user=self.user)
        self.assertFalse(hasattr(request, "session"))
        response = UpdatePassword.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))


@override_settings(ROOT_URLCONF="user_management.test_profile_urls")
class UserEditPasswordTests(TestCase):
    old_password = "OldSecret!7942"
    new_password = "BlueOrchid!4829"

    @classmethod
    def setUpTestData(cls):
        org = Organization.objects.create(name="User edit tests")
        cls.admin = UserProfile.objects.create_user("admin@example.test", "Administrator",
            UserRoles.objects.create(role="Admin").pk, org.pk, cls.old_password)
        cls.user = UserProfile.objects.create_user("target@example.test", "Original name",
            UserRoles.objects.create(role="Analyst").pk, org.pk, cls.old_password)

    def setUp(self):
        self.client.force_login(self.admin)
        self.edit_url = f"/users/edit_user/{self.user.uu_id}/"
        self.api_url = f"/api/v1/users/user/{self.user.uu_id}/"

    def data(self, **changes):
        return {"name": "Updated name", "email": self.user.email,
                "image": "", "role": self.user.role_id,
                "organization": self.user.organization_id, **changes}

    def test_edit_form_has_empty_password_fields_without_hash(self):
        response = self.client.get(self.edit_url)
        self.assertEqual(response.status_code, 200)
        soup = BeautifulSoup(response.content, "html.parser")
        fields = soup.select('input[type="password"]')
        self.assertEqual([field["name"] for field in fields], ["password", "password_confirm"])
        self.assertTrue(all(not field.get("value") for field in fields))
        self.assertTrue(all(field.get("autocomplete") == "new-password" for field in fields))
        self.assertNotContains(response, self.user.password)

    def test_rename_missing_blank_and_legacy_prefilled_hash_preserve_login(self):
        encoded = self.user.password
        password_time = self.user.password_updt_time
        for password_data in ({}, {"password": "", "password_confirm": ""}, {"password": encoded}):
            with self.subTest(password_field=list(password_data)):
                response = self.client.post(self.edit_url, self.data(**password_data))
                self.assertEqual(response.status_code, 302)
                self.user.refresh_from_db()
                self.assertEqual(self.user.password, encoded)
                self.assertEqual(self.user.password_updt_time, password_time)
                self.assertEqual(self.user.name, "Updated name")
                self.assertEqual(authenticate(username=self.user.email, password=self.old_password).pk, self.user.pk)

    def test_admin_api_partial_rename_preserves_password_role_flags_and_organization(self):
        encoded = self.user.password
        for password_data in ({}, {"password": ""}, {"password": encoded}):
            with self.subTest(password_field=list(password_data)):
                response = self.client.put(self.api_url, {"name": "API rename", **password_data}, content_type="application/json")
                self.assertEqual(response.status_code, 200)
                self.user.refresh_from_db()
                self.assertEqual(self.user.password, encoded)
                self.assertEqual(self.user.name, "API rename")
                self.assertEqual(self.user.role.role, "Analyst")
                self.assertEqual(self.user.organization_id, self.admin.organization_id)
                self.assertTrue(self.user.is_active)

    def test_explicit_reset_requires_confirmation_and_password_policy_before_saving(self):
        encoded = self.user.password
        attempts = ({"password": self.new_password},
                    {"password": self.new_password, "password_confirm": "different"},
                    {"password": "tiny", "password_confirm": "tiny"})
        for attempt in attempts:
            with self.subTest(fields=list(attempt)):
                response = self.client.post(self.edit_url, self.data(**attempt))
                self.assertEqual(response.status_code, 400)
                self.assertIn("password_confirm", response.data["errors"])
                self.assertNotContains(response, attempt["password"], status_code=400)
                soup = BeautifulSoup(response.content, "html.parser")
                self.assertTrue(all(not field.get("value") for field in soup.select('input[type="password"]')))
                self.user.refresh_from_db()
                self.assertEqual(self.user.password, encoded)
                self.assertEqual(self.user.name, "Original name")

    def test_explicit_reset_works_for_ui_and_api(self):
        for endpoint, method in ((self.edit_url, "post"), (self.api_url, "put")):
            with self.subTest(endpoint=endpoint):
                data = self.data(password=self.new_password, password_confirm=self.new_password)
                response = getattr(self.client, method)(endpoint, data, content_type="application/json")
                self.assertEqual(response.status_code, 302 if method == "post" else 200)
                self.user.refresh_from_db()
                self.assertTrue(self.user.check_password(self.new_password))
                self.assertFalse(self.user.check_password(self.old_password))
                self.assertEqual(authenticate(username=self.user.email, password=self.new_password).pk, self.user.pk)

    def test_stale_hash_different_from_current_password_is_not_hashed_again(self):
        stale_hash = self.user.password
        self.user.set_password(self.new_password)
        self.user.save()
        current_hash = self.user.password
        response = self.client.post(self.edit_url, self.data(password=stale_hash, password_confirm=stale_hash))
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertEqual(self.user.password, current_hash)
        self.assertNotContains(response, stale_hash, status_code=400)

    def test_edit_own_name_and_reset_password_keep_current_session(self):
        endpoint = f"/users/edit_user/{self.admin.uu_id}/"
        data = {"name": "Renamed admin", "email": self.admin.email}
        encoded = self.admin.password
        self.assertEqual(self.client.post(endpoint, data).status_code, 302)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.password, encoded)
        self.assertEqual(self.client.get(endpoint).status_code, 200)
        self.assertEqual(self.client.post(endpoint, {**data, "password": self.new_password,
                                                   "password_confirm": self.new_password}).status_code, 302)
        self.assertEqual(self.client.get(endpoint).status_code, 200)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password(self.new_password))

    def test_non_admin_cannot_reset_another_account(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(self.edit_url, self.data()).status_code, 403)
        self.assertEqual(self.client.put(self.api_url, {"name": "Denied"}, content_type="application/json").status_code, 403)
        self.user.refresh_from_db()
        self.assertEqual(self.user.name, "Original name")
