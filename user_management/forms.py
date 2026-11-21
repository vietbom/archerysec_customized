from django.contrib.auth.forms import PasswordChangeForm


class ProfilePasswordChangeForm(PasswordChangeForm):
    """Use Django's password checks with the profile page's form styling."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["old_password"].label = "Current password"
        self.fields["new_password2"].label = "Confirm new password"
        # Opening the page should start at the account heading on mobile.
        self.fields["old_password"].widget.attrs.pop("autofocus", None)
        for name, field in self.fields.items():
            field.widget.attrs["class"] = "form-control"
            if field.help_text:
                field.widget.attrs["aria-describedby"] = "id_" + name + "_help"
