"""
Constants for the operation of the module.
Keep immutable values here so as not to clog the namespace of OAuth backend and middleware layer.
"""


OAUTH_PROCESS_URLS = ("oauth2", "auth", "login_oauth_token", "social-logout")
API_URLS = (
    "certificates",
    "api",
    "user_api",
    "notifier_api",
    "update_example_certificate",
    "update_certificate",
    "request_certificate",
)

LOCAL_URLS = (
    "i18n",
    "search",
    "verify_student",
    "certificates",
    "jsi18n",
    "course_modes",
    "404",
    "500",
    "i18n.js",
    "wiki",
    "notify",
    "courses",
    "xblock",
    "change_setting",
    "account",
    "notification_prefs",
    "admin",
    "survey",
    "event",
    "instructor_task_status",
    "edinsights_service",
    "openassessment",
    "instructor_report",
    "logout",
)