import hashlib
import hmac
from functools import wraps

from django.http import HttpResponse, HttpResponseForbidden, JsonResponse


def verify_webhook_signature(secret: str, signature_header: str = "Sentry-Hook-Signature"):
    """Validate HMAC SHA-256 signatures for incoming webhook requests."""

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if request.method != "POST":
                return HttpResponse("Method not allowed", status=405)

            if not secret:
                return JsonResponse({"detail": "Webhook secret not configured"}, status=503)

            provided_signature = request.headers.get(signature_header, "").strip()
            if not provided_signature:
                return HttpResponseForbidden("Missing signature")

            # Accept signatures as either "sha256=<hex>" or plain "<hex>".
            if "=" in provided_signature:
                _, provided_signature = provided_signature.split("=", 1)

            expected_signature = hmac.new(
                key=secret.encode("utf-8"),
                msg=request.body,
                digestmod=hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(provided_signature, expected_signature):
                return HttpResponseForbidden("Invalid signature")

            return view_func(request, *args, **kwargs)

        return _wrapped

    return decorator