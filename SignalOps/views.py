import json

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from .decorators import verify_webhook_signature

def home(request):
    return render(request, 'home.html')


@csrf_exempt
@verify_webhook_signature(secret=settings.SENTRY_CLIENT_SECRET)
def sentry_webhook(request):
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON payload"}, status=400)

    event_action = payload.get("action")
    return JsonResponse({"status": "ok", "action": event_action}, status=200)