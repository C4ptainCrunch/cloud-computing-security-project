from django.http import HttpResponse


class NoChromeProtectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-XSS-Protection'] = "0"
        return response


class SafeRefererMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method != 'GET':
            if not request.META['HTTP_REFERER'].startswith("http://bob-cloud-computing.tk:8000/"):
                return HttpResponse("Bad referer")
        response = self.get_response(request)
        return response


class PreflightMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Access-Control-Allow-Origin'] = "http://bob-cloud-computing.tk:8000/"
        return response


class CSPNoInlineMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Content-Security-Policy'] = "script-src 'self'; report-uri https://sentry.io/api/1189287/csp-report/?sentry_key=6a8127a98f32458daf9e82be16903f56"
        return response


class CSPXHRMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Content-Security-Policy'] = "connect-src 'self' http://out.bob-cloud-computing.tk:8002/; default-src *; script-src 'self'; style-src 'self'; img-src 'self' data:; report-uri https://sentry.io/api/1189287/csp-report/?sentry_key=6a8127a98f32458daf9e82be16903f56"
        return response
