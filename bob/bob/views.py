
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.template import loader
from django.shortcuts import redirect
from jwt import JWT
from jwt.exceptions import JWTDecodeError
from jwt.jwk import OctetJWK


@csrf_exempt
def unsecure(request):
    template = loader.get_template('submit.html')
    response = HttpResponse(template.render({}, request))
    response['X-XSS-Protection'] = "0"
    return response


@csrf_exempt
def chrome_protect(request):
    template = loader.get_template('submit.html')
    response = HttpResponse(template.render({}, request))
    return response


@csrf_exempt
def referer_check(request):
    if request.method != 'GET':
        if not request.META['HTTP_REFERER'].startswith("https://bob-cloud-computing.tk/"):
            return HttpResponse("Bad referer")
    template = loader.get_template('submit.html')
    response = HttpResponse(template.render({}, request))
    response['X-XSS-Protection'] = "0"
    return response


@csrf_exempt
def source_self(request):
    template = loader.get_template('submit.html')
    response = HttpResponse(template.render({}, request))
    response['X-XSS-Protection'] = "0"
    response['Content-Security-Policy'] = ';'.join([
        "script-src 'self'",
        "report-uri https://sentry.io/api/1189287/csp-report/?sentry_key=6a8127a98f32458daf9e82be16903f56"
    ])
    return response


@csrf_exempt
def no_extract(request):
    template = loader.get_template('submit.html')
    response = HttpResponse(template.render({}, request))
    response['X-XSS-Protection'] = "0"
    response['Content-Security-Policy'] = ';'.join([
        "connect-src 'self'",
        "default-src *",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self'",
        "img-src 'self' data:",
        "report-uri https://sentry.io/api/1189287/csp-report/?sentry_key=6a8127a98f32458daf9e82be16903f56"
    ])
    return response


@csrf_exempt
def escape(request):
    template = loader.get_template('submit-escape.html')
    response = HttpResponse(template.render({}, request))
    response['X-XSS-Protection'] = "0"
    return response


def crsf(request):
    template = loader.get_template('submit.html')
    response = HttpResponse(template.render({}, request))
    response['X-XSS-Protection'] = "0"
    return response


jwt = JWT()
KEY = OctetJWK(b'MY secret')


def login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == "admin" and password == "toor":
            encoded = jwt.encode({'username': "admin", "ip": request.META.get('HTTP_X_REAL_IP')}, KEY, 'HS256')
            response = redirect('/admin')
            response.set_cookie('auth', encoded)
            # response.cookies['auth']['httponly'] = True
            return response

    template = loader.get_template('login.html')
    response = HttpResponse(template.render({}, request))
    return response


def admin(request):
    try:
        decoded = jwt.decode(request.COOKIES.get("auth", ''), KEY)
        if decoded['username'] != 'admin':
            return HttpResponse("Bad user")
        if decoded['ip'] != request.META.get('HTTP_X_REAL_IP'):
            return HttpResponse("Bad ip %s, not %s" % (request.META.get('HTTP_X_REAL_IP'), decoded['ip']))

        template = loader.get_template('admin.html')
        response = HttpResponse(template.render({'ip': request.META.get('HTTP_X_REAL_IP')}, request))
        return response

    except JWTDecodeError:
        return HttpResponse("Bad token")
