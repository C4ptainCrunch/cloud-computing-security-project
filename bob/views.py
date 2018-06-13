
from django.http import HttpResponse
from django.template import loader
from django.shortcuts import redirect
from jwt import JWT
from jwt.exceptions import JWTDecodeError
from jwt.jwk import OctetJWK


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
