from django.shortcuts import render

ENDPOINTS = [
    'unsecure',
    'chrome_protect',
    'referer_check',
    'source_self',
    'no_extract',
    'escape',
    'crsf',
]

EXTRACT = [
    'unsecure',
    'no_extract',
]


def index(request):
    return render(request, 'index.html', {'endpoints': ENDPOINTS, 'extract': EXTRACT})


def hidden(request):
    return render(request, 'hidden.html')


def iframe(request):
    return render(request, 'iframe.html')
