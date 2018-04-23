# -*- coding: utf-8 -*-
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, render
from django.utils.functional import wraps
from django.template.context import RequestContext
import django.http as http
from django.views.decorators.http import require_POST


# def inicio(request):
#     import pdb
#     pdb.set_trace()
#
#     try:
#         print request.GET
#     except:
#         print "No se ha podido imprimir"
#     return render_to_response('principal.html', context_instance=RequestContext(request,{}))


@login_required()
def cambiarPass(request):
        return render_to_response('principal.html', context_instance=RequestContext(request,{}))


@require_POST
def ajax_login(request):
    username = request.POST['username'].lower()
    password = request.POST['password']
    user = authenticate(username=username, password=password)
    if user is not None:
        if user.is_active:
            login(request, user)
        else:
            print 'No se ha podido iniciar sesion'
            return http.HttpResponseRedirect(reverse('inicio', args=(1,)))
    else:
        print 'No se ha podido iniciar sesion 2'
        return http.HttpResponseRedirect(reverse('inicio',args=(1,)))

    # return HttpResponse(json.dumps(result), content_type='application/json')
    return http.HttpResponseRedirect(reverse('inicio'))


def ajax_logout(request):
    logout(request)
    return http.HttpResponseRedirect(reverse('inicio'))

'''
@login_required()
def main(request):
    usuario = Usuario.objects.get(usuario=request.user)
    return render_to_response('principal.html',context_instance=RequestContext(request,{'usuario':usuario}))
'''