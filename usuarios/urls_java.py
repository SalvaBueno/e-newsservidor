# -*- encoding: utf-8 -*-

__author__ = 'brian'

from django.conf.urls import patterns, url
from usuarios import views_java as usuarios_java_views
from django.contrib.auth.decorators import login_required

urlpatterns = [url(r'^login/$', usuarios_java_views.login),
               url(r'^logout/$', usuarios_java_views.logout),
               url(r'^get_usuarios/$', usuarios_java_views.get_usuarios),
               url(r'^get_perfil/$', usuarios_java_views.get_perfil),
               url(r'^cambiar_datos/$', usuarios_java_views.cambiar_datos),
               url(r'^comprobar_token/$', usuarios_java_views.comprobar_token),
               url(r'^cambiar_pass/$', usuarios_java_views.cambiar_pass),

               ]
