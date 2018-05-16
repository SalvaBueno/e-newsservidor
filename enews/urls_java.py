# -*- encoding: utf-8 -*-

__author__ = 'salva'

from django.conf.urls import patterns, url
from enews import views_java
from django.contrib.auth.decorators import login_required

urlpatterns = [
    url(r'^get_noticias/$', login_required(views_java.get_noticias), name='get_noticias'),
    url(r'^get_comentarios/$', login_required(views_java.get_comentarios), name='get_comentarios'),
    url(r'^get_noticia/$', login_required(views_java.get_noticia), name='get_noticia'),
    url(r'^get_comentarios_noticia/$', login_required(views_java.get_comentarios_noticia), name='get_comentarios_noticia'),
    url(r'^registrar_comentarios/$', login_required(views_java.registrar_comentarios), name='registrar_comentarios'),
]
