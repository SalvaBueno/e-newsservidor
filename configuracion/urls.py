# -*- coding: utf-8 -*-

from django.conf.urls import patterns, include, url
from django.contrib.auth import views as auth_views
from configuracion import views as configuracion_views
from django.contrib.auth.decorators import login_required
from usuarios import views as usuarios_views
from textos import views as textos_views

from django.contrib import admin

admin.autodiscover()

urlpatterns = [

    url(r'^$', textos_views.Index.as_view(), name='inicio'),
    url(r'^(?P<error>\d+)$', textos_views.Index.as_view(), name='inicio'),
    # url(r'^main/$', usuarios_views.Calendario.as_view(), name='inicio'),
    url(r'^login/$', configuracion_views.ajax_login, name='login'),
    url(r'^logout/$', configuracion_views.ajax_logout, name='logout'),
    # url(r'^cambiarpass/$', 'django.contrib.auth.views.password_change', {'template_name': 'cambiar_pass.html'}),
    url(r'password_change/$', auth_views.password_change, {'template_name': 'cambiar_pass.html'},
        name='password_change'),
    # url(r'^accounts/password_change/$', 'django.contrib.auth.views.password_change',{'password_change_form': AdminPasswordChangeForm},
    #    name="password_change"),


    url(r'^admin/', include(admin.site.urls)),
    url(r'^usuarios/', include('usuarios.urls')),
    url(r'^busqueda/$', textos_views.Busqueda.as_view(), name='busqueda'),
    url(r'^texto/$', textos_views.Textos.as_view(), name='texto'),
    url(r'^ckeditor/', include('ckeditor_uploader.urls')),
]

# if settings.DEBUG:
# import debug_toolbar
# urlpatterns += patterns('',
#    url(r'^__debug__/', include(debug_toolbar.urls)),
# )
